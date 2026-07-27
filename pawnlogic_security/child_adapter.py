"""Optional, fail-closed child-process adapter using a single JSON exchange."""

from __future__ import annotations

import json
import os
import re
import shlex
import shutil
import signal
import subprocess
import threading
import time
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import BinaryIO, Protocol

from core.operation_policy import (
    OperationAction,
    OperationDecision,
    classify_shell_command,
    redact_command,
)

_SENSITIVE_FIELD_RE = re.compile(
    r"(?:api[_-]?key|access[_-]?key|token|password|passwd|secret|private[_-]?key)",
    re.IGNORECASE,
)


class OperationPolicyEvaluator(Protocol):
    """Callable shape provided by the host Operation Policy."""

    def __call__(
        self,
        command: str,
        *,
        cwd: str | Path,
        workspace_dir: str | Path | None = None,
    ) -> OperationDecision: ...


@dataclass(frozen=True, slots=True)
class ChildAdapterConfig:
    """Caller-owned process configuration; disabled unless explicitly enabled."""

    argv: tuple[str, ...] = field(default=(), repr=False)
    enabled: bool = False
    timeout_seconds: float = 10.0
    max_input_bytes: int = 64 * 1024
    max_output_bytes: int = 1024 * 1024


@dataclass(frozen=True, slots=True)
class ChildAdapterResult:
    """Deterministic result returned for every adapter outcome."""

    ok: bool
    code: str
    message: str
    data: object | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "ok": self.ok,
            "code": self.code,
            "message": self.message,
            "data": self.data,
        }


class ChildProcessAdapter:
    """Run one configured child process for one bounded JSON request."""

    def __init__(
        self,
        config: ChildAdapterConfig,
        *,
        policy_evaluator: OperationPolicyEvaluator = classify_shell_command,
    ) -> None:
        self._config = config
        self._policy_evaluator = policy_evaluator

    def run(self, request: Mapping[str, object]) -> ChildAdapterResult:
        if not self._config.enabled:
            return ChildAdapterResult(
                ok=False,
                code="disabled",
                message="Child-process adapter is disabled.",
            )

        cwd = Path.cwd()
        decision = self._policy_evaluator(
            shlex.join(self._config.argv),
            cwd=cwd,
            workspace_dir=cwd,
        )
        if decision.action is not OperationAction.ALLOW:
            code = (
                "policy_denied"
                if decision.action is OperationAction.DENY
                else "policy_confirmation_required"
            )
            return ChildAdapterResult(
                ok=False,
                code=code,
                message="Host Operation Policy refused child-process execution.",
            )

        executable = shutil.which(self._config.argv[0]) if self._config.argv else None
        if executable is None:
            return ChildAdapterResult(
                ok=False,
                code="executable_not_found",
                message="Configured executable was not found.",
            )

        if (
            self._config.timeout_seconds <= 0
            or self._config.max_input_bytes <= 0
            or self._config.max_output_bytes <= 0
        ):
            return ChildAdapterResult(
                ok=False,
                code="invalid_configuration",
                message="Adapter limits must be positive.",
            )

        try:
            input_bytes = (
                json.dumps(
                    dict(request),
                    ensure_ascii=False,
                    separators=(",", ":"),
                    sort_keys=True,
                    allow_nan=False,
                )
                + "\n"
            ).encode("utf-8")
        except (TypeError, ValueError):
            return ChildAdapterResult(
                ok=False,
                code="invalid_request",
                message="Request is not valid JSON.",
            )
        if len(input_bytes) > self._config.max_input_bytes:
            return ChildAdapterResult(
                ok=False,
                code="input_too_large",
                message="JSON request exceeds the configured input limit.",
            )

        argv = (executable, *self._config.argv[1:])
        try:
            process = subprocess.Popen(
                argv,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=False,
                env=_scrubbed_environment(),
                start_new_session=os.name == "posix",
            )
        except OSError:
            return ChildAdapterResult(
                ok=False,
                code="process_start_failed",
                message="Configured child process could not be started.",
            )

        exchange_code, stdout = _exchange_json(
            process,
            input_bytes=input_bytes,
            timeout_seconds=self._config.timeout_seconds,
            max_output_bytes=self._config.max_output_bytes,
        )
        if exchange_code == "timeout":
            return ChildAdapterResult(
                ok=False,
                code="timeout",
                message="Child process exceeded its configured timeout.",
            )
        if exchange_code == "output_too_large":
            return ChildAdapterResult(
                ok=False,
                code="output_too_large",
                message="Child-process output exceeds the configured limit.",
            )
        if process.returncode != 0:
            return ChildAdapterResult(
                ok=False,
                code="process_failed",
                message="Child process exited unsuccessfully.",
            )

        try:
            data = json.loads(
                stdout.decode("utf-8"),
                parse_constant=_reject_json_constant,
            )
        except (UnicodeDecodeError, ValueError):
            return ChildAdapterResult(
                ok=False,
                code="malformed_output",
                message="Child process returned malformed JSON.",
            )
        return ChildAdapterResult(
            ok=True,
            code="ok",
            message="Child process completed successfully.",
            data=_redact_json(data),
        )


def _scrubbed_environment() -> dict[str, str]:
    """Return a minimal environment without inheriting caller secrets."""
    environment = {
        "PATH": os.defpath,
        "PYTHONIOENCODING": "utf-8",
    }
    for name in ("SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT"):
        value = os.environ.get(name)
        if value:
            environment[name] = value
    return environment


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"Non-standard JSON constant: {value}")


def _redact_json(value: object) -> object:
    if isinstance(value, dict):
        redacted: dict[str, object] = {}
        for key in sorted(value):
            item = value[key]
            redacted[key] = (
                "<redacted>"
                if _SENSITIVE_FIELD_RE.fullmatch(key)
                else _redact_json(item)
            )
        return redacted
    if isinstance(value, list):
        return [_redact_json(item) for item in value]
    if isinstance(value, str):
        return redact_command(value)
    return value


class _BoundedOutput:
    """Share one byte budget across stdout and stderr reader threads."""

    def __init__(self, limit: int) -> None:
        self._limit = limit
        self._total = 0
        self._stdout = bytearray()
        self._lock = threading.Lock()
        self.overflow = threading.Event()

    def add(self, chunk: bytes, *, capture: bool) -> None:
        with self._lock:
            remaining = self._limit - self._total
            if len(chunk) > remaining:
                if capture and remaining > 0:
                    self._stdout.extend(chunk[:remaining])
                self._total = self._limit
                self.overflow.set()
                return
            self._total += len(chunk)
            if capture:
                self._stdout.extend(chunk)

    def stdout(self) -> bytes:
        with self._lock:
            return bytes(self._stdout)


def _exchange_json(
    process: subprocess.Popen[bytes],
    *,
    input_bytes: bytes,
    timeout_seconds: float,
    max_output_bytes: int,
) -> tuple[str, bytes]:
    assert process.stdin is not None
    assert process.stdout is not None
    assert process.stderr is not None

    output = _BoundedOutput(max_output_bytes)
    stdin_done = threading.Event()
    stdout_done = threading.Event()
    stderr_done = threading.Event()
    threads = (
        threading.Thread(
            target=_write_input,
            args=(process.stdin, input_bytes, stdin_done),
            daemon=True,
        ),
        threading.Thread(
            target=_read_output,
            args=(process.stdout, output, True, stdout_done),
            daemon=True,
        ),
        threading.Thread(
            target=_read_output,
            args=(process.stderr, output, False, stderr_done),
            daemon=True,
        ),
    )
    for thread in threads:
        thread.start()

    deadline = time.monotonic() + timeout_seconds
    exchange_code = "ok"
    while True:
        if output.overflow.is_set():
            exchange_code = "output_too_large"
            break
        process_finished = process.poll() is not None
        streams_finished = stdin_done.is_set() and stdout_done.is_set() and stderr_done.is_set()
        if process_finished and streams_finished:
            break
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            exchange_code = "timeout"
            break
        output.overflow.wait(timeout=min(0.01, remaining))

    if exchange_code != "ok":
        _terminate_process_group(process)
    else:
        process.wait()

    for thread in threads:
        thread.join(timeout=0.2)
    return exchange_code, output.stdout()


def _write_input(stream: BinaryIO, data: bytes, done: threading.Event) -> None:
    try:
        stream.write(data)
        stream.flush()
    except (BrokenPipeError, OSError):
        pass
    finally:
        try:
            stream.close()
        finally:
            done.set()


def _read_output(
    stream: BinaryIO,
    output: _BoundedOutput,
    capture: bool,
    done: threading.Event,
) -> None:
    try:
        read_chunk = getattr(stream, "read1", stream.read)
        while not output.overflow.is_set():
            chunk = read_chunk(8192)
            if not chunk:
                break
            output.add(chunk, capture=capture)
    except OSError:
        pass
    finally:
        try:
            stream.close()
        finally:
            done.set()


def _terminate_process_group(process: subprocess.Popen[bytes]) -> None:
    """Terminate the configured process and its process group when supported."""
    if os.name == "posix":
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            process.wait(timeout=0.2)
        except subprocess.TimeoutExpired:
            pass
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        if process.poll() is None:
            process.wait()
        return

    process.terminate()
    try:
        process.wait(timeout=0.2)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()


__all__ = [
    "ChildAdapterConfig",
    "ChildAdapterResult",
    "ChildProcessAdapter",
]
