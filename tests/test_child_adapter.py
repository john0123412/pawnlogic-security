"""Behavioral tests for the optional child-process JSON adapter."""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

from pawnlogic_security.child_adapter import ChildAdapterConfig, ChildProcessAdapter


def test_adapter_is_disabled_by_default() -> None:
    adapter = ChildProcessAdapter(
        ChildAdapterConfig(
            argv=(sys.executable, "-c", "raise SystemExit('must not run')"),
        )
    )

    result = adapter.run({"request": "ignored"})

    assert result.to_dict() == {
        "ok": False,
        "code": "disabled",
        "message": "Child-process adapter is disabled.",
        "data": None,
    }


def test_missing_binary_fails_without_echoing_argv() -> None:
    adapter = ChildProcessAdapter(
        ChildAdapterConfig(
            argv=("pawnlogic-child-binary-that-does-not-exist", "--token=do-not-echo"),
            enabled=True,
        )
    )

    result = adapter.run({"request": "ignored"})

    assert result.to_dict() == {
        "ok": False,
        "code": "executable_not_found",
        "message": "Configured executable was not found.",
        "data": None,
    }


def test_operation_policy_deny_is_refused_before_execution() -> None:
    adapter = ChildProcessAdapter(
        ChildAdapterConfig(
            argv=("cat", "~/.ssh/id_rsa"),
            enabled=True,
        )
    )

    result = adapter.run({"request": "ignored"})

    assert result.to_dict() == {
        "ok": False,
        "code": "policy_denied",
        "message": "Host Operation Policy refused child-process execution.",
        "data": None,
    }


def test_operation_policy_confirmation_is_refused_before_execution() -> None:
    adapter = ChildProcessAdapter(
        ChildAdapterConfig(
            argv=("rm", "-rf", "sandbox"),
            enabled=True,
        )
    )

    result = adapter.run({"request": "ignored"})

    assert result.to_dict() == {
        "ok": False,
        "code": "policy_confirmation_required",
        "message": "Host Operation Policy refused child-process execution.",
        "data": None,
    }


def test_successful_json_roundtrip_uses_literal_argv() -> None:
    child_code = (
        "import json, sys; "
        "request = json.loads(sys.stdin.read()); "
        "json.dump({'echo': request['value'], 'argument': sys.argv[1]}, sys.stdout)"
    )
    adapter = ChildProcessAdapter(
        ChildAdapterConfig(
            argv=(sys.executable, "-c", child_code, "literal;not-a-shell"),
            enabled=True,
            timeout_seconds=2.0,
            max_input_bytes=1_024,
            max_output_bytes=1_024,
        )
    )

    result = adapter.run({"value": "pong"})

    assert result.to_dict() == {
        "ok": True,
        "code": "ok",
        "message": "Child process completed successfully.",
        "data": {
            "argument": "literal;not-a-shell",
            "echo": "pong",
        },
    }


def test_timeout_cleans_up_the_child_process_group(tmp_path: Path) -> None:
    grandchild_pid_path = tmp_path / "grandchild.pid"
    child_code = (
        "import pathlib, subprocess, sys, time; "
        "grandchild = subprocess.Popen("
        "[sys.executable, '-c', "
        "'import signal, time; "
        "signal.signal(signal.SIGTERM, signal.SIG_IGN); "
        "time.sleep(30)']); "
        "pathlib.Path(sys.argv[1]).write_text(str(grandchild.pid), encoding='utf-8'); "
        "time.sleep(30)"
    )
    adapter = ChildProcessAdapter(
        ChildAdapterConfig(
            argv=(sys.executable, "-c", child_code, str(grandchild_pid_path)),
            enabled=True,
            timeout_seconds=0.5,
        )
    )

    result = adapter.run({"request": "timeout"})

    assert result.to_dict() == {
        "ok": False,
        "code": "timeout",
        "message": "Child process exceeded its configured timeout.",
        "data": None,
    }
    grandchild_pid = int(grandchild_pid_path.read_text(encoding="utf-8"))
    deadline = time.monotonic() + 2.0
    while _process_exists(grandchild_pid) and time.monotonic() < deadline:
        time.sleep(0.01)
    assert not _process_exists(grandchild_pid)


def _process_exists(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    return True


def test_malformed_output_is_refused_without_echoing_it() -> None:
    adapter = ChildProcessAdapter(
        ChildAdapterConfig(
            argv=(
                sys.executable,
                "-c",
                "import sys; sys.stdout.write('{\"first\": 1}\\n{\"second\": 2}')",
            ),
            enabled=True,
        )
    )

    result = adapter.run({"request": "malformed"})

    assert result.to_dict() == {
        "ok": False,
        "code": "malformed_output",
        "message": "Child process returned malformed JSON.",
        "data": None,
    }


def test_oversized_output_is_stopped_before_the_process_timeout() -> None:
    child_code = (
        "import sys, time; "
        "sys.stdout.write('x' * 4096); "
        "sys.stdout.flush(); "
        "time.sleep(30)"
    )
    adapter = ChildProcessAdapter(
        ChildAdapterConfig(
            argv=(sys.executable, "-c", child_code),
            enabled=True,
            timeout_seconds=3.0,
            max_output_bytes=128,
        )
    )

    started = time.monotonic()
    result = adapter.run({"request": "oversized"})
    elapsed = time.monotonic() - started

    assert result.to_dict() == {
        "ok": False,
        "code": "output_too_large",
        "message": "Child-process output exceeds the configured limit.",
        "data": None,
    }
    assert elapsed < 1.5


def test_successful_output_redacts_secret_fields_and_strings() -> None:
    child_code = (
        "import json, sys; "
        "request = json.loads(sys.stdin.read()); "
        "json.dump({"
        "'token': request['token'], "
        "'nested': {'api_key': 'example-api-key', 'safe': 'visible'}, "
        "'message': 'password=hunter2'"
        "}, sys.stdout)"
    )
    adapter = ChildProcessAdapter(
        ChildAdapterConfig(
            argv=(sys.executable, "-c", child_code),
            enabled=True,
        )
    )

    result = adapter.run({"token": "example-secret-token"})

    assert result.to_dict() == {
        "ok": True,
        "code": "ok",
        "message": "Child process completed successfully.",
        "data": {
            "message": "password=<redacted>",
            "nested": {
                "api_key": "<redacted>",
                "safe": "visible",
            },
            "token": "<redacted>",
        },
    }


def test_oversized_json_request_is_refused_before_start() -> None:
    adapter = ChildProcessAdapter(
        ChildAdapterConfig(
            argv=(sys.executable, "-c", "raise SystemExit('must not run')"),
            enabled=True,
            max_input_bytes=16,
        )
    )

    result = adapter.run({"value": "x" * 64})

    assert result.to_dict() == {
        "ok": False,
        "code": "input_too_large",
        "message": "JSON request exceeds the configured input limit.",
        "data": None,
    }


def test_child_does_not_inherit_caller_secret_environment() -> None:
    variable_name = "PAWNLOGIC_CHILD_TEST_SECRET"
    child_code = (
        "import json, os, sys; "
        f"json.dump({{'secret_inherited': bool(os.environ.get('{variable_name}'))}}, "
        "sys.stdout)"
    )
    adapter = ChildProcessAdapter(
        ChildAdapterConfig(
            argv=(sys.executable, "-c", child_code),
            enabled=True,
        )
    )
    previous = os.environ.get(variable_name)
    os.environ[variable_name] = "test-only-private-value"
    try:
        result = adapter.run({"request": "environment"})
    finally:
        if previous is None:
            os.environ.pop(variable_name, None)
        else:
            os.environ[variable_name] = previous

    assert result.to_dict() == {
        "ok": True,
        "code": "ok",
        "message": "Child process completed successfully.",
        "data": {"secret_inherited": False},
    }
