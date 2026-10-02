"""Install the exact wheel uploaded by this release and reject stale artifacts."""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import subprocess
import sys
import tempfile
import time
import venv
from pathlib import Path

WHEEL_PATTERN = re.compile(
    r"^pawnlogic_security-(?P<version>[^-]+)-[^-]+-[^-]+-[^-]+\.whl$"
)


def verify_wheel(wheel: Path, expected_version: str, expected_sha256: str) -> None:
    match = WHEEL_PATTERN.fullmatch(wheel.name)
    if match is None:
        raise ValueError(f"unexpected wheel filename: {wheel.name}")
    if match.group("version") != expected_version:
        raise ValueError(
            f"wheel version {match.group('version')} is not {expected_version}"
        )

    actual_sha256 = hashlib.sha256(wheel.read_bytes()).hexdigest()
    if actual_sha256 != expected_sha256.lower():
        raise ValueError(
            f"wheel sha256 {actual_sha256} does not match this build "
            f"{expected_sha256.lower()}"
        )


def _download_wheel(
    index_url: str,
    version: str,
    destination: Path,
    *,
    attempts: int,
    retry_seconds: int,
) -> Path:
    requirement = f"pawnlogic-security=={version}"
    for attempt in range(1, attempts + 1):
        attempt_dir = destination / f"attempt-{attempt}"
        attempt_dir.mkdir()
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "pip",
                "download",
                "--disable-pip-version-check",
                "--no-cache-dir",
                "--no-deps",
                "--only-binary=:all:",
                "--index-url",
                index_url,
                "--dest",
                str(attempt_dir),
                requirement,
            ],
            check=False,
        )
        wheels = list(attempt_dir.glob("*.whl"))
        if result.returncode == 0 and len(wheels) == 1:
            return wheels[0]
        if attempt < attempts:
            print(
                f"{requirement} is not available from {index_url} "
                f"(attempt {attempt}/{attempts}); retrying",
                flush=True,
            )
            time.sleep(retry_seconds)
    raise RuntimeError(f"could not download exactly one wheel for {requirement}")


def _install_and_verify(
    wheel: Path,
    expected_version: str,
    *,
    index_url: str,
    extra_index_url: str | None,
    environment_dir: Path,
) -> None:
    venv.EnvBuilder(with_pip=True).create(environment_dir)
    if os.name == "nt":
        scripts = environment_dir / "Scripts"
        environment_python = scripts / "python.exe"
        security_cli = scripts / "pawn-security.exe"
    else:
        scripts = environment_dir / "bin"
        environment_python = scripts / "python"
        security_cli = scripts / "pawn-security"

    install_command = [
        str(environment_python),
        "-m",
        "pip",
        "install",
        "--disable-pip-version-check",
        "--no-cache-dir",
        "--index-url",
        index_url,
    ]
    if extra_index_url is not None:
        install_command.extend(["--extra-index-url", extra_index_url])
    install_command.append(str(wheel))
    subprocess.run(install_command, check=True)

    environment = os.environ.copy()
    environment["EXPECTED_RELEASE_VERSION"] = expected_version
    subprocess.run(
        [
            str(environment_python),
            "-c",
            (
                "import os; "
                "from importlib.metadata import version as distribution_version; "
                "import core; "
                "import pawnlogic_security; "
                "assert pawnlogic_security.__version__ == "
                "os.environ['EXPECTED_RELEASE_VERSION']; "
                "core_version = distribution_version('pawnlogic'); "
                "core_parts = core_version.split('.'); "
                "assert len(core_parts) >= 2 and core_parts[0] == '0' "
                "and core_parts[1] == '4', "
                "f'pawnlogic>=0.4,<0.5 required, installed {core_version}'; "
                "print('installed pawnlogic-security', "
                "pawnlogic_security.__version__, 'with pawnlogic', core_version)"
            ),
        ],
        check=True,
        env=environment,
    )
    subprocess.run([str(security_cli), "--help"], check=True)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--index-url", required=True)
    parser.add_argument("--extra-index-url")
    parser.add_argument("--version", required=True)
    parser.add_argument("--wheel-sha256", required=True)
    parser.add_argument("--attempts", type=int, default=6)
    parser.add_argument("--retry-seconds", type=int, default=10)
    args = parser.parse_args()

    with tempfile.TemporaryDirectory(prefix="pawnlogic-security-smoke-") as temp:
        wheel = _download_wheel(
            args.index_url,
            args.version,
            Path(temp),
            attempts=args.attempts,
            retry_seconds=args.retry_seconds,
        )
        verify_wheel(wheel, args.version, args.wheel_sha256)
        _install_and_verify(
            wheel,
            args.version,
            index_url=args.index_url,
            extra_index_url=args.extra_index_url,
            environment_dir=Path(temp) / "venv",
        )


if __name__ == "__main__":
    main()
