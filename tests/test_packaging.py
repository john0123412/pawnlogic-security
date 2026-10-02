"""Packaging and distribution-content regression tests.

These verify the built wheel contains what it should and nothing else.
"""

from __future__ import annotations

import subprocess
import sys
from email import message_from_string
from pathlib import Path
from zipfile import ZipFile

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _build_wheel(tmp_path: Path) -> Path:
    """Build a wheel and return its path."""
    dist = tmp_path / "dist"
    result = subprocess.run(
        [sys.executable, "-m", "build", "--wheel", "--outdir", str(dist)],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    assert result.returncode == 0, f"build failed: {result.stderr}"
    wheels = list(dist.glob("*.whl"))
    assert len(wheels) == 1, f"expected 1 wheel, found {len(wheels)}"
    return wheels[0]


@pytest.fixture(scope="module")
def wheel_path(tmp_path_factory) -> Path:
    tmp = tmp_path_factory.mktemp("build")
    return _build_wheel(tmp)


def test_wheel_contains_package(wheel_path: Path):
    with ZipFile(wheel_path) as zf:
        names = zf.namelist()
    assert any("pawnlogic_security/" in name for name in names), names


def test_wheel_contains_no_pycache(wheel_path: Path):
    with ZipFile(wheel_path) as zf:
        names = zf.namelist()
    assert not any("__pycache__" in name for name in names), names


def test_wheel_contains_no_test_files(wheel_path: Path):
    with ZipFile(wheel_path) as zf:
        names = zf.namelist()
    assert not any("tests/" in name for name in names), names


def test_wheel_contains_no_secrets(wheel_path: Path):
    # Evidence.py contains regex patterns for detecting secrets (e.g.
    # r"sk-ant-[A-Za-z0-9_-]{20,}"). The patterns themselves are safe; only
    # actual credential values would be a leak.
    test_credentials = [
        "sk-ant-abcdefghijklmnopqrstuvwxyz012345",
        "ghp_abcdefghijklmnopqrstuvwxyz0123456789",
        "AKIAIOSFODNN7EXAMPLE",
    ]
    with ZipFile(wheel_path) as zf:
        for name in zf.namelist():
            if name.endswith(".py"):
                content = zf.read(name).decode("utf-8", errors="replace")
                for cred in test_credentials:
                    assert cred not in content, f"credential in {name}"


def test_wheel_metadata_contains_urls(wheel_path: Path):
    with ZipFile(wheel_path) as zf:
        for name in zf.namelist():
            if name.endswith("METADATA"):
                metadata = zf.read(name).decode("utf-8")
                assert "https://github.com/john0123412/pawnlogic-security" in metadata
                return
    pytest.fail("METADATA not found in wheel")


def test_wheel_declares_console_scripts(wheel_path: Path):
    with ZipFile(wheel_path) as zf:
        for name in zf.namelist():
            if name.endswith("entry_points.txt"):
                content = zf.read(name).decode("utf-8")
                assert "pawn-security" in content
                return
    pytest.fail("entry_points.txt not found in wheel")


def test_wheel_declares_pawnlogic_extension_entry_point(wheel_path: Path):
    with ZipFile(wheel_path) as zf:
        for name in zf.namelist():
            if name.endswith("entry_points.txt"):
                content = zf.read(name).decode("utf-8")
                assert "pawnlogic.extensions" in content
                assert "security" in content
                return
    pytest.fail("entry_points.txt not found in wheel")


def test_wheel_has_correct_core_dependency(wheel_path: Path):
    with ZipFile(wheel_path) as zf:
        for name in zf.namelist():
            if name.endswith("METADATA"):
                metadata = message_from_string(zf.read(name).decode("utf-8"))
                requirements = metadata.get_all("Requires-Dist") or []
                # setuptools sorts version specifiers, so >=0.4,<0.5 becomes <0.5,>=0.4
                assert "pawnlogic<0.5,>=0.4" in requirements, requirements
                return
    pytest.fail("METADATA not found in wheel")


def test_wheel_license_is_mit(wheel_path: Path):
    with ZipFile(wheel_path) as zf:
        for name in zf.namelist():
            if name.endswith("METADATA"):
                metadata = zf.read(name).decode("utf-8")
                # PEP 639: License-Expression header
                assert "License-Expression: MIT" in metadata
                return
    pytest.fail("METADATA not found in wheel")
