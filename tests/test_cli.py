"""Tests for the pawn-security command-line interface."""

from __future__ import annotations

import json
from pathlib import Path

from pawnlogic_security.cli import main


def test_default_output_shows_extension_info(capsys):
    assert main([]) == 0
    out = capsys.readouterr().out
    assert "pawnlogic-security" in out
    assert "Extension name: security" in out
    assert "/extension enable security" in out


def test_manifest_flag(capsys):
    assert main(["--manifest"]) == 0
    out = capsys.readouterr().out
    assert "name:              security" in out
    assert "core_version_spec: >=0.3,<0.4" in out


def _write_valid_scope(path: Path, **overrides: object) -> None:
    data: dict[str, object] = {
        "version": 1,
        "identifier": "cli-test",
        "authorized_by": "tester",
        "expires_at": 9999999999.0,
        "targets": ["example.com"],
    }
    data.update(overrides)
    path.write_text(json.dumps(data), encoding="utf-8")


def test_scope_validate_accepts_valid_file(tmp_path, capsys):
    path = tmp_path / "scope.json"
    _write_valid_scope(path)

    assert main(["scope", "validate", str(path)]) == 0
    out = capsys.readouterr().out
    assert "scope file is valid" in out
    assert "cli-test" in out


def test_scope_validate_reports_missing_file(tmp_path, capsys):
    assert main(["scope", "validate", str(tmp_path / "missing.json")]) == 1
    err = capsys.readouterr().err
    assert "not found" in err


def test_scope_validate_reports_malformed_json(tmp_path, capsys):
    path = tmp_path / "bad.json"
    path.write_text("{not json", encoding="utf-8")

    assert main(["scope", "validate", str(path)]) == 1
    err = capsys.readouterr().err
    assert "error:" in err


def test_scope_validate_reports_schema_error(tmp_path, capsys):
    path = tmp_path / "scope.json"
    _write_valid_scope(path, version=2)

    assert main(["scope", "validate", str(path)]) == 1
    err = capsys.readouterr().err
    assert "error:" in err


def test_scope_validate_reports_unknown_fields(tmp_path, capsys):
    path = tmp_path / "scope.json"
    _write_valid_scope(path, extra_field=True)

    assert main(["scope", "validate", str(path)]) == 1
    err = capsys.readouterr().err
    assert "error:" in err


def test_scope_validate_shows_active_flag(tmp_path, capsys):
    path = tmp_path / "scope.json"
    _write_valid_scope(path, allow_active=True)

    assert main(["scope", "validate", str(path)]) == 0
    out = capsys.readouterr().out
    assert "active:      yes" in out


def test_scope_validate_shows_cidr_targets(tmp_path, capsys):
    path = tmp_path / "scope.json"
    _write_valid_scope(path, targets=["10.0.0.0/24", "example.com"])

    assert main(["scope", "validate", str(path)]) == 0
    out = capsys.readouterr().out
    assert "targets:     2" in out
