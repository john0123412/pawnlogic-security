"""Evidence must be append-only and redacted on the way in."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from pawnlogic_security.evidence import SCHEMA_VERSION, EvidenceLog, redact

NOW = 1_000_000.0

# Synthetic credential-shaped strings. None of these is a real key: they are
# fixed filler and AWS's own documentation example, kept here because redaction
# cannot be tested without something shaped like a credential.
SECRETS = [
    "sk-ant-abcdefghijklmnopqrstuvwxyz012345",
    "ghp_abcdefghijklmnopqrstuvwxyz0123456789",
    "AKIAIOSFODNN7EXAMPLE",
    "AIzaSyA1234567890abcdefghijklmnopqrstuvw",
]


@pytest.mark.parametrize("secret", SECRETS)
def test_credential_shapes_are_redacted(secret: str):
    assert secret not in str(redact(f"authorization header was {secret}"))


def test_credential_keys_are_redacted_regardless_of_value_shape():
    out = redact({"api_key": "short", "Authorization": "x", "note": "fine"})
    assert out == {
        "api_key": "[redacted]",
        "Authorization": "[redacted]",
        "note": "fine",
    }


def test_url_embedded_credentials_are_redacted():
    assert "hunter2" not in str(redact("https://admin:hunter2@lab.example.com/x"))


def test_redaction_reaches_nested_values():
    payload = {"outer": [{"inner": f"token {SECRETS[0]}"}]}
    assert SECRETS[0] not in json.dumps(redact(payload))


def test_records_are_written_redacted_not_merely_rendered_redacted(tmp_path: Path):
    """A secret must never reach disk, so redaction runs before the write."""
    path = tmp_path / "evidence.jsonl"
    log = EvidenceLog(path=path)
    log.record(
        recorded_at=NOW,
        scope_id="eng-1",
        action="security_passive_recon",
        target="lab.example.com",
        outcome="allowed",
        detail={"token": SECRETS[0], "note": f"saw {SECRETS[1]}"},
    )
    raw = path.read_text(encoding="utf-8")
    for secret in (SECRETS[0], SECRETS[1]):
        assert secret not in raw
    assert json.loads(raw)["schema_version"] == SCHEMA_VERSION


def test_the_log_exposes_no_mutation_api():
    log = EvidenceLog()
    for forbidden in ("update", "delete", "remove", "clear", "pop", "__setitem__"):
        assert not hasattr(log, forbidden), forbidden


def test_returned_records_cannot_mutate_the_log():
    log = EvidenceLog()
    log.record(
        recorded_at=NOW,
        scope_id="eng-1",
        action="a",
        target="lab.example.com",
        outcome="allowed",
    )
    records = log.records
    assert isinstance(records, tuple)
    with pytest.raises((AttributeError, TypeError)):
        records[0].outcome = "refused"  # type: ignore[misc]
    assert len(log) == 1


def test_timestamps_come_from_the_caller():
    """Pure logic must not read the clock, or tests cannot be deterministic."""
    log = EvidenceLog()
    entry = log.record(
        recorded_at=12345.0,
        scope_id="eng-1",
        action="a",
        target="lab.example.com",
        outcome="allowed",
    )
    assert entry.recorded_at == 12345.0


def test_record_detail_is_immutable():
    log = EvidenceLog()
    entry = log.record(
        recorded_at=NOW,
        scope_id="eng-1",
        action="a",
        target="lab.example.com",
        outcome="allowed",
        detail={"key": "value", "nested": {"inner": 42}},
    )
    # detail is stored as a frozen tuple, not a mutable dict
    assert isinstance(entry.detail, tuple)
    # attempting to mutate it raises
    with pytest.raises((AttributeError, TypeError)):
        entry.detail["key"] = "changed"  # type: ignore[index]


def test_record_detail_round_trips_through_json():
    log = EvidenceLog()
    entry = log.record(
        recorded_at=NOW,
        scope_id="eng-1",
        action="a",
        target="lab.example.com",
        outcome="allowed",
        detail={"key": "value", "count": 3},
    )
    parsed = json.loads(entry.to_json())
    assert parsed["detail"] == {"key": "value", "count": 3}


def test_evidence_file_is_created_with_restrictive_permissions(tmp_path: Path):
    import os
    import stat

    path = tmp_path / "security" / "evidence.jsonl"
    log = EvidenceLog(path=path)
    log.record(
        recorded_at=NOW,
        scope_id="eng-1",
        action="a",
        target="lab.example.com",
        outcome="allowed",
    )
    assert path.exists()
    mode = stat.S_IMODE(os.stat(path).st_mode)
    assert mode == 0o600, f"expected 0600, got {oct(mode)}"


def test_evidence_directory_is_created_with_restrictive_permissions(tmp_path: Path):
    import os
    import stat

    path = tmp_path / "security" / "evidence.jsonl"
    log = EvidenceLog(path=path)
    log.record(
        recorded_at=NOW,
        scope_id="eng-1",
        action="a",
        target="lab.example.com",
        outcome="allowed",
    )
    mode = stat.S_IMODE(os.stat(path.parent).st_mode)
    assert mode == 0o700, f"expected 0700, got {oct(mode)}"
