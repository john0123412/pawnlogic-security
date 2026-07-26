"""Append-only evidence records for security work.

Evidence is written once and never edited. Timestamps are supplied by the
caller so records are reproducible in tests and so this module never depends on
wall-clock time.

Every value is redacted before it is stored. Redaction runs on the way in, not
on the way out, because a record that was never written cannot leak later.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterator, Mapping
from dataclasses import dataclass, field
from pathlib import Path

SCHEMA_VERSION = 1

_REDACTED = "[redacted]"

# Credential shapes worth catching before anything reaches disk. This is a
# safety net, not a licence to pass secrets in: callers should not put
# credentials in evidence at all.
_SECRET_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"sk-ant-[A-Za-z0-9_-]{20,}"),
    re.compile(r"sk-(?:proj-|svcacct-|live-)?[A-Za-z0-9_-]{20,}"),
    re.compile(r"ghp_[A-Za-z0-9]{36}"),
    re.compile(r"github_pat_[A-Za-z0-9_]{50,}"),
    re.compile(r"AIza[A-Za-z0-9_-]{35}"),
    re.compile(r"A(?:KIA|SIA)[0-9A-Z]{16}"),
    re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
    # Credentials embedded in a URL, for example https://user:pass@host.
    re.compile(r"(?<=://)[^/\s:@]+:[^/\s@]+(?=@)"),
)

# Keys whose value is redacted regardless of shape.
_SECRET_KEY_HINTS: frozenset[str] = frozenset(
    {
        "api_key",
        "apikey",
        "authorization",
        "cookie",
        "credential",
        "password",
        "passwd",
        "private_key",
        "secret",
        "session",
        "token",
    }
)


def _key_is_secret(key: str) -> bool:
    lowered = key.lower()
    return any(hint in lowered for hint in _SECRET_KEY_HINTS)


def redact_text(value: str) -> str:
    for pattern in _SECRET_PATTERNS:
        value = pattern.sub(_REDACTED, value)
    return value


def redact(value: object) -> object:
    """Recursively redact credential-shaped data in a JSON-compatible value."""
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, Mapping):
        return {
            str(key): _REDACTED if _key_is_secret(str(key)) else redact(item)
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [redact(item) for item in value]
    if value is None or isinstance(value, (bool, int, float)):
        return value
    # Anything else is stringified first so an unexpected object cannot smuggle
    # a credential through its repr.
    return redact_text(str(value))


@dataclass(frozen=True, slots=True)
class EvidenceRecord:
    """One immutable observation, already redacted."""

    schema_version: int
    recorded_at: float
    scope_id: str
    action: str
    target: str
    outcome: str
    detail: dict[str, object] = field(default_factory=dict)

    def to_json(self) -> str:
        return json.dumps(
            {
                "schema_version": self.schema_version,
                "recorded_at": self.recorded_at,
                "scope_id": self.scope_id,
                "action": self.action,
                "target": self.target,
                "outcome": self.outcome,
                "detail": self.detail,
            },
            ensure_ascii=False,
            sort_keys=True,
        )


class EvidenceLog:
    """An append-only evidence log.

    Records are held in memory and optionally mirrored to a JSONL file. There
    is no update or delete operation, by design.
    """

    def __init__(self, path: Path | None = None) -> None:
        self._path = path
        self._records: list[EvidenceRecord] = []

    def record(
        self,
        *,
        recorded_at: float,
        scope_id: str,
        action: str,
        target: str,
        outcome: str,
        detail: Mapping[str, object] | None = None,
    ) -> EvidenceRecord:
        """Append one record, redacting every field before it is stored."""
        redacted_detail = redact(dict(detail or {}))
        assert isinstance(redacted_detail, dict)  # redact preserves mappings
        entry = EvidenceRecord(
            schema_version=SCHEMA_VERSION,
            recorded_at=float(recorded_at),
            scope_id=redact_text(str(scope_id)),
            action=redact_text(str(action)),
            target=redact_text(str(target)),
            outcome=redact_text(str(outcome)),
            detail=redacted_detail,
        )
        self._records.append(entry)
        if self._path is not None:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            with self._path.open("a", encoding="utf-8") as handle:
                handle.write(entry.to_json() + "\n")
        return entry

    def __len__(self) -> int:
        return len(self._records)

    def __iter__(self) -> Iterator[EvidenceRecord]:
        return iter(tuple(self._records))

    @property
    def records(self) -> tuple[EvidenceRecord, ...]:
        return tuple(self._records)


__all__ = [
    "SCHEMA_VERSION",
    "EvidenceLog",
    "EvidenceRecord",
    "redact",
    "redact_text",
]
