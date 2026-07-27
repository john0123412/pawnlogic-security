"""Versioned Engagement Scope file format.

A scope file is a JSON document with a top-level ``version`` field and every
field the authorization contract requires. Unknown keys are rejected because a
silently ignored field is a field someone thinks was read.

This module owns validation and file I/O only. It never creates an
``EngagementScope`` on its own, because the caller may need to supply a clock,
an identifier override, or other runtime state the file cannot express.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 1

_KNOWN_TOP_KEYS: frozenset[str] = frozenset(
    {
        "version",
        "identifier",
        "authorized_by",
        "reference",
        "expires_at",
        "targets",
        "exclude",
        "ports",
        "allow_active",
        "actions",
        "destructive",
        "max_requests",
        "max_concurrency",
        "max_duration",
        "evidence_dir",
        "metadata",
    }
)


def _require_string(data: dict[str, Any], key: str, label: str) -> str:
    value = data.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} must be a non-empty string")
    return value.strip()


def _optional_string(data: dict[str, Any], key: str, default: str = "") -> str:
    value = data.get(key, default)
    if not isinstance(value, str):
        raise ValueError(f"'{key}' must be a string")
    return value


def _require_positive_int(data: dict[str, Any], key: str, label: str) -> int:
    value = data.get(key)
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise ValueError(f"{label} must be a positive integer")
    return value


def _optional_positive_int(data: dict[str, Any], key: str, default: int = 0) -> int:
    value = data.get(key, default)
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError(f"'{key}' must be an integer")
    if value < 0:
        raise ValueError(f"'{key}' must be non-negative")
    return value


def _require_string_list(data: dict[str, Any], key: str, label: str) -> tuple[str, ...]:
    value = data.get(key)
    if not isinstance(value, list) or not all(isinstance(s, str) for s in value):
        raise ValueError(f"{label} must be a list of strings")
    return tuple(value)


def _optional_string_list(data: dict[str, Any], key: str) -> tuple[str, ...]:
    value = data.get(key)
    if value is None:
        return ()
    if not isinstance(value, list) or not all(isinstance(s, str) for s in value):
        raise ValueError(f"'{key}' must be a list of strings if present")
    return tuple(value)


def _optional_string_set(data: dict[str, Any], key: str) -> frozenset[str]:
    value = data.get(key)
    if value is None:
        return frozenset()
    if not isinstance(value, list) or not all(isinstance(s, str) for s in value):
        raise ValueError(f"'{key}' must be a list of strings if present")
    return frozenset(value)


@dataclass(frozen=True, slots=True)
class ScopeFile:
    """A validated scope file that has passed schema and content checks.

    The fields are kept in their normalized form. The caller builds an
    ``EngagementScope`` from them, adding whatever runtime state the file
    cannot express.
    """

    identifier: str
    authorized_by: str
    reference: str
    expires_at: float
    targets: tuple[str, ...]
    exclude: tuple[str, ...]
    ports: tuple[str, ...]
    allow_active: bool
    actions: frozenset[str]
    destructive: bool
    max_requests: int
    max_concurrency: int
    max_duration: float
    evidence_dir: str
    metadata: dict[str, str]


def validate(data: dict[str, Any]) -> ScopeFile:
    """Validate a parsed JSON document and return a ``ScopeFile``.

    Raises ``ValueError`` on any schema or content violation. The caller is
    responsible for turning that into a user-facing message.
    """
    unknown = set(data) - _KNOWN_TOP_KEYS
    if unknown:
        raise ValueError(f"unknown field in scope file: {sorted(unknown)[0]}")

    version = data.get("version")
    if not isinstance(version, int) or version != SCHEMA_VERSION:
        raise ValueError(
            f"scope file version must be {SCHEMA_VERSION}, got {version!r}"
        )

    identifier = _require_string(data, "identifier", "identifier")
    authorized_by = _require_string(data, "authorized_by", "authorized_by")
    reference = _optional_string(data, "reference")
    expires_at = data.get("expires_at")
    if not isinstance(expires_at, (int, float)) or isinstance(expires_at, bool):
        raise ValueError("expires_at must be a POSIX timestamp")
    if expires_at <= 0:
        raise ValueError("expires_at must be positive")

    targets = _require_string_list(data, "targets", "targets")
    if not targets:
        raise ValueError("targets must contain at least one entry")
    exclude = _optional_string_list(data, "exclude")
    ports = _optional_string_list(data, "ports")

    allow_active = data.get("allow_active", False)
    if not isinstance(allow_active, bool):
        raise ValueError("allow_active must be a boolean")

    actions = _optional_string_set(data, "actions")
    if actions and not actions.issubset({"passive", "active"}):
        bad = sorted(actions - {"passive", "active"})
        raise ValueError(f"unknown actions: {bad}")

    destructive = data.get("destructive", False)
    if not isinstance(destructive, bool):
        raise ValueError("destructive must be a boolean")

    max_requests = _optional_positive_int(data, "max_requests")
    max_concurrency = _optional_positive_int(data, "max_concurrency")
    max_duration_raw = data.get("max_duration", 0)
    if not isinstance(max_duration_raw, (int, float)) or isinstance(
        max_duration_raw, bool
    ):
        raise ValueError("max_duration must be a non-negative number")
    if max_duration_raw < 0:
        raise ValueError("max_duration must be non-negative")
    evidence_dir = _optional_string(data, "evidence_dir")

    raw_meta = data.get("metadata", {})
    if not isinstance(raw_meta, dict):
        raise ValueError("metadata must be a mapping")
    for key, value in raw_meta.items():
        if not isinstance(key, str) or not isinstance(value, str):
            raise ValueError("metadata keys and values must be strings")

    return ScopeFile(
        identifier=identifier,
        authorized_by=authorized_by,
        reference=reference,
        expires_at=float(expires_at),
        targets=targets,
        exclude=exclude,
        ports=ports,
        allow_active=allow_active,
        actions=actions,
        destructive=destructive,
        max_requests=max_requests,
        max_concurrency=max_concurrency,
        max_duration=float(max_duration_raw),
        evidence_dir=evidence_dir,
        metadata=dict(raw_meta),
    )


def load(path: Path) -> ScopeFile:
    """Read and validate a scope file from disk."""
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as error:
        raise ValueError(f"cannot read scope file: {error}") from error
    try:
        data = json.loads(text)
    except json.JSONDecodeError as error:
        raise ValueError(f"scope file is not valid JSON: {error}") from error
    if not isinstance(data, dict):
        raise ValueError("scope file must be a JSON object")
    return validate(data)


def save(path: Path, scope_file: ScopeFile) -> None:
    """Write a scope file to disk."""
    data: dict[str, Any] = {
        "version": SCHEMA_VERSION,
        "identifier": scope_file.identifier,
        "authorized_by": scope_file.authorized_by,
        "reference": scope_file.reference,
        "expires_at": scope_file.expires_at,
        "targets": list(scope_file.targets),
        "exclude": list(scope_file.exclude),
        "ports": list(scope_file.ports),
        "allow_active": scope_file.allow_active,
        "actions": sorted(scope_file.actions),
        "destructive": scope_file.destructive,
        "max_requests": scope_file.max_requests,
        "max_concurrency": scope_file.max_concurrency,
        "max_duration": scope_file.max_duration,
        "evidence_dir": scope_file.evidence_dir,
        "metadata": scope_file.metadata,
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


__all__ = [
    "SCHEMA_VERSION",
    "ScopeFile",
    "load",
    "save",
    "validate",
]
