"""Regression tests for the runtime Engagement Scope contract."""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from pathlib import Path
from threading import Event

import pytest

from pawnlogic_security.scope import EngagementScope, from_scope_file
from pawnlogic_security.scope_file import validate
from pawnlogic_security.scope_manager import ScopeManager


def _scope_document(**overrides: object) -> dict[str, object]:
    document: dict[str, object] = {
        "version": 1,
        "identifier": "eng-001",
        "authorized_by": "operator",
        "reference": "ticket-001",
        "expires_at": 9_999_999_999.0,
        "targets": ["example.com", "93.184.216.0/24"],
        "exclude": [],
        "ports": ["443", "8000-8002"],
        "allow_active": True,
        "actions": ["passive", "active"],
        "destructive": False,
        "max_requests": 5,
        "max_concurrency": 2,
        "max_duration": 60,
        "evidence_dir": "evidence/eng-001",
    }
    document.update(overrides)
    return document


def _write_scope(path: Path, **overrides: object) -> None:
    path.write_text(json.dumps(_scope_document(**overrides)), encoding="utf-8")


def test_scope_file_conversion_preserves_every_authorization_field() -> None:
    scope_file = validate(_scope_document())

    scope = from_scope_file(scope_file, clock=1000.0)

    assert scope.ports == (443, (8000, 8002))
    assert scope.actions == frozenset({"passive", "active"})
    assert scope.destructive is False
    assert scope.max_requests == 5
    assert scope.max_concurrency == 2
    assert scope.max_duration == 60
    assert scope.evidence_dir == "evidence/eng-001"


@pytest.mark.parametrize("ports", [["0"], ["65536"], ["443-80"], ["abc"], ["80", "80"]])
def test_scope_file_rejects_invalid_or_duplicate_ports(ports: list[str]) -> None:
    with pytest.raises(ValueError, match="port"):
        from_scope_file(validate(_scope_document(ports=ports)), clock=1000.0)


def test_active_scope_requires_explicit_ports() -> None:
    with pytest.raises(ValueError, match="ports"):
        from_scope_file(validate(_scope_document(ports=[])), clock=1000.0)


def test_active_flag_and_actions_cannot_disagree() -> None:
    with pytest.raises(ValueError, match="active"):
        from_scope_file(
            validate(_scope_document(allow_active=False, actions=["passive", "active"])),
            clock=1000.0,
        )


def test_destructive_scope_is_rejected_until_destructive_workflows_exist() -> None:
    with pytest.raises(ValueError, match="destructive"):
        from_scope_file(validate(_scope_document(destructive=True)), clock=1000.0)


def test_scope_rejects_non_positive_runtime_budgets() -> None:
    for field in ("max_requests", "max_concurrency", "max_duration"):
        with pytest.raises(ValueError, match=field):
            validate(_scope_document(**{field: 0}))


def test_explicit_url_port_must_be_in_scope() -> None:
    scope = from_scope_file(validate(_scope_document()), clock=1000.0)

    assert scope.is_authorized("https://example.com:443/", 1000.0).authorized
    denied = scope.is_authorized("https://example.com:444/", 1000.0)
    assert denied.authorized is False
    assert denied.denial is not None
    assert denied.denial.value == "port_not_in_scope"


def test_request_budget_is_shared_across_calls(tmp_path: Path) -> None:
    path = tmp_path / "scope.json"
    _write_scope(path, max_requests=3)
    manager = ScopeManager(clock=lambda: 1000.0)
    manager.set_scope(path)

    assert manager.consume_requests(2) is None
    assert manager.consume_requests(1) is None
    with pytest.raises(PermissionError, match="request budget"):
        manager.consume_requests(1)
    assert "3/3" in manager.format_status()


def test_wall_clock_budget_is_enforced(tmp_path: Path) -> None:
    now = [1000.0]
    path = tmp_path / "scope.json"
    _write_scope(path, expires_at=2000.0, max_duration=10)
    manager = ScopeManager(clock=lambda: now[0])
    manager.set_scope(path)
    now[0] = 1010.0

    with pytest.raises(PermissionError, match="duration"):
        manager.consume_requests(1)


@dataclass
class _Status:
    error: str | None = None


def test_failed_set_recontribution_restores_previous_scope(tmp_path: Path) -> None:
    first = tmp_path / "first.json"
    second = tmp_path / "second.json"
    _write_scope(first, identifier="first", targets=["example.com"])
    _write_scope(second, identifier="second", targets=["other.example.com"])
    results = iter((_Status(), _Status("duplicate command")))
    manager = ScopeManager(
        clock=lambda: 1000.0,
        recontribute=lambda: next(results),
    )
    manager.set_scope(first)

    with pytest.raises(ValueError, match="re-contribution failed"):
        manager.set_scope(second)

    assert manager.scope is not None
    assert manager.scope.identifier == "first"
    assert manager.authorize_target("example.com").authorized


def test_failed_clear_recontribution_restores_scope(tmp_path: Path) -> None:
    path = tmp_path / "scope.json"
    _write_scope(path)
    results = iter((_Status(), _Status("registry unavailable")))
    manager = ScopeManager(
        clock=lambda: 1000.0,
        recontribute=lambda: next(results),
    )
    manager.set_scope(path)

    with pytest.raises(ValueError, match="re-contribution failed"):
        manager.clear_scope()

    assert manager.scope is not None
    assert manager.scope.identifier == "eng-001"


def test_scope_value_validates_directly_supplied_ports() -> None:
    with pytest.raises(ValueError, match="port"):
        EngagementScope(
            identifier="bad-port",
            targets=frozenset({"example.com"}),
            expires_at=2000.0,
            authorized_by="operator",
            ports=(70000,),
            max_requests=1,
            max_concurrency=1,
            max_duration=1,
        )


def test_scope_expiry_triggers_tool_withdrawal_callback(tmp_path: Path) -> None:
    path = tmp_path / "scope.json"
    _write_scope(path, expires_at=time.time() + 0.1)
    expired = Event()
    calls: list[int] = []

    def recontribute() -> None:
        calls.append(1)
        if len(calls) == 2:
            expired.set()

    manager = ScopeManager(recontribute=recontribute)
    manager.set_scope(path)

    assert expired.wait(1.0)
    assert manager.scope is None
    assert calls == [1, 1]
    manager.close()


def test_evidence_directory_is_resolved_from_the_scope_file(tmp_path: Path) -> None:
    scope_dir = tmp_path / "engagement"
    scope_dir.mkdir()
    path = scope_dir / "scope.json"
    _write_scope(path, evidence_dir="records")
    manager = ScopeManager(clock=lambda: 1000.0)
    manager.set_scope(path)

    evidence_path = manager.evidence_path(tmp_path / "fallback.jsonl")

    assert evidence_path == scope_dir / "records" / "evidence.jsonl"
