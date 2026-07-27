"""Tests for the runtime scope manager and scope file format."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from pawnlogic_security.scope import EngagementScope, ScopeDenial
from pawnlogic_security.scope_file import ScopeFile, load, save, validate
from pawnlogic_security.scope_manager import ScopeManager

# -- Scope file format tests -------------------------------------------------


def _valid_scope_data(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
        "version": 1,
        "identifier": "test-engagement",
        "authorized_by": "tester",
        "reference": "ticket-123",
        "expires_at": 9999999999.0,
        "targets": ["example.com", "10.0.0.0/24"],
        "exclude": ["internal.example.com"],
        "ports": ["80", "443", "8000-9000"],
        "allow_active": False,
        "actions": ["passive"],
        "destructive": False,
        "max_requests": 1000,
        "max_concurrency": 10,
        "max_duration": 3600,
        "evidence_dir": "runs/engagement-001",
        "metadata": {"team": "red"},
    }
    base.update(overrides)
    return base


def test_validate_accepts_a_complete_scope_file():
    data = _valid_scope_data()
    scope_file = validate(data)

    assert isinstance(scope_file, ScopeFile)
    assert scope_file.identifier == "test-engagement"
    assert scope_file.authorized_by == "tester"
    assert scope_file.targets == ("example.com", "10.0.0.0/24")
    assert scope_file.exclude == ("internal.example.com",)
    assert scope_file.ports == ("80", "443", "8000-9000")
    assert scope_file.allow_active is False
    assert scope_file.actions == frozenset({"passive"})
    assert scope_file.max_requests == 1000
    assert scope_file.metadata == {"team": "red"}


def test_validate_rejects_unknown_fields():
    data = _valid_scope_data(sneaky_field=True)
    with pytest.raises(ValueError, match="unknown field.*sneaky_field"):
        validate(data)


def test_validate_rejects_wrong_version():
    data = _valid_scope_data(version=2)
    with pytest.raises(ValueError, match="version must be 1"):
        validate(data)


def test_validate_rejects_missing_identifier():
    data = _valid_scope_data()
    del data["identifier"]
    with pytest.raises(ValueError, match="identifier must be a non-empty string"):
        validate(data)


def test_validate_rejects_empty_targets():
    data = _valid_scope_data(targets=[])
    with pytest.raises(ValueError, match="targets must contain at least one entry"):
        validate(data)


def test_validate_rejects_unknown_actions():
    data = _valid_scope_data(actions=["passive", "exploit"])
    with pytest.raises(ValueError, match="unknown actions"):
        validate(data)


def test_validate_rejects_negative_max_requests():
    data = _valid_scope_data(max_requests=-1)
    with pytest.raises(ValueError, match="max_requests"):
        validate(data)


def test_validate_rejects_non_mapping_metadata():
    data = _valid_scope_data(metadata="not a mapping")
    with pytest.raises(ValueError, match="metadata must be a mapping"):
        validate(data)


def test_validate_accepts_minimal_scope():
    data = {
        "version": 1,
        "identifier": "min",
        "authorized_by": "me",
        "expires_at": 9999999999.0,
        "targets": ["a.example.com"],
    }
    scope_file = validate(data)
    assert scope_file.identifier == "min"
    assert scope_file.exclude == ()
    assert scope_file.ports == ()
    assert scope_file.actions == frozenset()
    assert scope_file.max_requests == 0


def test_load_and_save_round_trip(tmp_path: Path):
    path = tmp_path / "scope.json"
    scope_file = validate(_valid_scope_data())
    save(path, scope_file)
    assert path.exists()
    loaded = load(path)
    assert loaded.identifier == scope_file.identifier
    assert loaded.targets == scope_file.targets
    assert loaded.exclude == scope_file.exclude


def test_load_rejects_malformed_json(tmp_path: Path):
    path = tmp_path / "bad.json"
    path.write_text("{not json", encoding="utf-8")
    with pytest.raises(ValueError, match="not valid JSON"):
        load(path)


def test_load_rejects_nonexistent_file():
    with pytest.raises(ValueError, match="cannot read scope file"):
        load(Path("/nonexistent/scope.json"))


# -- EngagementScope CIDR and exclusion tests --------------------------------


def test_scope_accepts_cidr_targets():
    scope = EngagementScope(
        identifier="cidr-test",
        targets=frozenset(["10.0.0.0/24"]),
        expires_at=9999999999.0,
        authorized_by="tester",
    )
    assert scope.is_authorized("10.0.0.1", 0.0).authorized is True
    assert scope.is_authorized("10.0.0.254", 0.0).authorized is True
    assert scope.is_authorized("10.0.1.1", 0.0).denial is ScopeDenial.NOT_IN_SCOPE


def test_scope_exclusion_overrides_target():
    scope = EngagementScope(
        identifier="excl-test",
        targets=frozenset(["example.com", "10.0.0.0/24"]),
        expires_at=9999999999.0,
        authorized_by="tester",
        exclude=frozenset(["internal.example.com", "10.0.0.1"]),
    )
    assert scope.is_authorized("example.com", 0.0).authorized is True
    assert (
        scope.is_authorized("internal.example.com", 0.0).denial is ScopeDenial.EXCLUDED
    )
    assert scope.is_authorized("10.0.0.1", 0.0).denial is ScopeDenial.EXCLUDED
    assert scope.is_authorized("10.0.0.2", 0.0).authorized is True


def test_scope_cidr_exclusion_overrides_cidr_target():
    scope = EngagementScope(
        identifier="cidr-excl",
        targets=frozenset(["10.0.0.0/24"]),
        expires_at=9999999999.0,
        authorized_by="tester",
        exclude=frozenset(["10.0.0.128/25"]),
    )
    assert scope.is_authorized("10.0.0.1", 0.0).authorized is True
    assert scope.is_authorized("10.0.0.200", 0.0).denial is ScopeDenial.EXCLUDED


def test_scope_rejects_malformed_exclusion():
    with pytest.raises(ValueError, match="exclusion is not a usable host or CIDR"):
        EngagementScope(
            identifier="bad-excl",
            targets=frozenset(["example.com"]),
            expires_at=9999999999.0,
            authorized_by="tester",
            exclude=frozenset(["not a host!@#"]),
        )


# -- ScopeManager tests -----------------------------------------------------


def _scope_file_json(*, expires_at: float = 9999999999.0) -> str:
    return json.dumps(
        {
            "version": 1,
            "identifier": "test-engagement",
            "authorized_by": "tester",
            "expires_at": expires_at,
            "targets": ["example.com"],
        }
    )


def test_manager_starts_with_no_scope():
    manager = ScopeManager()
    assert manager.scope is None
    assert manager.is_active is False
    assert "no scope" in manager.format_status()


def test_manager_set_scope_loads_and_activates(tmp_path: Path):
    path = tmp_path / "scope.json"
    path.write_text(_scope_file_json(), encoding="utf-8")
    manager = ScopeManager()

    result = manager.set_scope(path)

    assert manager.scope is not None
    assert manager.is_active is True
    assert "test-engagement" in result
    assert "example.com" in result or "1" in result


def test_manager_set_scope_rejects_expired_file(tmp_path: Path):
    path = tmp_path / "scope.json"
    path.write_text(_scope_file_json(expires_at=1.0), encoding="utf-8")
    manager = ScopeManager()

    with pytest.raises(ValueError, match="already expired"):
        manager.set_scope(path)

    assert manager.scope is None


def test_manager_clear_scope_withdraws(tmp_path: Path):
    path = tmp_path / "scope.json"
    path.write_text(_scope_file_json(), encoding="utf-8")
    manager = ScopeManager()
    manager.set_scope(path)
    assert manager.is_active is True

    result = manager.clear_scope()

    assert manager.scope is None
    assert manager.is_active is False
    assert "cleared" in result
    assert "no scope" in manager.format_status()


def test_manager_clear_when_none_is_idempotent():
    manager = ScopeManager()
    assert "no scope" in manager.clear_scope()
    assert manager.scope is None


def test_manager_set_scope_triggers_recontribution(tmp_path: Path):
    path = tmp_path / "scope.json"
    path.write_text(_scope_file_json(), encoding="utf-8")
    calls: list[int] = []
    manager = ScopeManager(recontribute=lambda: calls.append(1))

    manager.set_scope(path)
    assert calls == [1]


def test_manager_clear_scope_triggers_recontribution(tmp_path: Path):
    path = tmp_path / "scope.json"
    path.write_text(_scope_file_json(), encoding="utf-8")
    calls: list[int] = []
    manager = ScopeManager(recontribute=lambda: calls.append(1))
    manager.set_scope(path)
    calls.clear()

    manager.clear_scope()
    assert calls == [1]


def test_manager_authorize_delegates_to_scope(tmp_path: Path):
    path = tmp_path / "scope.json"
    path.write_text(_scope_file_json(), encoding="utf-8")
    manager = ScopeManager()
    manager.set_scope(path)

    decision = manager.authorize_target("example.com")
    assert decision.authorized is True

    decision = manager.authorize_target("other.com")
    assert decision.authorized is False


def test_manager_authorize_returns_no_scope_when_empty():
    manager = ScopeManager()
    decision = manager.authorize_target("example.com")
    assert decision.denial is ScopeDenial.NO_SCOPE


def test_manager_format_status_shows_scope_details(tmp_path: Path):
    path = tmp_path / "scope.json"
    data = json.loads(_scope_file_json())
    data["exclude"] = ["internal.example.com"]
    data["max_requests"] = 500
    data["max_concurrency"] = 5
    data["max_duration"] = 1800
    data["evidence_dir"] = "runs/001"
    path.write_text(json.dumps(data), encoding="utf-8")
    manager = ScopeManager()
    manager.set_scope(path)

    status = manager.format_status()
    assert "test-engagement" in status
    assert "targets:" in status
    assert "1 entries" in status  # exclude count
    assert "500" in status
    assert "5" in status
    assert "1800" in status
    assert "runs/001" in status


def test_manager_set_scope_rejects_nonexistent_file():
    manager = ScopeManager()
    with pytest.raises(ValueError, match="cannot read scope file"):
        manager.set_scope(Path("/nonexistent/scope.json"))


def test_manager_set_scope_rejects_malformed_file(tmp_path: Path):
    path = tmp_path / "bad.json"
    path.write_text("{bad json", encoding="utf-8")
    manager = ScopeManager()
    with pytest.raises(ValueError):
        manager.set_scope(path)


def test_manager_set_scope_rejects_missing_version(tmp_path: Path):
    path = tmp_path / "scope.json"
    path.write_text(
        json.dumps(
            {
                "identifier": "x",
                "authorized_by": "y",
                "expires_at": 9999999999.0,
                "targets": ["a.com"],
            }
        ),
        encoding="utf-8",
    )
    manager = ScopeManager()
    with pytest.raises(ValueError, match="version must be 1"):
        manager.set_scope(path)


def test_manager_replaces_scope_on_second_set(tmp_path: Path):
    path1 = tmp_path / "scope1.json"
    path2 = tmp_path / "scope2.json"
    path1.write_text(_scope_file_json(), encoding="utf-8")
    data2 = json.loads(_scope_file_json())
    data2["identifier"] = "second-engagement"
    data2["targets"] = ["other.com"]
    path2.write_text(json.dumps(data2), encoding="utf-8")
    manager = ScopeManager()

    manager.set_scope(path1)
    assert manager.authorize_target("example.com").authorized is True
    assert manager.authorize_target("other.com").authorized is False

    manager.set_scope(path2)
    assert manager.authorize_target("example.com").authorized is False
    assert manager.authorize_target("other.com").authorized is True
