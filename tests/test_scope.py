"""Engagement Scope must deny by default and never widen itself."""

from __future__ import annotations

import pytest

from pawnlogic_security.scope import (
    EngagementScope,
    ScopeDenial,
    authorize,
    normalize_target,
)

NOW = 1_000_000.0
LATER = NOW + 3600.0


def make_scope(**overrides: object) -> EngagementScope:
    defaults: dict[str, object] = {
        "identifier": "eng-1",
        "targets": frozenset({"lab.example.com"}),
        "expires_at": LATER,
        "authorized_by": "operator",
    }
    defaults.update(overrides)
    return EngagementScope(**defaults)  # type: ignore[arg-type]


def test_absent_scope_denies():
    decision = authorize(None, "lab.example.com", NOW)
    assert decision.authorized is False
    assert decision.denial is ScopeDenial.NO_SCOPE


def test_expired_scope_denies_even_for_a_named_target():
    scope = make_scope()
    decision = scope.is_authorized("lab.example.com", now=scope.expires_at)
    assert decision.authorized is False
    assert decision.denial is ScopeDenial.EXPIRED


def test_target_outside_the_scope_denies():
    decision = make_scope().is_authorized("other.example.com", NOW)
    assert decision.authorized is False
    assert decision.denial is ScopeDenial.NOT_IN_SCOPE


def test_named_target_within_validity_is_authorized():
    decision = make_scope().is_authorized("lab.example.com", NOW)
    assert decision.authorized is True
    assert decision.denial is None
    assert decision.normalized_target == "lab.example.com"


@pytest.mark.parametrize(
    "target",
    [
        "",
        "   ",
        "http://",
        "not a host",
        "/etc/passwd",
    ],
)
def test_malformed_targets_deny_rather_than_raise(target: str):
    decision = make_scope().is_authorized(target, NOW)
    assert decision.authorized is False
    assert decision.denial in {
        ScopeDenial.MALFORMED_TARGET,
        ScopeDenial.NOT_IN_SCOPE,
    }


def test_subdomain_is_not_implicitly_in_scope():
    """A scope naming a host must not cover hosts it never named."""
    decision = make_scope().is_authorized("admin.lab.example.com", NOW)
    assert decision.authorized is False
    assert decision.denial is ScopeDenial.NOT_IN_SCOPE


def test_scope_is_immutable():
    scope = make_scope()
    with pytest.raises((AttributeError, TypeError)):
        scope.targets = frozenset({"anything.example.com"})  # type: ignore[misc]


def test_scope_requires_at_least_one_target():
    with pytest.raises(ValueError):
        make_scope(targets=frozenset())


def test_scope_rejects_unusable_targets_at_construction():
    with pytest.raises(ValueError):
        make_scope(targets=frozenset({"not a host"}))


def test_scope_requires_an_authorization_record():
    with pytest.raises(ValueError):
        make_scope(authorized_by="  ")


def test_active_work_is_off_by_default():
    assert make_scope().allow_active is False


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("https://Lab.Example.COM/path", "lab.example.com"),
        ("lab.example.com.", "lab.example.com"),
        ("lab.example.com:8443", "lab.example.com"),
        ("https://user:pass@lab.example.com", "lab.example.com"),
    ],
)
def test_normalization_is_consistent(raw: str, expected: str):
    assert normalize_target(raw) == expected


def test_url_credentials_do_not_change_the_matched_host():
    """A credential in the URL must not smuggle in a different host."""
    decision = make_scope().is_authorized("https://user:pass@lab.example.com", NOW)
    assert decision.authorized is True
    assert decision.normalized_target == "lab.example.com"


@pytest.mark.parametrize(
    "raw",
    ["::1", "[::1]", "http://[::1]/", "127.0.0.1", "http://127.0.0.1:8080/"],
)
def test_normalization_is_idempotent(raw: str):
    """Normalizing an already-normalized host must not fail.

    A bare IPv6 literal round-trips through this function whenever a caller
    normalizes a target and then builds a scope from the result, so the second
    pass has to be a no-op rather than a parse error.
    """
    once = normalize_target(raw)
    assert once, raw
    assert normalize_target(once) == once


def test_ipv6_forms_compare_equal():
    scope = make_scope(targets=frozenset({"::1"}))
    assert scope.is_authorized("http://[::1]/", NOW).authorized is True
