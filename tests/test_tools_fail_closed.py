"""Tool handlers must fail closed with the real host policy in the loop.

These tests deliberately use the real ``core.network_policy.NetworkPolicy``
rather than a stub. A stub would prove only that the adapter calls something;
it would not prove the host actually refuses the operation.
"""

from __future__ import annotations

import pytest
from core.network_policy import NetworkPolicy

from pawnlogic_security.evidence import EvidenceLog
from pawnlogic_security.scope import EngagementScope
from pawnlogic_security.tools import (
    SecurityToolContext,
    make_active_discovery_handler,
    make_passive_recon_handler,
)

NOW = 1_000_000.0
LATER = NOW + 3600.0


def clock() -> float:
    return NOW


def make_context(
    *,
    scope: EngagementScope | None,
    interactive: bool = False,
) -> SecurityToolContext:
    return SecurityToolContext(
        policy=NetworkPolicy(),
        evidence=EvidenceLog(),
        clock=clock,
        scope=scope,
        interactive=interactive,
    )


def passive_scope(**overrides: object) -> EngagementScope:
    defaults: dict[str, object] = {
        "identifier": "eng-1",
        "targets": frozenset({"lab.example.com"}),
        "expires_at": LATER,
        "authorized_by": "operator",
    }
    defaults.update(overrides)
    return EngagementScope(**defaults)  # type: ignore[arg-type]


def test_passive_recon_without_a_scope_is_refused():
    handler = make_passive_recon_handler(make_context(scope=None))
    result = handler({"target": "https://lab.example.com"})
    assert "refused" in result
    assert "scope:no_scope" in result


def test_passive_recon_with_an_expired_scope_is_refused():
    scope = passive_scope(expires_at=NOW - 1.0)
    handler = make_passive_recon_handler(make_context(scope=scope))
    result = handler({"target": "https://lab.example.com"})
    assert "refused" in result
    assert "scope:expired" in result


def test_passive_recon_outside_the_scope_is_refused():
    handler = make_passive_recon_handler(make_context(scope=passive_scope()))
    result = handler({"target": "https://not-in-scope.example.com"})
    assert "refused" in result
    assert "scope:not_in_scope" in result


def test_active_discovery_requires_a_scope_permitting_active_work():
    """A passive scope must not authorize active probing."""
    handler = make_active_discovery_handler(make_context(scope=passive_scope()))
    result = handler({"target": "https://lab.example.com"})
    assert "refused" in result
    assert "scope:active_not_permitted" in result


def test_active_discovery_is_refused_non_interactively_even_when_in_scope():
    """Non-interactive confirmation must fail closed, not assume yes."""
    scope = passive_scope(allow_active=True)
    handler = make_active_discovery_handler(
        make_context(scope=scope, interactive=False)
    )
    result = handler({"target": "https://lab.example.com"})
    assert "refused" in result


def test_in_scope_passive_recon_is_allowed_and_recorded():
    context = make_context(scope=passive_scope())
    handler = make_passive_recon_handler(context)
    result = handler({"target": "https://lab.example.com"})
    assert "allowed" in result
    assert len(context.evidence) == 1
    assert context.evidence.records[0].outcome == "allowed"


def test_refusals_are_recorded_as_evidence_too():
    context = make_context(scope=None)
    make_passive_recon_handler(context)({"target": "https://lab.example.com"})
    assert len(context.evidence) == 1
    assert context.evidence.records[0].outcome == "refused"


@pytest.mark.parametrize(
    "target",
    [
        "http://169.254.169.254/latest/meta-data/",  # cloud metadata
        "https://admin:hunter2@lab.example.com/",  # embedded credentials
        "http://127.0.0.1:8080/",  # loopback
        "http://[::1]/",  # loopback v6
    ],
)
def test_host_network_policy_still_refuses_dangerous_targets_in_scope(target: str):
    """Being named by a scope does not override the host Network Policy."""
    from pawnlogic_security.scope import normalize_target

    host = normalize_target(target)
    # Put the dangerous host itself in scope, so only the host policy can
    # refuse it. This is the case that matters: scope must not be a bypass.
    scope = passive_scope(targets=frozenset({host}), allow_active=False)
    handler = make_passive_recon_handler(make_context(scope=scope))
    assert "refused" in handler({"target": target})


def test_tool_arguments_cannot_assert_their_own_authorization():
    """Extra argument keys must not be read as an authorization signal."""
    handler = make_passive_recon_handler(make_context(scope=None))
    hostile = {
        "target": "https://lab.example.com",
        "authorized": True,
        "scope_valid": True,
        "explicit_authorization": True,
        "engagement_scope": "eng-1",
    }
    result = handler(hostile)
    assert "refused" in result
    assert "scope:no_scope" in result


def test_a_missing_target_is_refused():
    handler = make_passive_recon_handler(make_context(scope=passive_scope()))
    assert "refused" in handler({})
