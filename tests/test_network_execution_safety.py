"""Network execution must use only addresses rechecked against Scope."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from core.network_policy import NetworkAction, NetworkDecision

from pawnlogic_security.evidence import EvidenceLog
from pawnlogic_security.recon import (
    DnsResult,
    HttpHeadersResult,
    active_port_scan,
    passive_recon,
)
from pawnlogic_security.scope import EngagementScope
from pawnlogic_security.scope_manager import ScopeManager
from pawnlogic_security.tools import SecurityToolContext


def _scope(**overrides: object) -> EngagementScope:
    values: dict[str, object] = {
        "identifier": "eng-001",
        "targets": frozenset({"example.com", "93.184.216.0/24"}),
        "expires_at": 2000.0,
        "authorized_by": "operator",
        "allow_active": True,
        "actions": frozenset({"passive", "active"}),
        "ports": (80, 443),
        "max_requests": 10,
        "max_concurrency": 2,
        "max_duration": 60,
    }
    values.update(overrides)
    return EngagementScope(**values)  # type: ignore[arg-type]


def test_passive_recon_stops_before_connecting_when_any_dns_answer_is_out_of_scope() -> None:
    with (
        patch(
            "pawnlogic_security.recon._resolve_dns",
            return_value=DnsResult(
                hostname="example.com",
                addresses=("93.184.216.34", "203.0.113.9"),
            ),
        ),
        patch("pawnlogic_security.recon._inspect_tls") as tls,
        patch(
            "pawnlogic_security.recon._http_headers",
            return_value=HttpHeadersResult(
                url="https://example.com:443/",
                status=200,
            ),
        ) as http,
    ):
        result = passive_recon("example.com", _scope(), 1000.0)

    tls.assert_not_called()
    http.assert_not_called()
    assert any("203.0.113.9" in error for error in result.errors)


def test_passive_recon_connects_to_the_rechecked_ip_not_the_hostname() -> None:
    with (
        patch(
            "pawnlogic_security.recon._resolve_dns",
            return_value=DnsResult(
                hostname="example.com",
                addresses=("93.184.216.34",),
            ),
        ),
        patch("pawnlogic_security.recon._inspect_tls") as tls,
        patch(
            "pawnlogic_security.recon._http_headers",
            return_value=HttpHeadersResult(
                url="https://example.com:443/",
                status=200,
            ),
        ) as http,
    ):
        passive_recon("example.com", _scope(), 1000.0)

    tls.assert_called_once()
    http.assert_called_once()
    assert tls.call_args.kwargs["address"] == "93.184.216.34"
    assert http.call_args.kwargs["address"] == "93.184.216.34"


def test_active_scan_refuses_when_scope_has_no_explicit_ports() -> None:
    scope = _scope(ports=(), allow_active=False, actions=frozenset({"passive"}))

    results = active_port_scan("example.com", scope, 1000.0)

    assert len(results) == 1
    assert results[0].state == "error"
    assert "active" in results[0].error or "port" in results[0].error


def test_active_scan_does_not_connect_when_dns_answer_leaves_scope() -> None:
    with (
        patch(
            "pawnlogic_security.recon._resolve_dns",
            return_value=DnsResult(
                hostname="example.com",
                addresses=("203.0.113.9",),
            ),
        ),
        patch("pawnlogic_security.recon.socket.socket") as socket_factory,
    ):
        results = active_port_scan("example.com", _scope(), 1000.0)

    socket_factory.assert_not_called()
    assert results[0].state == "error"
    assert "not in scope" in results[0].error


def test_network_policy_receives_scope_authorization_and_resolved_addresses() -> None:
    policy = MagicMock()
    policy.evaluate.return_value = NetworkDecision(
        action=NetworkAction.ALLOW,
        reason="authorized",
        rule="test",
        normalized_target="https://example.com/",
    )
    context = SecurityToolContext(
        policy=policy,
        evidence=EvidenceLog(),
        clock=lambda: 1000.0,
        scope=_scope(),
    )

    result = context.authorize_target(
        action="security_active_discovery",
        target="https://example.com/",
        active_probe=True,
        resolved_addresses=("93.184.216.34",),
    )

    assert result.allowed
    operation = policy.evaluate.call_args.args[0]
    assert operation.explicit_authorization is True
    assert operation.authorized_targets
    assert operation.resolved_addresses == ("93.184.216.34",)
    assert operation.engagement_scope == "eng-001"


def test_success_evidence_is_recorded_after_execution_not_before() -> None:
    policy = MagicMock()
    policy.evaluate.return_value = NetworkDecision(
        action=NetworkAction.ALLOW,
        reason="authorized",
        rule="test",
        normalized_target="https://example.com/",
    )
    evidence = EvidenceLog()
    context = SecurityToolContext(
        policy=policy,
        evidence=evidence,
        clock=lambda: 1000.0,
        scope=_scope(),
    )

    outcome = context.authorize_target(
        action="security_passive_recon",
        target="https://example.com/",
        active_probe=False,
        resolved_addresses=("93.184.216.34",),
    )

    assert outcome.allowed
    assert len(evidence) == 0
    context.record_result(
        action="security_passive_recon",
        target=outcome.target,
        outcome="completed",
        detail={"addresses": ["93.184.216.34"]},
    )
    assert evidence.records[0].outcome == "completed"


@pytest.mark.parametrize("count", [0, -1])
def test_request_consumption_rejects_non_positive_counts(count: int) -> None:
    with pytest.raises(ValueError, match="positive"):
        ScopeManager().consume_requests(count)


def test_active_scan_exhausted_budget_opens_no_sockets(tmp_path) -> None:
    import json

    scope_path = tmp_path / "scope.json"
    scope_path.write_text(
        json.dumps(
            {
                "version": 1,
                "identifier": "budget",
                "authorized_by": "operator",
                "expires_at": 9_999_999_999.0,
                "targets": ["example.com", "93.184.216.0/24"],
                "ports": ["80", "443"],
                "allow_active": True,
                "actions": ["passive", "active"],
                "max_requests": 2,
                "max_concurrency": 1,
                "max_duration": 60,
            }
        ),
        encoding="utf-8",
    )
    manager = ScopeManager(clock=lambda: 1000.0)
    manager.set_scope(scope_path)
    assert manager.scope is not None

    with (
        patch(
            "pawnlogic_security.recon._resolve_dns",
            return_value=DnsResult(
                hostname="example.com",
                addresses=("93.184.216.34",),
            ),
        ),
        patch("pawnlogic_security.recon.socket.socket") as socket_factory,
    ):
        results = active_port_scan(
            "example.com",
            manager.scope,
            1000.0,
            consume_requests=manager.consume_requests,
        )

    socket_factory.assert_not_called()
    assert len(results) == 1
    assert "request budget" in results[0].error
