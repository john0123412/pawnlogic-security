"""Tests for real passive recon and active discovery handlers."""

from __future__ import annotations

from unittest.mock import patch

from core.network_policy import NetworkPolicy

from pawnlogic_security.evidence import EvidenceLog
from pawnlogic_security.scope import EngagementScope
from pawnlogic_security.tools import (
    SecurityToolContext,
    make_active_discovery_handler,
    make_passive_recon_handler,
)


def _scope(*, allow_active: bool = False) -> EngagementScope:
    return EngagementScope(
        identifier="test",
        targets=frozenset(["example.com"]),
        expires_at=9999999999.0,
        authorized_by="tester",
        allow_active=allow_active,
    )


def _context(
    scope: EngagementScope | None = None, *, interactive: bool = False
) -> SecurityToolContext:
    return SecurityToolContext(
        policy=NetworkPolicy(),
        evidence=EvidenceLog(),
        clock=lambda: 1000.0,
        scope=scope,
        interactive=interactive,
    )


def test_passive_recon_refused_without_scope():
    handler = make_passive_recon_handler(_context(scope=None))
    result = handler({"target": "https://example.com/"})
    assert "refused" in result
    assert "no_scope" in result


def test_passive_recon_refused_out_of_scope():
    handler = make_passive_recon_handler(_context(_scope()))
    result = handler({"target": "https://other.com/"})
    assert "refused" in result
    assert "not_in_scope" in result


def test_passive_recon_calls_real_recon_when_allowed():
    from pawnlogic_security.recon import (
        DnsResult,
        HttpHeadersResult,
        PassiveReconResult,
        TlsCertResult,
    )

    mock_result = PassiveReconResult(
        target="example.com",
        dns=DnsResult(hostname="example.com", addresses=("93.184.216.34",)),
        tls=TlsCertResult(
            hostname="example.com",
            port=443,
            subject="example.com",
            issuer="DigiCert",
            not_before="2024",
            not_after="2025",
        ),
        http=HttpHeadersResult(
            url="https://example.com:443/",
            status=200,
            server="ECS",
            technologies=("server: ECS",),
        ),
        scope_addresses=("93.184.216.34",),
    )

    with patch(
        "pawnlogic_security.recon.passive_recon", return_value=mock_result
    ) as mock:
        handler = make_passive_recon_handler(_context(_scope()))
        result = handler({"target": "https://example.com/"})

    mock.assert_called_once()
    assert "passive recon: example.com" in result
    assert "93.184.216.34" in result
    assert "DigiCert" in result
    assert "ECS" in result


def test_active_discovery_refused_without_scope():
    handler = make_active_discovery_handler(_context(scope=None, interactive=False))
    result = handler({"target": "https://example.com/"})
    assert "refused" in result


def test_active_discovery_refused_when_scope_forbids_active():
    handler = make_active_discovery_handler(
        _context(_scope(allow_active=False), interactive=False)
    )
    result = handler({"target": "https://example.com/"})
    assert "refused" in result
    assert "active_not_permitted" in result


def test_active_discovery_calls_port_scan_when_allowed():
    from unittest.mock import MagicMock

    from pawnlogic_security.recon import PortResult
    from pawnlogic_security.tools import ToolOutcome

    mock_results = (
        PortResult(port=80, state="open", service="http"),
        PortResult(port=443, state="open", service="https"),
    )

    ctx = _context(_scope(allow_active=True), interactive=False)
    ctx.authorize_target = MagicMock(
        return_value=ToolOutcome(allowed=True, reason="ok", target="example.com", rule="scope")
    )
    handler = make_active_discovery_handler(ctx)

    with patch(
        "pawnlogic_security.recon.active_port_scan", return_value=mock_results
    ) as mock:
        result = handler({"target": "https://example.com/"})

    mock.assert_called_once()
    assert "port scan: example.com" in result
    assert "80/tcp open" in result
    assert "443/tcp open" in result


def test_active_discovery_reports_no_open_ports():
    from unittest.mock import MagicMock

    from pawnlogic_security.recon import PortResult
    from pawnlogic_security.tools import ToolOutcome

    mock_results = (
        PortResult(port=80, state="closed"),
        PortResult(port=443, state="closed"),
    )

    ctx = _context(_scope(allow_active=True), interactive=False)
    ctx.authorize_target = MagicMock(
        return_value=ToolOutcome(allowed=True, reason="ok", target="example.com", rule="scope")
    )
    handler = make_active_discovery_handler(ctx)

    with patch("pawnlogic_security.recon.active_port_scan", return_value=mock_results):
        result = handler({"target": "https://example.com/"})

    assert "no open ports found" in result


def test_passive_recon_handles_dns_error():
    from pawnlogic_security.recon import DnsResult, PassiveReconResult

    mock_result = PassiveReconResult(
        target="example.com",
        dns=DnsResult(hostname="example.com", error="DNS resolution failed"),
    )

    with patch("pawnlogic_security.recon.passive_recon", return_value=mock_result):
        handler = make_passive_recon_handler(_context(_scope()))
        result = handler({"target": "https://example.com/"})

    assert "dns: error:" in result


def test_passive_recon_handles_tls_error():
    from pawnlogic_security.recon import DnsResult, PassiveReconResult, TlsCertResult

    mock_result = PassiveReconResult(
        target="example.com",
        dns=DnsResult(hostname="example.com", addresses=("93.184.216.34",)),
        tls=TlsCertResult(hostname="example.com", port=443, error="connection refused"),
    )

    with patch("pawnlogic_security.recon.passive_recon", return_value=mock_result):
        handler = make_passive_recon_handler(_context(_scope()))
        result = handler({"target": "https://example.com/"})

    assert "tls: error:" in result
