"""Security tool handlers.

Every handler here is a thin, fail-closed adapter. The order is always the
same and is never rearranged for convenience:

1. Require a valid Engagement Scope for the requested target.
2. Ask the host Network Policy to decide.
3. Refuse a confirmation-required decision when the session is not interactive.
4. Record evidence.

Nothing in this module reimplements host policy, and nothing in it can grant
authorization. Tool arguments come from a model and are untrusted: they may
name a target, but they may never assert that the target is allowed.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass

from core.network_policy import NetworkOperation, NetworkPolicy

from pawnlogic_security.evidence import EvidenceLog
from pawnlogic_security.scope import EngagementScope, authorize

Clock = Callable[[], float]


@dataclass(frozen=True, slots=True)
class ToolOutcome:
    """A handler result that states plainly whether work was performed."""

    allowed: bool
    reason: str
    target: str = ""
    rule: str = ""

    def render(self) -> str:
        verdict = "allowed" if self.allowed else "refused"
        target = f" target={self.target}" if self.target else ""
        rule = f" rule={self.rule}" if self.rule else ""
        return f"[{verdict}]{target} {self.reason}{rule}".strip()


class SecurityToolContext:
    """Everything a security handler is allowed to reach.

    The scope, the clock, and the policy are injected. A handler cannot
    construct its own policy or read the current time on its own, so a test can
    always reproduce a decision exactly.
    """

    def __init__(
        self,
        *,
        policy: NetworkPolicy,
        evidence: EvidenceLog,
        clock: Clock,
        scope: EngagementScope | None = None,
        interactive: bool = False,
    ) -> None:
        self._policy = policy
        self._evidence = evidence
        self._clock = clock
        self._scope = scope
        self._interactive = interactive

    @property
    def scope(self) -> EngagementScope | None:
        return self._scope

    @property
    def evidence(self) -> EvidenceLog:
        return self._evidence

    def _refuse(self, action: str, target: str, reason: str, rule: str) -> ToolOutcome:
        self._evidence.record(
            recorded_at=self._clock(),
            scope_id=self._scope.identifier if self._scope else "none",
            action=action,
            target=target,
            outcome="refused",
            detail={"reason": reason, "rule": rule},
        )
        return ToolOutcome(allowed=False, reason=reason, target=target, rule=rule)

    def authorize_target(
        self, *, action: str, target: str, active_probe: bool
    ) -> ToolOutcome:
        """Run the full gate for one target and return the verdict."""
        now = self._clock()

        # 1. Engagement Scope first. Without it there is nothing to evaluate.
        scope_decision = authorize(self._scope, target, now)
        if not scope_decision.authorized:
            assert scope_decision.denial is not None
            return self._refuse(
                action,
                scope_decision.normalized_target or str(target),
                scope_decision.reason,
                f"scope:{scope_decision.denial.value}",
            )

        # An active probe additionally needs the scope to permit active work.
        if active_probe and not (self._scope and self._scope.allow_active):
            return self._refuse(
                action,
                scope_decision.normalized_target,
                "engagement scope does not permit active operations",
                "scope:active_not_permitted",
            )

        # 2. Host Network Policy decides. The scope only reports its own state;
        #    it never claims the target is authorized.
        operation = NetworkOperation(
            url=str(target),
            tool_name=action,
            action=action,
            interactive=self._interactive,
            engagement_scope=self._scope.identifier if self._scope else None,
            scope_valid=True,
            active_probe=active_probe,
        )
        decision = self._policy.evaluate(operation)

        # 3. Anything short of an outright allow is refused here. A tool driven
        #    by a model has no way to answer a confirmation prompt, so treating
        #    "confirm" as "yes" would silently remove the gate.
        if decision.action.value != "allow":
            return self._refuse(
                action,
                decision.normalized_target or scope_decision.normalized_target,
                decision.reason,
                decision.rule,
            )

        # 4. Record the authorized observation.
        self._evidence.record(
            recorded_at=now,
            scope_id=self._scope.identifier if self._scope else "none",
            action=action,
            target=decision.normalized_target,
            outcome="allowed",
            detail={"reason": decision.reason, "rule": decision.rule},
        )
        return ToolOutcome(
            allowed=True,
            reason=decision.reason,
            target=decision.normalized_target,
            rule=decision.rule,
        )


def _target_of(args: Mapping[str, object]) -> str:
    value = args.get("target", "")
    return value if isinstance(value, str) else ""


def make_passive_recon_handler(
    context: SecurityToolContext,
) -> Callable[[dict[str, object]], str]:
    """Passive reconnaissance: DNS, TLS, HTTP headers, and technology fingerprint."""

    def handler(args: dict[str, object]) -> str:
        raw_target = _target_of(args)
        outcome = context.authorize_target(
            action="security_passive_recon",
            target=raw_target,
            active_probe=False,
        )
        if not outcome.allowed:
            return outcome.render()

        from pawnlogic_security.recon import passive_recon

        scope = context.scope
        if scope is None:
            return outcome.render()

        result = passive_recon(
            target=raw_target,
            scope=scope,
            now=context._clock(),
        )

        lines: list[str] = [f"passive recon: {result.target}"]

        if result.dns:
            if result.dns.error:
                lines.append(f"  dns: error: {result.dns.error}")
            else:
                lines.append(f"  dns: {', '.join(result.dns.addresses)}")

        if result.tls:
            if result.tls.error:
                lines.append(f"  tls: error: {result.tls.error}")
            else:
                lines.append(f"  tls: subject={result.tls.subject} issuer={result.tls.issuer}")
                lines.append(f"       valid={result.tls.not_before} to {result.tls.not_after}")

        if result.http:
            if result.http.error:
                lines.append(f"  http: error: {result.http.error}")
            else:
                lines.append(f"  http: status={result.http.status}")
                if result.http.server:
                    lines.append(f"        server: {result.http.server}")
                if result.http.technologies:
                    lines.append(f"        tech: {'; '.join(result.http.technologies)}")

        if result.scope_addresses:
            lines.append(f"  scope-validated addresses: {', '.join(result.scope_addresses)}")
        if result.errors:
            for error in result.errors:
                lines.append(f"  warning: {error}")

        return "\n".join(lines)

    return handler


def make_active_discovery_handler(
    context: SecurityToolContext,
) -> Callable[[dict[str, object]], str]:
    """Bounded active discovery: port scanning within scope constraints."""

    def handler(args: dict[str, object]) -> str:
        raw_target = _target_of(args)
        outcome = context.authorize_target(
            action="security_active_discovery",
            target=raw_target,
            active_probe=True,
        )
        if not outcome.allowed:
            return outcome.render()

        from pawnlogic_security.recon import active_port_scan

        scope = context.scope
        if scope is None:
            return outcome.render()

        results = active_port_scan(
            target=raw_target,
            scope=scope,
            now=context._clock(),
        )

        lines: list[str] = [f"port scan: {outcome.target}"]
        open_ports = [r for r in results if r.state == "open"]
        if open_ports:
            for r in open_ports:
                svc = f" ({r.service})" if r.service else ""
                lines.append(f"  {r.port}/tcp open{svc}")
        else:
            lines.append("  no open ports found")
        errors = [r for r in results if r.state == "error"]
        for r in errors:
            lines.append(f"  {r.port}: error: {r.error}")

        return "\n".join(lines)

    return handler


def _tool_schema(name: str, description: str) -> dict[str, object]:
    """Build the schema shape the host ToolRegistry validates.

    The registry requires ``schema["function"]["name"]`` to equal the ToolSpec
    name, so the two are derived from one argument here rather than written out
    twice and allowed to drift.
    """
    return {
        "type": "function",
        "function": {
            "name": name,
            "description": description,
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": (
                            "Host named by the active Engagement Scope. Naming "
                            "a target here does not authorize it."
                        ),
                    }
                },
                "required": ["target"],
            },
        },
    }


PASSIVE_RECON_SCHEMA: dict[str, object] = _tool_schema(
    "security_passive_recon",
    "Passive reconnaissance against an in-scope host. Sends nothing to the target.",
)

ACTIVE_DISCOVERY_SCHEMA: dict[str, object] = _tool_schema(
    "security_active_discovery",
    "Bounded active discovery. Requires a scope that permits active operations.",
)


__all__ = [
    "ACTIVE_DISCOVERY_SCHEMA",
    "PASSIVE_RECON_SCHEMA",
    "SecurityToolContext",
    "ToolOutcome",
    "make_active_discovery_handler",
    "make_passive_recon_handler",
]
