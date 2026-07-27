"""Engagement Scope: the authorization record for active security work.

A scope is an immutable value. It never widens itself, it never infers
authorization from a target, and every ambiguous case denies. Callers pass the
current time in explicitly so expiry is testable without a real clock.

This module decides only whether a target is *in scope*. It is not a substitute
for the host Network Policy, which runs afterwards and can still deny something
this module considers in scope. The host Operation Policy governs subprocess
execution and is not on this path, because nothing here runs a subprocess.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from enum import Enum
from urllib.parse import urlsplit

PortRange = int | tuple[int, int]


class ScopeDenial(str, Enum):
    """Why a target was refused. Every value denies."""

    NO_SCOPE = "no_scope"
    EXPIRED = "expired"
    NOT_IN_SCOPE = "not_in_scope"
    MALFORMED_TARGET = "malformed_target"
    EXCLUDED = "excluded"
    PORT_NOT_IN_SCOPE = "port_not_in_scope"


@dataclass(frozen=True, slots=True)
class ScopeDecision:
    """The result of a scope check.

    ``authorized`` is the only field callers should branch on. It is False
    whenever ``denial`` is set, and the two can never disagree.
    """

    authorized: bool
    denial: ScopeDenial | None = None
    reason: str = ""
    normalized_target: str = ""

    def __post_init__(self) -> None:
        if self.authorized and self.denial is not None:
            raise ValueError("an authorized decision cannot carry a denial")
        if not self.authorized and self.denial is None:
            raise ValueError("a denied decision must carry a denial reason")


def normalize_target(raw: str) -> str:
    """Reduce a target to a comparable lowercase host, or "" if unusable.

    Returning "" rather than raising keeps the caller on the deny path instead
    of turning a malformed target into an exception someone might catch and
    treat as success.
    """
    if not isinstance(raw, str):
        return ""
    candidate = raw.strip()
    if not candidate:
        return ""

    # A bare IPv6 literal such as "::1" must survive a second pass unchanged.
    # urlsplit would read its colons as a port separator, so handle it first
    # and keep this function idempotent.
    try:
        return str(ipaddress.ip_address(candidate)).lower()
    except ValueError:
        pass

    if "://" in candidate:
        host = urlsplit(candidate).hostname or ""
    else:
        # Accept a bare host, host:port, or [v6]:port without inventing a
        # scheme. urlsplit needs the authority form to parse an authority.
        try:
            host = urlsplit(f"//{candidate}").hostname or ""
        except ValueError:
            return ""

    host = host.strip().rstrip(".").lower()
    if not host or "/" in host or " " in host:
        return ""
    # urlsplit strips the brackets from [::1]; normalize the address form so
    # "::1", "[::1]", and "http://[::1]/" all compare equal.
    try:
        return str(ipaddress.ip_address(host)).lower()
    except ValueError:
        return host


def _parse_cidr(raw: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network | None:
    """Parse a CIDR or single IP as a network, or None if unusable."""
    try:
        return ipaddress.ip_network(raw, strict=False)
    except ValueError:
        return None


def _host_in_network(host: str, network: ipaddress.IPv4Network | ipaddress.IPv6Network) -> bool:
    """Check whether a normalized host belongs to a network."""
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        return False
    return addr in network


def _port_in_ranges(port: int, ranges: tuple[PortRange, ...]) -> bool:
    """Check whether a port is allowed by any range in ``ranges``."""
    for entry in ranges:
        if isinstance(entry, int):
            if port == entry:
                return True
        else:
            low, high = entry
            if low <= port <= high:
                return True
    return False


def _parse_port(raw: str) -> int | None:
    """Parse a port string, or None if it is not a valid port number."""
    try:
        value = int(raw)
    except (ValueError, TypeError):
        return None
    if 0 < value <= 65535:
        return value
    return None


def _parse_port_range(raw: str) -> PortRange | None:
    """Parse a port range like ``80`` or ``8000-9000``."""
    if "-" in raw:
        parts = raw.split("-", 1)
        if len(parts) != 2:
            return None
        low = _parse_port(parts[0].strip())
        high = _parse_port(parts[1].strip())
        if low is None or high is None:
            return None
        if low > high:
            return None
        return (low, high)
    port = _parse_port(raw)
    return port


def _normalize_entry(raw: str) -> str:
    """Normalize a target entry, preserving CIDR prefix if present.

    A CIDR like ``10.0.0.0/24`` must keep its prefix so membership tests
    work. A bare host or IP goes through the normal ``normalize_target`` path.
    """
    if "/" in raw:
        cidr = _parse_cidr(raw)
        if cidr is not None:
            return str(cidr)
    return normalize_target(raw)


@dataclass(frozen=True, slots=True)
class EngagementScope:
    """An explicit, expiring authorization to act against named targets.

    ``targets`` holds exact hostnames and CIDRs. Wildcards are deliberately
    unsupported: a scope that can match something its author did not enumerate
    is not an authorization record.

    ``exclude`` overrides ``targets``: a host matched by an exclusion is
    denied even if it is also in ``targets``. Exclusions are evaluated first,
    so the effect is always deny-first, never widen-first.

    ``ports`` constrains every connection. An empty tuple authorizes no active
    connection ports; there is deliberately no implicit common-port fallback.
    """

    identifier: str
    targets: frozenset[str]
    expires_at: float
    authorized_by: str
    reference: str = ""
    allow_active: bool = False
    actions: frozenset[str] = field(default_factory=frozenset)
    destructive: bool = False
    exclude: frozenset[str] = field(default_factory=frozenset)
    ports: tuple[PortRange, ...] = ()
    max_requests: int = 0
    max_concurrency: int = 0
    max_duration: float = 0.0
    evidence_dir: str = ""
    metadata: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.identifier, str) or not self.identifier.strip():
            raise ValueError("identifier must be a non-empty string")
        if not isinstance(self.authorized_by, str) or not self.authorized_by.strip():
            raise ValueError("authorized_by must be a non-empty string")
        if isinstance(self.expires_at, bool) or not isinstance(
            self.expires_at, (int, float)
        ):
            raise TypeError("expires_at must be a POSIX timestamp")

        normalized_targets: set[str] = set()
        for target in self.targets:
            entry = _normalize_entry(target)
            if not entry:
                raise ValueError(f"scope target is not a usable host or CIDR: {target!r}")
            normalized_targets.add(entry)
        if not normalized_targets:
            raise ValueError("a scope must name at least one target")

        normalized_exclude: set[str] = set()
        for entry in self.exclude:
            norm = _normalize_entry(entry)
            if not norm:
                raise ValueError(f"scope exclusion is not a usable host or CIDR: {entry!r}")
            normalized_exclude.add(norm)

        normalized_ports: list[PortRange] = []
        occupied: list[tuple[int, int]] = []
        for port_entry in self.ports:
            if isinstance(port_entry, bool):
                raise ValueError(f"scope port is invalid: {port_entry!r}")
            if isinstance(port_entry, int):
                parsed: PortRange | None = (
                    port_entry if 0 < port_entry <= 65535 else None
                )
            elif (
                isinstance(port_entry, tuple)
                and len(port_entry) == 2
                and all(
                    isinstance(value, int) and not isinstance(value, bool)
                    for value in port_entry
                )
            ):
                low, high = port_entry
                parsed = port_entry if 0 < low <= high <= 65535 else None
            else:
                parsed = None
            if parsed is None:
                raise ValueError(f"scope port or range is invalid: {port_entry!r}")
            low, high = (parsed, parsed) if isinstance(parsed, int) else parsed
            if any(not (high < used_low or low > used_high) for used_low, used_high in occupied):
                raise ValueError(
                    f"scope port ranges overlap or repeat: {port_entry!r}"
                )
            occupied.append((low, high))
            normalized_ports.append(parsed)

        actions = frozenset(self.actions)
        if any(action not in {"passive", "active"} for action in actions):
            raise ValueError("actions may contain only 'passive' and 'active'")
        if not actions:
            actions = frozenset(
                {"passive", "active"} if self.allow_active else {"passive"}
            )
        if "active" in actions and not self.allow_active:
            raise ValueError("active action requires allow_active=true")
        if self.allow_active and "active" not in actions:
            raise ValueError("allow_active=true requires the active action")
        if self.allow_active and not normalized_ports:
            raise ValueError("active scopes must explicitly authorize ports")
        if self.destructive:
            raise ValueError(
                "destructive operations are not implemented in pawnlogic-security 0.1"
            )

        object.__setattr__(self, "identifier", self.identifier.strip())
        object.__setattr__(self, "targets", frozenset(normalized_targets))
        object.__setattr__(self, "exclude", frozenset(normalized_exclude))
        object.__setattr__(self, "ports", tuple(normalized_ports))
        object.__setattr__(self, "actions", actions)
        object.__setattr__(self, "expires_at", float(self.expires_at))
        object.__setattr__(self, "max_requests", int(self.max_requests))
        object.__setattr__(self, "max_concurrency", int(self.max_concurrency))
        object.__setattr__(self, "max_duration", float(self.max_duration))
        object.__setattr__(self, "evidence_dir", self.evidence_dir.strip())
        object.__setattr__(self, "metadata", dict(self.metadata))

    def is_expired(self, now: float) -> bool:
        return now >= self.expires_at

    def allows_action(self, action: str) -> bool:
        """Return whether the authorization record names ``action``."""
        return action in self.actions

    def allows_port(self, port: int) -> bool:
        """Return whether ``port`` is explicitly named by the scope."""
        return _port_in_ranges(port, self.ports)

    def _is_host_in_targets(self, host: str) -> bool:
        """Check whether ``host`` is in scope by exact match or CIDR membership."""
        if host in self.targets:
            return True
        for entry in self.targets:
            if "/" in entry:
                cidr = _parse_cidr(entry)
                if cidr is not None and _host_in_network(host, cidr):
                    return True
        return False

    def _is_excluded(self, host: str) -> bool:
        """Check whether ``host`` is excluded by exact match or CIDR membership."""
        if host in self.exclude:
            return True
        for entry in self.exclude:
            if "/" in entry:
                cidr = _parse_cidr(entry)
                if cidr is not None and _host_in_network(host, cidr):
                    return True
        return False

    def is_authorized(self, target: str, now: float) -> ScopeDecision:
        """Decide whether ``target`` may be acted on at time ``now``."""
        host = normalize_target(target)
        if not host:
            return ScopeDecision(
                authorized=False,
                denial=ScopeDenial.MALFORMED_TARGET,
                reason="target could not be normalized to a host",
            )
        if self.is_expired(now):
            return ScopeDecision(
                authorized=False,
                denial= ScopeDenial.EXPIRED,
                reason=f"engagement scope {self.identifier} has expired",
                normalized_target=host,
            )
        if self._is_excluded(host):
            return ScopeDecision(
                authorized=False,
                denial=ScopeDenial.EXCLUDED,
                reason=f"{host} is excluded by engagement scope {self.identifier}",
                normalized_target=host,
            )
        if not self._is_host_in_targets(host):
            return ScopeDecision(
                authorized=False,
                denial=ScopeDenial.NOT_IN_SCOPE,
                reason=f"{host} is not named by engagement scope {self.identifier}",
                normalized_target=host,
            )
        try:
            parsed = urlsplit(target if "://" in target else f"//{target}")
            explicit_port = parsed.port
        except ValueError:
            return ScopeDecision(
                authorized=False,
                denial=ScopeDenial.MALFORMED_TARGET,
                reason="target contains an invalid port",
                normalized_target=host,
            )
        if explicit_port is not None and not self.allows_port(explicit_port):
            return ScopeDecision(
                authorized=False,
                denial=ScopeDenial.PORT_NOT_IN_SCOPE,
                reason=(
                    f"port {explicit_port} is not named by engagement scope "
                    f"{self.identifier}"
                ),
                normalized_target=host,
            )
        return ScopeDecision(
            authorized=True,
            reason=f"{host} is named by engagement scope {self.identifier}",
            normalized_target=host,
        )


def authorize(scope: EngagementScope | None, target: str, now: float) -> ScopeDecision:
    """Check ``target`` against an optional scope.

    A missing scope is the common case in practice, so it gets an explicit
    branch here instead of being an ``AttributeError`` at some call site.
    """
    if scope is None:
        return ScopeDecision(
            authorized=False,
            denial=ScopeDenial.NO_SCOPE,
            reason="no engagement scope is active",
            normalized_target=normalize_target(target),
        )
    return scope.is_authorized(target, now)


def from_scope_file(scope_file: object, *, clock: float) -> EngagementScope:
    """Build an ``EngagementScope`` from a ``ScopeFile``.

    The caller supplies the current time so it can also be used by the
    authorization check. ``ScopeFile`` is a plain data object; this function
    has no import dependency on the module that defines it.
    """
    from pawnlogic_security.scope_file import ScopeFile as _ScopeFile

    if not isinstance(scope_file, _ScopeFile):
        raise TypeError(f"expected ScopeFile, got {type(scope_file).__name__}")
    del clock  # retained as a compatibility parameter for existing callers
    parsed_ports: list[PortRange] = []
    for raw in scope_file.ports:
        parsed = _parse_port_range(raw)
        if parsed is None:
            raise ValueError(f"scope port or range is invalid: {raw!r}")
        parsed_ports.append(parsed)
    return EngagementScope(
        identifier=scope_file.identifier,
        targets=frozenset(scope_file.targets),
        expires_at=scope_file.expires_at,
        authorized_by=scope_file.authorized_by,
        reference=scope_file.reference,
        allow_active=scope_file.allow_active,
        actions=scope_file.actions,
        destructive=scope_file.destructive,
        exclude=frozenset(scope_file.exclude),
        ports=tuple(parsed_ports),
        max_requests=scope_file.max_requests,
        max_concurrency=scope_file.max_concurrency,
        max_duration=scope_file.max_duration,
        evidence_dir=scope_file.evidence_dir,
        metadata=dict(scope_file.metadata),
    )


__all__ = [
    "EngagementScope",
    "PortRange",
    "ScopeDecision",
    "ScopeDenial",
    "authorize",
    "from_scope_file",
    "normalize_target",
]
