"""Engagement Scope: the authorization record for active security work.

A scope is an immutable value. It never widens itself, it never infers
authorization from a target, and every ambiguous case denies. Callers pass the
current time in explicitly so expiry is testable without a real clock.

This module decides only whether a target is *in scope*. It is not a substitute
for the host Network Policy or Operation Policy; both still run afterwards, and
either can still deny something this module considers in scope.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from enum import Enum
from urllib.parse import urlsplit


class ScopeDenial(str, Enum):
    """Why a target was refused. Every value denies."""

    NO_SCOPE = "no_scope"
    EXPIRED = "expired"
    NOT_IN_SCOPE = "not_in_scope"
    MALFORMED_TARGET = "malformed_target"


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


@dataclass(frozen=True, slots=True)
class EngagementScope:
    """An explicit, expiring authorization to act against named targets.

    ``targets`` holds exact hostnames. Wildcards are deliberately unsupported:
    a scope that can match something its author did not enumerate is not an
    authorization record.
    """

    identifier: str
    targets: frozenset[str]
    expires_at: float
    authorized_by: str
    reference: str = ""
    allow_active: bool = False
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

        normalized = set()
        for target in self.targets:
            host = normalize_target(target)
            if not host:
                raise ValueError(f"scope target is not a usable host: {target!r}")
            normalized.add(host)
        if not normalized:
            raise ValueError("a scope must name at least one target")

        object.__setattr__(self, "identifier", self.identifier.strip())
        object.__setattr__(self, "targets", frozenset(normalized))
        object.__setattr__(self, "expires_at", float(self.expires_at))
        object.__setattr__(self, "metadata", dict(self.metadata))

    def is_expired(self, now: float) -> bool:
        return now >= self.expires_at

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
                denial=ScopeDenial.EXPIRED,
                reason=f"engagement scope {self.identifier} has expired",
                normalized_target=host,
            )
        if host not in self.targets:
            return ScopeDecision(
                authorized=False,
                denial=ScopeDenial.NOT_IN_SCOPE,
                reason=f"{host} is not named by engagement scope {self.identifier}",
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


__all__ = [
    "EngagementScope",
    "ScopeDecision",
    "ScopeDenial",
    "authorize",
    "normalize_target",
]
