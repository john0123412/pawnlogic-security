"""Runtime Engagement Scope state.

The Extension owns the ScopeManager and passes it to command handlers. It is
not a persistence layer; it is the live authorization record that the
authorization path reads at call time.

A ScopeManager is also the callback the Extension uses to trigger a
re-contribution when the scope changes.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from pawnlogic_security.scope import EngagementScope, ScopeDecision, authorize
from pawnlogic_security.scope_file import load as load_scope_file

RecontributeCallback = Callable[[], object]


@dataclass
class ScopeState:
    """The current engagement scope and its metadata."""

    scope: EngagementScope | None = None
    scope_file_path: str = ""
    loaded_at: float = 0.0


class ScopeManager:
    """The single source of truth for whether a scope is active.

    The Extension constructs it, wires command handlers to it, and passes its
    own ``recontribute`` callback so a scope change can swap the tool set.
    """

    def __init__(
        self,
        *,
        recontribute: RecontributeCallback | None = None,
        clock: Callable[[], float] | None = None,
    ) -> None:
        self._scope: EngagementScope | None = None
        self._scope_file_path: str = ""
        self._loaded_at: float = 0.0
        self._recontribute = recontribute
        self._clock = clock or time.time
        self._request_count: int = 0
        self._active_count: int = 0

    @property
    def scope(self) -> EngagementScope | None:
        return self._scope

    @property
    def state(self) -> ScopeState:
        return ScopeState(
            scope=self._scope,
            scope_file_path=self._scope_file_path,
            loaded_at=self._loaded_at,
        )

    @property
    def is_active(self) -> bool:
        if self._scope is None:
            return False
        return not self._scope.is_expired(self._clock())

    def set_scope(self, path: Path) -> str:
        """Load a scope file and make it the active scope.

        Returns a success message, or raises ``ValueError`` with a user-facing
        reason.
        """
        scope_file = load_scope_file(path)
        now = self._clock()
        scope = EngagementScope(
            identifier=scope_file.identifier,
            targets=frozenset(scope_file.targets),
            expires_at=scope_file.expires_at,
            authorized_by=scope_file.authorized_by,
            reference=scope_file.reference,
            allow_active=scope_file.allow_active,
            exclude=frozenset(scope_file.exclude),
            max_requests=scope_file.max_requests,
            max_concurrency=scope_file.max_concurrency,
            max_duration=scope_file.max_duration,
            evidence_dir=scope_file.evidence_dir,
            metadata=dict(scope_file.metadata),
        )
        if scope.is_expired(now):
            raise ValueError(
                f"scope {scope.identifier} has already expired (expires_at={scope.expires_at})"
            )
        self._scope = scope
        self._scope_file_path = str(path)
        self._loaded_at = now
        self._request_count = 0
        self._active_count = 0
        if self._recontribute is not None:
            self._recontribute()
        return (
            f"scope {scope.identifier} loaded from {path.name}, "
            f"{len(scope.targets)} targets, expires at {scope.expires_at}"
        )

    def clear_scope(self) -> str:
        """Withdraw the active scope, if any.

        Returns a message describing what was cleared.
        """
        if self._scope is None:
            return "no scope was active"
        identifier = self._scope.identifier
        self._scope = None
        self._scope_file_path = ""
        self._loaded_at = 0.0
        self._request_count = 0
        self._active_count = 0
        if self._recontribute is not None:
            self._recontribute()
        return f"scope {identifier} cleared"

    def authorize_target(self, target: str) -> ScopeDecision:
        """Check ``target`` against the live scope."""
        return authorize(self._scope, target, self._clock())

    def format_status(self) -> str:
        """Return a human-readable status block."""
        now = self._clock()
        if self._scope is None:
            return "no scope active"
        scope = self._scope
        expired = scope.is_expired(now)
        lines = [
            f"scope:       {scope.identifier}",
            f"file:        {self._scope_file_path}",
            f"loaded at:   {self._loaded_at}",
            f"expires at:  {scope.expires_at}{'  EXPIRED' if expired else ''}",
            f"authorized:  {scope.authorized_by}",
            f"targets:     {len(scope.targets)}",
            f"active:      {scope.allow_active}",
            f"requests:    {self._request_count}/{scope.max_requests or 'unlimited'}",
            f"concurrency: {self._active_count}/{scope.max_concurrency or 'unlimited'}",
        ]
        if scope.exclude:
            lines.append(f"exclude:     {len(scope.exclude)} entries")
        if scope.max_duration:
            remaining = max(0.0, scope.max_duration - (now - self._loaded_at))
            lines.append(
                f"duration:    {scope.max_duration}s ({remaining:.0f}s remaining)"
            )
        if scope.evidence_dir:
            lines.append(f"evidence:    {scope.evidence_dir}")
        return "\n".join(lines)


__all__ = [
    "ScopeManager",
    "ScopeState",
]
