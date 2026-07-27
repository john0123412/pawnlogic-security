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
from threading import RLock, Timer

from pawnlogic_security.scope import (
    EngagementScope,
    ScopeDecision,
    authorize,
    from_scope_file,
)
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
        self._uses_wall_clock = clock is None
        self._clock = clock or time.time
        self._request_count: int = 0
        self._active_count: int = 0
        self._lock = RLock()
        self._expiry_timer: Timer | None = None

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
        scope = from_scope_file(scope_file, clock=now)
        if scope.is_expired(now):
            raise ValueError(
                f"scope {scope.identifier} has already expired (expires_at={scope.expires_at})"
            )
        with self._lock:
            previous = self._snapshot()
            self._scope = scope
            self._scope_file_path = str(path)
            self._loaded_at = now
            self._request_count = 0
            self._active_count = 0
            try:
                self._notify_recontribution()
            except Exception:
                self._restore(previous)
                raise
            self._schedule_expiry()
        return (
            f"scope {scope.identifier} loaded from {path.name}, "
            f"{len(scope.targets)} targets, expires at {scope.expires_at}"
        )

    def clear_scope(self) -> str:
        """Withdraw the active scope, if any.

        Returns a message describing what was cleared.
        """
        with self._lock:
            if self._scope is None:
                return "no scope was active"
            identifier = self._scope.identifier
            previous = self._snapshot()
            self._scope = None
            self._scope_file_path = ""
            self._loaded_at = 0.0
            self._request_count = 0
            self._active_count = 0
            try:
                self._notify_recontribution()
            except Exception:
                self._restore(previous)
                raise
            self._cancel_expiry()
        return f"scope {identifier} cleared"

    def set_recontribute(self, callback: RecontributeCallback | None) -> None:
        """Set the host callback used for atomic contribution rebuilds."""
        with self._lock:
            self._recontribute = callback

    def consume_requests(self, count: int) -> None:
        """Atomically consume part of the engagement-wide request budget."""
        if isinstance(count, bool) or not isinstance(count, int) or count <= 0:
            raise ValueError("request count must be a positive integer")
        with self._lock:
            scope = self._scope
            if scope is None:
                raise PermissionError("no engagement scope is active")
            now = self._clock()
            if scope.is_expired(now):
                raise PermissionError("engagement scope has expired")
            if scope.max_duration and now - self._loaded_at >= scope.max_duration:
                raise PermissionError("engagement duration budget is exhausted")
            if scope.max_requests and self._request_count + count > scope.max_requests:
                raise PermissionError("engagement request budget is exhausted")
            self._request_count += count

    def evidence_path(self, default_path: Path) -> Path:
        """Resolve the active Scope's evidence directory without widening it."""
        with self._lock:
            if self._scope is None or not self._scope.evidence_dir:
                return default_path
            directory = Path(self._scope.evidence_dir).expanduser()
            if not directory.is_absolute():
                directory = Path(self._scope_file_path).parent / directory
            return directory / "evidence.jsonl"

    def close(self) -> None:
        """Cancel runtime timers without changing persisted authorization data."""
        with self._lock:
            self._cancel_expiry()

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

    def _snapshot(self) -> tuple[EngagementScope | None, str, float, int, int]:
        return (
            self._scope,
            self._scope_file_path,
            self._loaded_at,
            self._request_count,
            self._active_count,
        )

    def _restore(
        self, snapshot: tuple[EngagementScope | None, str, float, int, int]
    ) -> None:
        (
            self._scope,
            self._scope_file_path,
            self._loaded_at,
            self._request_count,
            self._active_count,
        ) = snapshot

    def _notify_recontribution(self) -> None:
        if self._recontribute is None:
            return
        result = self._recontribute()
        error = getattr(result, "error", None)
        if error:
            raise ValueError(f"host re-contribution failed: {error}")

    def _cancel_expiry(self) -> None:
        if self._expiry_timer is not None:
            self._expiry_timer.cancel()
            self._expiry_timer = None

    def _schedule_expiry(self) -> None:
        self._cancel_expiry()
        if not self._uses_wall_clock or self._scope is None:
            return
        deadline = self._scope.expires_at
        if self._scope.max_duration:
            deadline = min(deadline, self._loaded_at + self._scope.max_duration)
        delay = max(0.0, deadline - self._clock())
        identifier = self._scope.identifier
        timer = Timer(delay, self._expire_scope, args=(identifier,))
        timer.daemon = True
        timer.start()
        self._expiry_timer = timer

    def _expire_scope(self, identifier: str) -> None:
        with self._lock:
            if self._scope is None or self._scope.identifier != identifier:
                return
        try:
            self.clear_scope()
        except ValueError:
            # The old Tool closures still carry the now-expired Scope and deny
            # execution. Keep the record so status reports the failed withdrawal.
            return


__all__ = [
    "ScopeManager",
    "ScopeState",
]
