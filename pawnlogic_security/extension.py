"""The PawnLogic Extension exported by this distribution.

Importing this module registers nothing. The host discovers the entry point by
reading metadata, and only an explicit enable call loads and starts anything.
Installing this distribution is not authorization to run it.

Tools are registered only while a valid Engagement Scope is active. The
Extension contributes commands at start, and those commands are how an operator
sets and clears the scope. Setting or clearing a scope triggers a
re-contribution so the host's tool set reflects the new state.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from pathlib import Path

from core.extension_contracts import (
    CommandContribution,
    ExtensionContext,
    ExtensionContributions,
    ExtensionManifest,
)
from core.network_policy import NetworkPolicy
from core.tool_registry import ToolSpec
from core.trust import TrustBoundaryKind

from pawnlogic_security import __version__
from pawnlogic_security.evidence import EvidenceLog
from pawnlogic_security.scope_manager import ScopeManager
from pawnlogic_security.tools import (
    ACTIVE_DISCOVERY_SCHEMA,
    PASSIVE_RECON_SCHEMA,
    SecurityToolContext,
    make_active_discovery_handler,
    make_passive_recon_handler,
)

API_VERSION = 1
EXTENSION_NAME = "security"

MANIFEST = ExtensionManifest(
    name=EXTENSION_NAME,
    version=__version__,
    core_version_spec=">=0.3,<0.4",
    api_version=API_VERSION,
    description="Scope-gated reconnaissance and discovery tools.",
    capabilities=frozenset({"network"}),
)


class SecurityExtension:
    """Lifecycle object for the security Extension.

    ``start`` registers commands but no tools. Tools appear only after the
    operator loads a scope, and disappear when it is cleared or expires.
    The host's ``recontribute`` mechanism is how the tool set is rebuilt.
    """

    manifest = MANIFEST

    def __init__(
        self,
        *,
        policy: NetworkPolicy | None = None,
        clock: Callable[[], float] | None = None,
    ) -> None:
        self._policy = policy
        self._clock = clock or time.time
        self._context: SecurityToolContext | None = None
        self._evidence: EvidenceLog | None = None
        self._scope_manager: ScopeManager | None = None
        self._extension_context: ExtensionContext | None = None
        self._started = False

    @property
    def started(self) -> bool:
        return self._started

    @property
    def evidence(self) -> EvidenceLog | None:
        return self._evidence

    @property
    def scope_manager(self) -> ScopeManager | None:
        return self._scope_manager

    def start(self, context: ExtensionContext) -> ExtensionContributions:
        """Build the tool set and commands. No tools until a scope is set."""
        evidence_path = context.runtime_home / "security" / "evidence.jsonl"
        evidence = EvidenceLog(path=evidence_path)
        policy = self._policy if self._policy is not None else NetworkPolicy()

        # The scope manager's callback triggers a re-contribution through the
        # host. The callback is set after the Extension is fully constructed,
        # so a scope change during start() would be safe but unnecessary.
        scope_manager = ScopeManager(clock=self._clock)

        tool_context = SecurityToolContext(
            policy=policy,
            evidence=evidence,
            clock=self._clock,
            scope=scope_manager.scope,
            interactive=False,
        )

        commands = (
            CommandContribution(
                name="security",
                handler=self._handle_security_command,
                metadata={"subcommands": ["scope", "status"]},
            ),
        )

        # Only record state once construction has fully succeeded.
        self._context = tool_context
        self._evidence = evidence
        self._scope_manager = scope_manager
        self._extension_context = context
        self._started = True

        # Wire the callback now that everything is ready.
        scope_manager._recontribute = self._do_recontribute

        # Commands only: the tool set is not knowable until a scope is set.
        return ExtensionContributions(commands=commands)

    def contribute(self, context: ExtensionContext) -> ExtensionContributions:
        """Rebuild contributions for the current scope state.

        This is the method the host calls when ``recontribute`` is triggered.
        The Extension calls ``recontribute`` itself when the scope changes.
        """
        del context  # the Extension uses its own stored state
        scope = self._scope_manager.scope if self._scope_manager else None
        if scope is None or scope.is_expired(self._clock()):
            return ExtensionContributions()

        policy = self._policy if self._policy is not None else NetworkPolicy()
        evidence = self._evidence

        tool_context = SecurityToolContext(
            policy=policy,
            evidence=evidence,
            clock=self._clock,
            scope=scope,
            interactive=False,
        )

        return ExtensionContributions(
            tools=(
                ToolSpec(
                    name="security_passive_recon",
                    handler=make_passive_recon_handler(tool_context),
                    schema=PASSIVE_RECON_SCHEMA,
                    trust=TrustBoundaryKind.PRIVATE_NETWORK,
                    capabilities=frozenset({"network"}),
                ),
                ToolSpec(
                    name="security_active_discovery",
                    handler=make_active_discovery_handler(tool_context),
                    schema=ACTIVE_DISCOVERY_SCHEMA,
                    trust=TrustBoundaryKind.PRIVATE_NETWORK,
                    capabilities=frozenset({"network"}),
                ),
            )
        )

    def stop(self) -> None:
        """Release state. Safe to call when start never succeeded."""
        if self._scope_manager is not None:
            self._scope_manager._recontribute = None
        self._scope_manager = None
        self._extension_context = None
        self._context = None
        self._evidence = None
        self._started = False

    def _do_recontribute(self) -> object:
        """Trigger a host re-contribution, if the host supports it."""
        ctx = self._extension_context
        if ctx is None:
            return None
        callback = getattr(ctx, "recontribute", None)
        if callback is None:
            return None
        return callback()

    def _handle_security_command(self, *args: object, **kwargs: object) -> str:
        """Route /security subcommands to the scope manager."""
        # The host passes the full argument list. Parse the first arg as the
        # subcommand; the rest is positional.
        parts = [str(a) for a in args] if args else []
        if not parts:
            return self._handle_status()
        subcommand = parts[0]
        if subcommand == "status":
            return self._handle_status()
        if subcommand == "scope":
            return self._handle_scope(parts[1:])
        return f"unknown subcommand: {subcommand}. " "Available: scope, status"

    def _handle_status(self) -> str:
        if self._scope_manager is None:
            return "Extension not started"
        return self._scope_manager.format_status()

    def _handle_scope(self, args: list[str]) -> str:
        if self._scope_manager is None:
            return "Extension not started"
        if not args:
            return self._handle_scope_show()
        subcommand = args[0]
        if subcommand == "show":
            return self._handle_scope_show()
        if subcommand == "set":
            return self._handle_scope_set(args[1:])
        if subcommand == "clear":
            return self._scope_manager.clear_scope()
        return f"unknown scope subcommand: {subcommand}. " "Available: show, set, clear"

    def _handle_scope_show(self) -> str:
        if self._scope_manager is None:
            return "Extension not started"
        state = self._scope_manager.state
        if state.scope is None:
            return "no scope active"
        return self._scope_manager.format_status()

    def _handle_scope_set(self, args: list[str]) -> str:
        if self._scope_manager is None:
            return "Extension not started"
        if not args:
            return "usage: /security scope set <scope-file>"
        path = Path(args[0]).expanduser()
        if not path.is_file():
            return f"scope file not found: {path}"
        try:
            return self._scope_manager.set_scope(path)
        except ValueError as error:
            return f"scope rejected: {error}"


def build_extension() -> SecurityExtension:
    """Entry-point factory. Loading this does not start the Extension."""
    return SecurityExtension()


__all__ = [
    "API_VERSION",
    "EXTENSION_NAME",
    "MANIFEST",
    "SecurityExtension",
    "build_extension",
]
