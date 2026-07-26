"""The PawnLogic Extension exported by this distribution.

Importing this module registers nothing. The host discovers the entry point by
reading metadata, and only an explicit enable call loads and starts anything.
Installing this distribution is not authorization to run it.
"""

from __future__ import annotations

import time
from collections.abc import Callable

from core.extension_contracts import (
    ExtensionContext,
    ExtensionContributions,
    ExtensionManifest,
)
from core.network_policy import NetworkPolicy
from core.tool_registry import ToolSpec
from core.trust import TrustBoundaryKind

from pawnlogic_security import __version__
from pawnlogic_security.evidence import EvidenceLog
from pawnlogic_security.scope import EngagementScope
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

    ``start`` is the only method that builds anything. If it raises partway
    through, nothing has been handed to the host: contributions are returned as
    a single value, so a partial start cannot leave half a tool set registered.
    """

    manifest = MANIFEST

    def __init__(
        self,
        *,
        policy: NetworkPolicy | None = None,
        clock: Callable[[], float] | None = None,
        scope: EngagementScope | None = None,
    ) -> None:
        # Injected for tests; production uses the host defaults.
        self._policy = policy
        self._clock = clock or time.time
        self._scope = scope
        self._context: SecurityToolContext | None = None
        self._evidence: EvidenceLog | None = None
        self._started = False

    @property
    def started(self) -> bool:
        return self._started

    @property
    def evidence(self) -> EvidenceLog | None:
        return self._evidence

    def start(self, context: ExtensionContext) -> ExtensionContributions:
        """Build the tool set. No scope is active until an operator sets one."""
        evidence_path = context.runtime_home / "security" / "evidence.jsonl"
        evidence = EvidenceLog(path=evidence_path)
        policy = self._policy if self._policy is not None else NetworkPolicy()

        tool_context = SecurityToolContext(
            policy=policy,
            evidence=evidence,
            clock=self._clock,
            scope=self._scope,
            # A tool invoked by a model cannot answer a confirmation prompt, so
            # this side of the boundary is always non-interactive.
            interactive=False,
        )

        contributions = ExtensionContributions(
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

        # Only record state once construction has fully succeeded.
        self._context = tool_context
        self._evidence = evidence
        self._started = True
        return contributions

    def stop(self) -> None:
        """Release state. Safe to call when start never succeeded."""
        self._context = None
        self._evidence = None
        self._started = False


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
