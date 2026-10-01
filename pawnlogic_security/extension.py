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

import shlex
import time
from collections.abc import Callable
from pathlib import Path

from core.commands import CommandContext
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
from pawnlogic_security.workflows import (
    WorkflowError,
    WorkflowRunner,
    WorkflowRunStore,
    render_objective_plan,
)

API_VERSION = 1
EXTENSION_NAME = "security"

MANIFEST = ExtensionManifest(
    name=EXTENSION_NAME,
    version=__version__,
    core_version_spec=">=0.4,<0.5",
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
        self._runtime_policy: NetworkPolicy | None = None
        self._context: SecurityToolContext | None = None
        self._evidence: EvidenceLog | None = None
        self._default_evidence_path: Path | None = None
        self._evidence_path: Path | None = None
        self._scope_manager: ScopeManager | None = None
        self._workflow_runner: WorkflowRunner | None = None
        self._run_store: WorkflowRunStore | None = None
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

        scope_manager = ScopeManager(
            recontribute=self._do_recontribute,
            clock=self._clock,
        )

        tool_context = SecurityToolContext(
            policy=policy,
            evidence=evidence,
            clock=self._clock,
            scope=scope_manager.scope,
            scope_manager=scope_manager,
            interactive=False,
        )

        commands = self._command_contributions()

        # Only record state once construction has fully succeeded.
        self._runtime_policy = policy
        self._context = tool_context
        self._evidence = evidence
        self._default_evidence_path = evidence_path
        self._evidence_path = evidence_path
        self._scope_manager = scope_manager
        self._run_store = WorkflowRunStore(
            context.runtime_home / "security" / "runs"
        )
        self._workflow_runner = WorkflowRunner(
            policy=policy,
            evidence=evidence,
            clock=self._clock,
            run_store=self._run_store,
        )
        self._extension_context = context
        self._started = True

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
            return ExtensionContributions(commands=self._command_contributions())

        policy = self._runtime_policy or NetworkPolicy()
        evidence = self._configure_scope_storage()
        if evidence is None:
            return ExtensionContributions(commands=self._command_contributions())

        tool_context = SecurityToolContext(
            policy=policy,
            evidence=evidence,
            clock=self._clock,
            scope=scope,
            scope_manager=self._scope_manager,
            interactive=False,
        )
        self._context = tool_context

        tools: list[ToolSpec] = []
        if scope.allows_action("passive"):
            tools.append(
                ToolSpec(
                    name="security_passive_recon",
                    handler=make_passive_recon_handler(tool_context),
                    schema=PASSIVE_RECON_SCHEMA,
                    trust=TrustBoundaryKind.PRIVATE_NETWORK,
                    capabilities=frozenset({"network"}),
                )
            )
        if (
            scope.allows_action("active")
            and scope.allow_active
            and bool(scope.ports)
        ):
            tools.append(
                ToolSpec(
                    name="security_active_discovery",
                    handler=make_active_discovery_handler(tool_context),
                    schema=ACTIVE_DISCOVERY_SCHEMA,
                    trust=TrustBoundaryKind.PRIVATE_NETWORK,
                    capabilities=frozenset({"network"}),
                )
            )

        return ExtensionContributions(
            tools=tuple(tools),
            commands=self._command_contributions(),
        )

    def stop(self) -> None:
        """Release state. Safe to call when start never succeeded."""
        if self._scope_manager is not None:
            self._scope_manager.close()
        self._scope_manager = None
        self._workflow_runner = None
        self._run_store = None
        self._extension_context = None
        self._context = None
        self._evidence = None
        self._default_evidence_path = None
        self._evidence_path = None
        self._runtime_policy = None
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

    def _configure_scope_storage(self) -> EvidenceLog | None:
        """Point evidence and run records at the active Scope's directory."""
        scope_manager = self._scope_manager
        default_path = self._default_evidence_path
        if scope_manager is None or default_path is None:
            return self._evidence
        evidence_path = scope_manager.evidence_path(default_path)
        if evidence_path == self._evidence_path and self._evidence is not None:
            return self._evidence

        evidence = EvidenceLog(path=evidence_path)
        run_store = WorkflowRunStore(evidence_path.parent / "runs")
        policy = self._runtime_policy or NetworkPolicy()
        self._evidence = evidence
        self._evidence_path = evidence_path
        self._run_store = run_store
        self._workflow_runner = WorkflowRunner(
            policy=policy,
            evidence=evidence,
            clock=self._clock,
            run_store=run_store,
        )
        return evidence

    def _command_contributions(self) -> tuple[CommandContribution, ...]:
        """Return the complete command set for start and every rebuild."""
        return (
            CommandContribution(
                name="/security",
                handler=self._handle_security_command,
                metadata={
                    "subcommands": [
                        "scope",
                        "status",
                        "plan",
                        "run",
                        "evidence",
                    ]
                },
            ),
        )

    async def _handle_security_command(self, context: CommandContext) -> None:
        """Route one host command and write its result through the active sink."""
        subcommand = context.arg.strip()
        if subcommand == "status":
            output = self._handle_status()
        elif subcommand == "scope":
            try:
                scope_args = shlex.split(context.arg2)
            except ValueError as error:
                output = f"scope arguments rejected: {error}"
            else:
                output = self._handle_scope(scope_args)
        elif subcommand == "plan":
            try:
                output = render_objective_plan(context.arg2)
            except WorkflowError as error:
                output = f"error: {error}"
        elif subcommand == "run":
            output = await self._handle_run(context.arg2)
        elif subcommand == "evidence":
            output = self._handle_evidence(context.arg2)
        elif not subcommand:
            output = self._handle_status()
        else:
            output = (
                f"unknown subcommand: {subcommand}. "
                "Available: scope, status, plan, run, evidence"
            )
        context.sink.print(output)

    async def _handle_run(self, raw_workflow: str) -> str:
        parts = raw_workflow.split()
        if len(parts) != 1:
            return "usage: /security run <workflow>"
        if self._scope_manager is None or self._workflow_runner is None:
            return "error: Extension not started"
        self._configure_scope_storage()
        if self._workflow_runner is None:
            return "error: workflow runner is unavailable"
        try:
            result = await self._workflow_runner.run(
                parts[0],
                self._scope_manager,
            )
        except WorkflowError as error:
            return f"error: {error}"
        return result.render()

    def _handle_evidence(self, raw_args: str) -> str:
        parts = raw_args.split()
        if self._run_store is None:
            return "error: Extension not started"
        if parts == ["list"]:
            summaries = self._run_store.list_runs()
            if not summaries:
                return "no workflow runs recorded"
            return "\n".join(
                (
                    f"{item.run_id} workflow={item.workflow} "
                    f"scope={item.scope_id} recorded_at={item.recorded_at}"
                )
                for item in summaries
            )
        if len(parts) == 2 and parts[0] == "export":
            try:
                return self._run_store.export(parts[1])
            except WorkflowError as error:
                return f"error: {error}"
        return "usage: /security evidence list|export <run-id>"

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
            message = self._scope_manager.set_scope(path)
            self._configure_scope_storage()
            return message
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
