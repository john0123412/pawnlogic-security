"""Versioned security workflows shared by the CLI and PawnLogic Extension."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
import stat
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path

from core.network_policy import NetworkPolicy

from pawnlogic_security.evidence import EvidenceLog, redact, redact_text
from pawnlogic_security.scope_manager import ScopeManager
from pawnlogic_security.tools import (
    SecurityToolContext,
    make_active_discovery_handler,
    make_passive_recon_handler,
)

WORKFLOW_MANIFEST_SCHEMA_VERSION = 1
WORKFLOW_RUN_SCHEMA_VERSION = 1
WorkflowExecutor = Callable[[str], str]


class WorkflowError(ValueError):
    """A safe, user-facing workflow error."""


@dataclass(frozen=True, slots=True)
class WorkflowStep:
    """One bounded action in a workflow."""

    action: str
    active: bool

    def to_dict(self) -> dict[str, object]:
        return {"action": self.action, "active": self.active}


@dataclass(frozen=True, slots=True)
class WorkflowManifest:
    """A stable description of one executable security workflow."""

    name: str
    workflow_version: int
    description: str
    steps: tuple[WorkflowStep, ...]
    schema_version: int = WORKFLOW_MANIFEST_SCHEMA_VERSION

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "name": self.name,
            "workflow_version": self.workflow_version,
            "description": self.description,
            "steps": [step.to_dict() for step in self.steps],
        }

    def to_json(self) -> str:
        """Serialize canonically so the same manifest always has the same bytes."""
        return json.dumps(
            self.to_dict(),
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )


@dataclass(frozen=True, slots=True)
class WorkflowPlan:
    """The exact manifest and targets admitted for one run."""

    manifest: WorkflowManifest
    scope_id: str
    targets: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "manifest": self.manifest.to_dict(),
            "scope_id": self.scope_id,
            "targets": list(self.targets),
        }

    def to_json(self) -> str:
        return json.dumps(
            self.to_dict(),
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )


@dataclass(frozen=True, slots=True)
class WorkflowResult:
    """The observable output of one action against one target."""

    action: str
    target: str
    output: str

    def to_dict(self) -> dict[str, str]:
        return {
            "action": self.action,
            "target": self.target,
            "output": self.output,
        }


@dataclass(frozen=True, slots=True)
class WorkflowRun:
    """A versioned record returned by the shared runner."""

    run_id: str
    recorded_at: float
    plan: WorkflowPlan
    results: tuple[WorkflowResult, ...]
    schema_version: int = WORKFLOW_RUN_SCHEMA_VERSION

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "run_id": self.run_id,
            "recorded_at": self.recorded_at,
            "plan": self.plan.to_dict(),
            "results": [result.to_dict() for result in self.results],
        }

    def to_json(self) -> str:
        return json.dumps(
            self.to_dict(),
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )

    def render(self) -> str:
        lines = [
            (
                f"workflow {self.plan.manifest.name} "
                f"v{self.plan.manifest.workflow_version}"
            ),
            f"run: {self.run_id}",
            f"scope: {self.plan.scope_id}",
        ]
        for result in self.results:
            lines.append(f"[{result.action}] {result.target}")
            lines.append(result.output)
        return "\n".join(lines)


@dataclass(frozen=True, slots=True)
class WorkflowRunSummary:
    """The non-sensitive fields shown by evidence list."""

    run_id: str
    workflow: str
    scope_id: str
    recorded_at: float


_RUN_ID_PATTERN = re.compile(r"^[0-9a-f]{16}$")
_MAX_RUN_BYTES = 1_000_000


class WorkflowRunStore:
    """A restrictive local store for versioned workflow run records."""

    def __init__(self, root: Path) -> None:
        self.root = root

    def save(self, run: WorkflowRun) -> None:
        payload = run.to_json()
        self.root.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.root, stat.S_IRWXU)
        except OSError:
            pass
        path = self.root / f"{run.run_id}.json"
        try:
            fd = os.open(
                path,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                stat.S_IRUSR | stat.S_IWUSR,
            )
        except FileExistsError:
            if self.export(run.run_id) == payload:
                return
            raise WorkflowError(f"run record already exists: {run.run_id}") from None
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(payload)

    def list_runs(self) -> tuple[WorkflowRunSummary, ...]:
        if not self.root.is_dir():
            return ()
        summaries: list[WorkflowRunSummary] = []
        for path in sorted(self.root.glob("*.json")):
            try:
                data = self._load(path.stem)
                plan = data.get("plan")
                if not isinstance(plan, dict):
                    raise WorkflowError(f"run record has no plan: {path.stem}")
                manifest = plan.get("manifest")
                if not isinstance(manifest, dict):
                    raise WorkflowError(
                        f"run record has no manifest: {path.stem}"
                    )
                run_id = data.get("run_id")
                workflow = manifest.get("name")
                scope_id = plan.get("scope_id")
                recorded_at = data.get("recorded_at")
                if (
                    not isinstance(run_id, str)
                    or not isinstance(workflow, str)
                    or not isinstance(scope_id, str)
                    or isinstance(recorded_at, bool)
                    or not isinstance(recorded_at, (int, float))
                ):
                    raise WorkflowError(
                        f"run record summary is invalid: {path.stem}"
                    )
                summaries.append(
                    WorkflowRunSummary(
                        run_id=run_id,
                        workflow=workflow,
                        scope_id=scope_id,
                        recorded_at=float(recorded_at),
                    )
                )
            except (KeyError, TypeError, ValueError):
                continue
        return tuple(summaries)

    def export(self, run_id: str) -> str:
        data = self._load(run_id)
        return json.dumps(
            redact(data),
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )

    def _load(self, run_id: str) -> dict[str, object]:
        if not _RUN_ID_PATTERN.fullmatch(run_id):
            raise WorkflowError("run ID must contain exactly 16 lowercase hex characters")
        path = self.root / f"{run_id}.json"
        try:
            info = path.lstat()
        except OSError as error:
            raise WorkflowError(f"run record not found: {run_id}") from error
        if not stat.S_ISREG(info.st_mode) or path.is_symlink():
            raise WorkflowError(f"run record is not a regular file: {run_id}")
        if info.st_size > _MAX_RUN_BYTES:
            raise WorkflowError(f"run record is too large: {run_id}")
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise WorkflowError(f"run record is invalid: {run_id}") from error
        if not isinstance(data, dict):
            raise WorkflowError(f"run record is invalid: {run_id}")
        if data.get("schema_version") != WORKFLOW_RUN_SCHEMA_VERSION:
            raise WorkflowError(f"unsupported run record version: {run_id}")
        if data.get("run_id") != run_id:
            raise WorkflowError(f"run record identity mismatch: {run_id}")
        return data


_WORKFLOW_MANIFESTS = {
    "active-discovery": WorkflowManifest(
        name="active-discovery",
        workflow_version=1,
        description="Run bounded active discovery for each explicit scope target.",
        steps=(WorkflowStep(action="security_active_discovery", active=True),),
    ),
    "passive-recon": WorkflowManifest(
        name="passive-recon",
        workflow_version=1,
        description="Run passive reconnaissance for each explicit scope target.",
        steps=(WorkflowStep(action="security_passive_recon", active=False),),
    ),
}


class WorkflowRunner:
    """Execute built-in manifests through the existing gated tool handlers."""

    def __init__(
        self,
        *,
        policy: NetworkPolicy | None = None,
        evidence: EvidenceLog | None = None,
        clock: Callable[[], float] | None = None,
        executors: Mapping[str, WorkflowExecutor] | None = None,
        run_store: WorkflowRunStore | None = None,
    ) -> None:
        self._policy = policy if policy is not None else NetworkPolicy()
        self._evidence = evidence if evidence is not None else EvidenceLog()
        self._clock = clock or time.time
        self._executors = dict(executors) if executors is not None else None
        self._run_store = run_store

    def plan(self, workflow: str, scope_manager: ScopeManager) -> WorkflowPlan:
        """Build the deterministic run plan without executing any action."""
        manifest = get_workflow_manifest(workflow)
        scope = scope_manager.scope
        if scope is None or not scope_manager.is_active:
            raise WorkflowError("a valid Engagement Scope is required")
        for step in manifest.steps:
            action = "active" if step.active else "passive"
            if not scope.allows_action(action):
                raise WorkflowError(
                    f"workflow {manifest.name!r} requires the {action} scope action"
                )
            if step.active and (not scope.allow_active or not scope.ports):
                raise WorkflowError(
                    f"workflow {manifest.name!r} requires active authorization "
                    "and explicit ports"
                )

        # Expanding a CIDR would invent targets and can turn a small command
        # into a broad scan. Only explicit host entries are executable.
        targets = tuple(sorted(target for target in scope.targets if "/" not in target))
        if not targets:
            raise WorkflowError(
                "workflow requires at least one explicit host target; "
                "CIDR expansion is not implemented"
            )
        return WorkflowPlan(
            manifest=manifest,
            scope_id=scope.identifier,
            targets=targets,
        )

    async def run(
        self,
        workflow: str,
        scope_manager: ScopeManager,
    ) -> WorkflowRun:
        """Execute one deterministic plan and return its versioned run record."""
        plan = self.plan(workflow, scope_manager)
        if self._executors is not None:
            request_count = len(plan.targets) * len(plan.manifest.steps)
            try:
                scope_manager.consume_requests(request_count)
            except PermissionError as error:
                raise WorkflowError(str(error)) from error

        recorded_at = float(self._clock())
        run_id = hashlib.sha256(
            json.dumps(
                {
                    "plan": plan.to_dict(),
                    "recorded_at": recorded_at,
                },
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
        ).hexdigest()[:16]

        results: list[WorkflowResult] = []
        executors = self._executors_for(scope_manager)
        for step in plan.manifest.steps:
            executor = executors.get(step.action)
            if executor is None:
                raise WorkflowError(
                    f"workflow action is not available: {step.action}"
                )
            for target in plan.targets:
                try:
                    output = await asyncio.to_thread(executor, target)
                except Exception as error:
                    raise WorkflowError(
                        f"workflow action failed for {target}: "
                        f"{type(error).__name__}"
                    ) from error
                results.append(
                    WorkflowResult(
                        action=step.action,
                        target=target,
                        output=redact_text(str(output)),
                    )
                )

        run = WorkflowRun(
            run_id=run_id,
            recorded_at=recorded_at,
            plan=plan,
            results=tuple(results),
        )
        if self._run_store is not None:
            self._run_store.save(run)
        return run

    def _executors_for(
        self,
        scope_manager: ScopeManager,
    ) -> Mapping[str, WorkflowExecutor]:
        if self._executors is not None:
            return self._executors
        context = SecurityToolContext(
            policy=self._policy,
            evidence=self._evidence,
            clock=self._clock,
            scope=scope_manager.scope,
            scope_manager=scope_manager,
            interactive=False,
        )
        passive_handler = make_passive_recon_handler(context)
        active_handler = make_active_discovery_handler(context)
        return {
            "security_passive_recon": lambda target: passive_handler(
                {"target": target}
            ),
            "security_active_discovery": lambda target: active_handler(
                {"target": target}
            ),
        }


def list_workflow_manifests() -> tuple[WorkflowManifest, ...]:
    """Return built-in workflows in canonical name order."""
    return tuple(_WORKFLOW_MANIFESTS[name] for name in sorted(_WORKFLOW_MANIFESTS))


def get_workflow_manifest(name: str) -> WorkflowManifest:
    """Resolve a built-in workflow or raise a concise user-facing error."""
    normalized = name.strip().lower()
    try:
        return _WORKFLOW_MANIFESTS[normalized]
    except KeyError as error:
        available = ", ".join(sorted(_WORKFLOW_MANIFESTS))
        raise WorkflowError(
            f"unknown workflow {name!r}; available: {available}"
        ) from error


def render_objective_plan(objective: str) -> str:
    """Render a conservative deterministic plan without executing anything."""
    normalized = " ".join(objective.split())
    if not normalized:
        raise WorkflowError("usage: /security plan <objective>")
    return "\n".join(
        [
            f"objective: {redact_text(normalized)}",
            "proposed workflow: passive-recon",
            "reason: start with the non-active built-in workflow",
            "execution: not started",
            "run with: /security run passive-recon",
        ]
    )


__all__ = [
    "WORKFLOW_MANIFEST_SCHEMA_VERSION",
    "WORKFLOW_RUN_SCHEMA_VERSION",
    "WorkflowError",
    "WorkflowManifest",
    "WorkflowPlan",
    "WorkflowResult",
    "WorkflowRun",
    "WorkflowRunStore",
    "WorkflowRunSummary",
    "WorkflowRunner",
    "WorkflowStep",
    "get_workflow_manifest",
    "list_workflow_manifests",
    "render_objective_plan",
]
