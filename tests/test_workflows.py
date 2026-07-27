"""Shared, reproducible workflow contracts for direct and hosted execution."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

from pawnlogic_security.scope_manager import ScopeManager
from pawnlogic_security.workflows import (
    WORKFLOW_MANIFEST_SCHEMA_VERSION,
    WorkflowError,
    WorkflowRunner,
    WorkflowRunStore,
    get_workflow_manifest,
)

NOW = 1_000_000.0


def _write_scope(path: Path, targets: list[str]) -> None:
    path.write_text(
        json.dumps(
            {
                "version": 1,
                "identifier": "workflow-test",
                "authorized_by": "tester",
                "expires_at": NOW + 3600,
                "targets": targets,
                "actions": ["passive"],
                "max_requests": 10,
                "max_concurrency": 1,
                "max_duration": 60,
            }
        ),
        encoding="utf-8",
    )


def test_workflow_manifest_is_versioned_and_reproducible():
    first = get_workflow_manifest("passive-recon")
    second = get_workflow_manifest("passive-recon")

    assert first.to_json() == second.to_json()
    assert json.loads(first.to_json()) == {
        "description": "Run passive reconnaissance for each explicit scope target.",
        "name": "passive-recon",
        "schema_version": WORKFLOW_MANIFEST_SCHEMA_VERSION,
        "steps": [
            {
                "action": "security_passive_recon",
                "active": False,
            }
        ],
        "workflow_version": 1,
    }


def test_runner_executes_manifest_for_sorted_explicit_scope_targets(tmp_path: Path):
    scope_path = tmp_path / "scope.json"
    _write_scope(scope_path, ["z.example", "a.example"])
    manager = ScopeManager(clock=lambda: NOW)
    manager.set_scope(scope_path)
    observed: list[str] = []

    def execute(target: str) -> str:
        observed.append(target)
        return f"checked {target}"

    runner = WorkflowRunner(
        clock=lambda: NOW,
        executors={"security_passive_recon": execute},
    )
    result = asyncio.run(runner.run("passive-recon", manager))

    assert observed == ["a.example", "z.example"]
    assert result.plan.to_json() == runner.plan("passive-recon", manager).to_json()
    assert [item.output for item in result.results] == [
        "checked a.example",
        "checked z.example",
    ]
    assert result.run_id


def test_completed_run_is_listable_and_exportable_by_safe_run_id(tmp_path: Path):
    scope_path = tmp_path / "scope.json"
    _write_scope(scope_path, ["example.com"])
    manager = ScopeManager(clock=lambda: NOW)
    manager.set_scope(scope_path)
    store = WorkflowRunStore(tmp_path / "runs")
    runner = WorkflowRunner(
        clock=lambda: NOW,
        executors={
            "security_passive_recon": lambda target: f"checked {target}"
        },
        run_store=store,
    )

    result = asyncio.run(runner.run("passive-recon", manager))

    summaries = store.list_runs()
    assert [(item.run_id, item.workflow, item.scope_id) for item in summaries] == [
        (result.run_id, "passive-recon", "workflow-test")
    ]
    assert store.export(result.run_id) == result.to_json()


def test_export_redacts_tampered_run_record(tmp_path: Path):
    scope_path = tmp_path / "scope.json"
    _write_scope(scope_path, ["example.com"])
    manager = ScopeManager(clock=lambda: NOW)
    manager.set_scope(scope_path)
    store = WorkflowRunStore(tmp_path / "runs")
    runner = WorkflowRunner(
        clock=lambda: NOW,
        executors={"security_passive_recon": lambda target: f"checked {target}"},
        run_store=store,
    )
    result = asyncio.run(runner.run("passive-recon", manager))
    path = store.root / f"{result.run_id}.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    synthetic_secret = "sk-ant-abcdefghijklmnopqrstuvwxyz012345"
    payload["results"][0]["output"] = synthetic_secret
    path.write_text(json.dumps(payload), encoding="utf-8")

    exported = store.export(result.run_id)

    assert synthetic_secret not in exported
    assert "[redacted]" in exported


def test_plan_rejects_workflow_action_not_authorized_by_scope(tmp_path: Path):
    scope_path = tmp_path / "scope.json"
    scope_path.write_text(
        json.dumps(
            {
                "version": 1,
                "identifier": "active-only",
                "authorized_by": "tester",
                "expires_at": NOW + 3600,
                "targets": ["example.com"],
                "ports": ["443"],
                "allow_active": True,
                "actions": ["active"],
                "max_requests": 10,
                "max_concurrency": 1,
                "max_duration": 60,
            }
        ),
        encoding="utf-8",
    )
    manager = ScopeManager(clock=lambda: NOW)
    manager.set_scope(scope_path)
    runner = WorkflowRunner(
        clock=lambda: NOW,
        executors={"security_passive_recon": lambda target: target},
    )

    with pytest.raises(WorkflowError, match="passive"):
        runner.plan("passive-recon", manager)
