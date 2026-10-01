"""Discovery must not execute the Extension; enablement must be explicit."""

from __future__ import annotations

import asyncio
import importlib.metadata as metadata
import inspect
import json
from pathlib import Path

from core.commands import CommandContext
from core.extension_contracts import (
    ExtensionContext,
    ExtensionContributions,
    ExtensionManifest,
)
from core.tool_registry import ToolSpec

from pawnlogic_security.extension import (
    API_VERSION,
    EXTENSION_NAME,
    SecurityExtension,
    build_extension,
)

ENTRY_POINT_GROUP = "pawnlogic.extensions"


class RecordingRegistrar:
    def __init__(self) -> None:
        self.registered: list[object] = []

    def register_many(self, items) -> None:  # noqa: ANN001 - protocol shape
        self.registered.extend(items)


class InertSink:
    def emit(self, event) -> None:  # noqa: ANN001 - protocol shape
        return None


class RecordingCommandSink:
    def __init__(self) -> None:
        self.output: list[str] = []

    def print(self, text: str) -> None:
        self.output.append(text)


def make_context(tmp_path: Path) -> ExtensionContext:
    return ExtensionContext(
        name=EXTENSION_NAME,
        core_version="0.4.0",
        runtime_home=tmp_path,
        config={},
        tools=RecordingRegistrar(),
        commands=RecordingRegistrar(),
        prompts=RecordingRegistrar(),
        events=InertSink(),
        phases=RecordingRegistrar(),
    )


def test_entry_point_is_declared_in_installed_metadata():
    names = {
        ep.name
        for ep in metadata.entry_points(group=ENTRY_POINT_GROUP)
        if ep.name == EXTENSION_NAME
    }
    assert EXTENSION_NAME in names


def test_discovery_reads_metadata_without_loading_the_entry_point():
    """Reading the entry point must not import or run the Extension body."""
    selected = [
        ep
        for ep in metadata.entry_points(group=ENTRY_POINT_GROUP)
        if ep.name == EXTENSION_NAME
    ]
    assert selected, "entry point not found"
    entry_point = selected[0]
    # The value is a string until something calls .load().
    assert entry_point.value == "pawnlogic_security.extension:build_extension"
    assert isinstance(entry_point.value, str)


def test_the_factory_does_not_start_the_extension():
    extension = build_extension()
    assert isinstance(extension, SecurityExtension)
    assert extension.started is False
    assert extension.evidence is None


def test_manifest_declares_a_narrow_core_range_and_api_version():
    manifest = build_extension().manifest
    assert isinstance(manifest, ExtensionManifest)
    assert manifest.name == EXTENSION_NAME
    assert manifest.core_version_spec == ">=0.4,<0.5"
    assert manifest.api_version == API_VERSION


def test_start_returns_commands_but_no_tools(tmp_path: Path):
    extension = build_extension()
    contributions = extension.start(make_context(tmp_path))

    assert isinstance(contributions, ExtensionContributions)
    assert not contributions.tools  # tools appear only when a scope is active
    assert contributions.commands  # commands are always available
    assert extension.started is True


def test_security_command_uses_host_async_context_and_sink(tmp_path: Path):
    extension = build_extension()
    contributions = extension.start(make_context(tmp_path))
    command = contributions.commands[0]
    sink = RecordingCommandSink()
    context = CommandContext(
        verb="/security",
        arg="status",
        arg2="",
        session=object(),
        sink=sink,
    )

    assert command.name == "/security"
    assert inspect.iscoroutinefunction(command.handler)
    assert asyncio.run(command.handler(context)) is None
    assert sink.output == ["no scope active"]


def test_security_scope_set_accepts_quoted_file_path(tmp_path: Path):
    extension = build_extension()
    contributions = extension.start(make_context(tmp_path))
    command = contributions.commands[0]
    scope_path = tmp_path / "scope files" / "engagement.json"
    scope_path.parent.mkdir()
    scope_path.write_text(
        json.dumps(
            {
                "version": 1,
                "identifier": "quoted-path",
                "authorized_by": "tester",
                "expires_at": 9999999999.0,
                "targets": ["127.0.0.1"],
                "actions": ["passive"],
                "max_requests": 10,
                "max_concurrency": 1,
                "max_duration": 60,
            }
        ),
        encoding="utf-8",
    )
    sink = RecordingCommandSink()
    context = CommandContext(
        verb="/security",
        arg="scope",
        arg2=f'set "{scope_path}"',
        session=object(),
        sink=sink,
    )

    assert asyncio.run(command.handler(context)) is None
    assert sink.output == [
        "scope quoted-path loaded from engagement.json, "
        "1 targets, expires at 9999999999.0"
    ]


def test_security_plan_is_deterministic_and_does_not_execute(tmp_path: Path):
    extension = build_extension()
    contributions = extension.start(make_context(tmp_path))
    command = contributions.commands[0]
    sink = RecordingCommandSink()
    context = CommandContext(
        verb="/security",
        arg="plan",
        arg2="review the public attack surface",
        session=object(),
        sink=sink,
    )

    assert asyncio.run(command.handler(context)) is None
    assert sink.output == [
        "\n".join(
            [
                "objective: review the public attack surface",
                "proposed workflow: passive-recon",
                "reason: start with the non-active built-in workflow",
                "execution: not started",
                "run with: /security run passive-recon",
            ]
        )
    ]
    assert extension.evidence is not None
    assert len(extension.evidence) == 0


def test_security_run_uses_the_shared_scope_gated_runner(tmp_path: Path):
    extension = build_extension()
    host_context = make_context(tmp_path)
    extension.start(host_context)
    scope_file = tmp_path / "scope.json"
    scope_file.write_text(
        """{
        "version": 1,
        "identifier": "hosted-run",
        "authorized_by": "tester",
        "expires_at": 9999999999.0,
        "targets": ["127.0.0.1"],
        "actions": ["passive"],
        "max_requests": 10,
        "max_concurrency": 1,
        "max_duration": 60
    }""",
        encoding="utf-8",
    )
    extension.scope_manager.set_scope(scope_file)
    command = extension.contribute(host_context).commands[0]
    sink = RecordingCommandSink()
    command_context = CommandContext(
        verb="/security",
        arg="run",
        arg2="passive-recon",
        session=object(),
        sink=sink,
    )

    assert asyncio.run(command.handler(command_context)) is None
    assert "workflow passive-recon v1" in sink.output[0]
    assert "security_passive_recon" in sink.output[0]
    assert "[refused]" in sink.output[0]


def test_security_evidence_list_is_empty_before_any_workflow_run(tmp_path: Path):
    extension = build_extension()
    contributions = extension.start(make_context(tmp_path))
    command = contributions.commands[0]
    sink = RecordingCommandSink()
    context = CommandContext(
        verb="/security",
        arg="evidence",
        arg2="list",
        session=object(),
        sink=sink,
    )

    assert asyncio.run(command.handler(context)) is None
    assert sink.output == ["no workflow runs recorded"]


def test_security_evidence_lists_and_exports_completed_run(tmp_path: Path):
    extension = build_extension()
    host_context = make_context(tmp_path)
    contributions = extension.start(host_context)
    command = contributions.commands[0]
    scope_file = tmp_path / "scope.json"
    scope_file.write_text(
        json.dumps(
            {
                "version": 1,
                "identifier": "evidence-run",
                "authorized_by": "tester",
                "expires_at": 9999999999.0,
                "targets": ["127.0.0.1"],
                "actions": ["passive"],
                "max_requests": 10,
                "max_concurrency": 1,
                "max_duration": 60,
            }
        ),
        encoding="utf-8",
    )
    extension.scope_manager.set_scope(scope_file)
    run_sink = RecordingCommandSink()
    asyncio.run(
        command.handler(
            CommandContext(
                verb="/security",
                arg="run",
                arg2="passive-recon",
                session=object(),
                sink=run_sink,
            )
        )
    )
    run_id = run_sink.output[0].splitlines()[1].removeprefix("run: ")

    list_sink = RecordingCommandSink()
    asyncio.run(
        command.handler(
            CommandContext(
                verb="/security",
                arg="evidence",
                arg2="list",
                session=object(),
                sink=list_sink,
            )
        )
    )
    assert list_sink.output[0].startswith(
        f"{run_id} workflow=passive-recon scope=evidence-run"
    )

    export_sink = RecordingCommandSink()
    asyncio.run(
        command.handler(
            CommandContext(
                verb="/security",
                arg="evidence",
                arg2=f"export {run_id}",
                session=object(),
                sink=export_sink,
            )
        )
    )
    exported = json.loads(export_sink.output[0])
    assert exported["schema_version"] == 1
    assert exported["run_id"] == run_id
    assert exported["plan"]["manifest"]["name"] == "passive-recon"


def test_security_run_uses_scope_relative_evidence_directory(tmp_path: Path):
    extension = build_extension()
    host_context = make_context(tmp_path)
    command = extension.start(host_context).commands[0]
    scope_file = tmp_path / "scope.json"
    scope_file.write_text(
        json.dumps(
            {
                "version": 1,
                "identifier": "scoped-evidence",
                "authorized_by": "tester",
                "expires_at": 9999999999.0,
                "targets": ["127.0.0.1"],
                "actions": ["passive"],
                "max_requests": 10,
                "max_concurrency": 1,
                "max_duration": 60,
                "evidence_dir": "records",
            }
        ),
        encoding="utf-8",
    )
    extension.scope_manager.set_scope(scope_file)
    extension.contribute(host_context)
    sink = RecordingCommandSink()

    asyncio.run(
        command.handler(
            CommandContext(
                verb="/security",
                arg="run",
                arg2="passive-recon",
                session=object(),
                sink=sink,
            )
        )
    )

    assert (tmp_path / "records" / "evidence.jsonl").is_file()
    assert len(list((tmp_path / "records" / "runs").glob("*.json"))) == 1
    assert not (tmp_path / "security" / "evidence.jsonl").exists()


def test_contribute_returns_only_tools_authorized_by_scope(tmp_path: Path):
    extension = build_extension()
    context = make_context(tmp_path)
    extension.start(context)

    # Load a scope so the tool set becomes knowable.
    scope_file = tmp_path / "scope.json"
    scope_file.write_text(
        """{
        "version": 1,
        "identifier": "test-engagement",
        "authorized_by": "tester",
        "expires_at": 9999999999.0,
        "targets": ["example.com"],
        "allow_active": false,
        "max_requests": 10,
        "max_concurrency": 1,
        "max_duration": 60
    }""",
        encoding="utf-8",
    )
    extension.scope_manager.set_scope(scope_file)

    contributions = extension.contribute(context)
    assert isinstance(contributions, ExtensionContributions)
    assert contributions.tools
    assert all(isinstance(spec, ToolSpec) for spec in contributions.tools)
    names = {spec.name for spec in contributions.tools}
    assert names == {"security_passive_recon"}


def test_stop_releases_state_and_is_safe_before_start():
    extension = build_extension()
    extension.stop()  # never started; must not raise
    assert extension.started is False


def test_start_then_stop_round_trips(tmp_path: Path):
    extension = build_extension()
    extension.start(make_context(tmp_path))
    assert extension.started is True
    extension.stop()
    assert extension.started is False
    assert extension.evidence is None


def test_start_succeeds_and_records_state(tmp_path: Path):
    extension = SecurityExtension()
    context = make_context(tmp_path)
    contributions = extension.start(context)

    assert extension.started is True
    assert extension.evidence is not None
    assert extension.scope_manager is not None
    assert contributions.commands
    assert not contributions.tools  # tools are scope-gated


def test_tools_carry_a_real_trust_boundary_and_capability(tmp_path: Path):
    extension = build_extension()
    context = make_context(tmp_path)
    extension.start(context)
    scope_file = tmp_path / "scope.json"
    scope_file.write_text(
        """{
        "version": 1,
        "identifier": "test-engagement",
        "authorized_by": "tester",
        "expires_at": 9999999999.0,
        "targets": ["example.com"],
        "allow_active": false,
        "max_requests": 10,
        "max_concurrency": 1,
        "max_duration": 60
    }""",
        encoding="utf-8",
    )
    extension.scope_manager.set_scope(scope_file)
    contributions = extension.contribute(context)
    for spec in contributions.tools:
        assert spec.capabilities == frozenset({"network"})
        assert spec.trust.value == "private_network"
