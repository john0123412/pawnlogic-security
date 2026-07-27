"""End-to-end: tools appear when a scope is set, disappear when cleared."""

from __future__ import annotations

import json
from pathlib import Path

from core.extension_contracts import ExtensionContext
from core.tool_registry import ToolRegistry

from pawnlogic_security.extension import EXTENSION_NAME, build_extension


class _Registrar:
    def __init__(self) -> None:
        self.registered: list[object] = []

    def register_many(self, items) -> None:  # noqa: ANN001
        self.registered.extend(items)


class _InertSink:
    def emit(self, event) -> None:  # noqa: ANN001
        return None


def _context(tmp_path: Path, registry: ToolRegistry) -> ExtensionContext:
    return ExtensionContext(
        name=EXTENSION_NAME,
        core_version="0.3.0",
        runtime_home=tmp_path,
        config={},
        tools=_Registrar(),
        commands=_Registrar(),
        prompts=_Registrar(),
        events=_InertSink(),
        phases=_Registrar(),
    )


def _scope_json(*, targets: list[str] | None = None, **extra: object) -> str:
    data: dict[str, object] = {
        "version": 1,
        "identifier": "test-engagement",
        "authorized_by": "tester",
        "expires_at": 9999999999.0,
        "targets": targets or ["example.com"],
    }
    data.update(extra)
    return json.dumps(data)


def test_tools_absent_at_start(tmp_path: Path):
    registry = ToolRegistry()
    extension = build_extension()
    ctx = _context(tmp_path, registry)
    extension.start(ctx)

    assert registry.snapshot_specs() == ()
    assert extension.started is True


def test_tools_appear_after_scope_set(tmp_path: Path):
    registry = ToolRegistry()
    extension = build_extension()
    ctx = _context(tmp_path, registry)
    extension.start(ctx)

    scope_file = tmp_path / "scope.json"
    scope_file.write_text(_scope_json(), encoding="utf-8")
    extension.scope_manager.set_scope(scope_file)

    # Now contribute to get the tools (simulating what the host does).
    contributions = extension.contribute(ctx)
    assert len(contributions.tools) == 2
    names = {spec.name for spec in contributions.tools}
    assert "security_passive_recon" in names
    assert "security_active_discovery" in names


def test_tools_disappear_after_scope_clear(tmp_path: Path):
    registry = ToolRegistry()
    extension = build_extension()
    ctx = _context(tmp_path, registry)
    extension.start(ctx)

    scope_file = tmp_path / "scope.json"
    scope_file.write_text(_scope_json(), encoding="utf-8")
    extension.scope_manager.set_scope(scope_file)
    extension.contribute(ctx)
    extension.scope_manager.clear_scope()

    contributions = extension.contribute(ctx)
    assert contributions.tools == ()


def test_commands_always_present_regardless_of_scope(tmp_path: Path):
    registry = ToolRegistry()
    extension = build_extension()
    ctx = _context(tmp_path, registry)
    start_contributions = extension.start(ctx)

    assert start_contributions.commands
    assert start_contributions.commands[0].name == "security"

    scope_file = tmp_path / "scope.json"
    scope_file.write_text(_scope_json(), encoding="utf-8")
    extension.scope_manager.set_scope(scope_file)
    with_scope = extension.contribute(ctx)
    assert with_scope.commands == ()  # contribute returns tools, not commands

    extension.scope_manager.clear_scope()
    without_scope = extension.contribute(ctx)
    assert without_scope.commands == ()


def test_stop_clears_scope_and_state(tmp_path: Path):
    registry = ToolRegistry()
    extension = build_extension()
    ctx = _context(tmp_path, registry)
    extension.start(ctx)

    scope_file = tmp_path / "scope.json"
    scope_file.write_text(_scope_json(), encoding="utf-8")
    extension.scope_manager.set_scope(scope_file)

    extension.stop()

    assert extension.started is False
    assert extension.scope_manager is None
    assert extension.evidence is None
