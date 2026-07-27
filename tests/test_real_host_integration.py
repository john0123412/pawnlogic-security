"""Exercise the installed Extension contract through the real core host."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

from core.commands import (
    COMMANDS,
    CommandContext,
    dispatch,
    register_owned_commands,
    unregister_owned_commands,
)
from core.extension_contracts import ExtensionState
from core.extensions import ExtensionManager
from core.tool_registry import ToolRegistry

from pawnlogic_security import __version__
from pawnlogic_security.extension import SecurityExtension


class _Distribution:
    name = "pawnlogic-security"
    version = __version__


class _EntryPoint:
    name = "security"
    value = "pawnlogic_security.extension:build_extension"
    dist = _Distribution()

    def __init__(self, extension: SecurityExtension) -> None:
        self._extension = extension

    def load(self) -> SecurityExtension:
        return self._extension


class _Sink:
    def __init__(self) -> None:
        self.lines: list[str] = []

    def print(self, value: object = "") -> None:
        self.lines.append(str(value))


def _scope_file(path: Path, *, active: bool = True) -> None:
    path.write_text(
        json.dumps(
            {
                "version": 1,
                "identifier": "integration",
                "authorized_by": "operator",
                "reference": "ticket-1",
                "expires_at": 9_999_999_999.0,
                "targets": ["example.com", "93.184.216.0/24"],
                "ports": ["80", "443"] if active else ["443"],
                "allow_active": active,
                "actions": ["passive", "active"] if active else ["passive"],
                "destructive": False,
                "max_requests": 20,
                "max_concurrency": 2,
                "max_duration": 60,
                "evidence_dir": "evidence",
            }
        ),
        encoding="utf-8",
    )


def test_real_host_registers_dispatches_and_preserves_security_command(
    tmp_path: Path,
) -> None:
    unregister_owned_commands("security")
    extension = SecurityExtension(clock=lambda: 1000.0)
    registry = ToolRegistry()
    manager = ExtensionManager(
        registry,
        runtime_home=tmp_path / "runtime",
        entry_points=[_EntryPoint(extension)],
        core_version="0.3.0",
        command_register=register_owned_commands,
        command_unregister=unregister_owned_commands,
    )
    try:
        status = manager.enable("security")
        assert status.state is ExtensionState.ENABLED, status.error
        assert "/security" in COMMANDS

        sink = _Sink()
        result = asyncio.run(
            dispatch(
                CommandContext(
                    verb="/security",
                    arg="status",
                    arg2="",
                    session=object(),
                    sink=sink,
                )
            )
        )
        assert result is None
        assert sink.lines == ["no scope active"]

        scope_path = tmp_path / "scope.json"
        _scope_file(scope_path)
        sink.lines.clear()
        asyncio.run(
            dispatch(
                CommandContext(
                    verb="/security",
                    arg="scope",
                    arg2=f"set {scope_path}",
                    session=object(),
                    sink=sink,
                )
            )
        )
        assert sink.lines and "loaded" in sink.lines[-1]
        assert "/security" in COMMANDS
        assert {spec.name for spec in registry.snapshot_specs()} == {
            "security_active_discovery",
            "security_passive_recon",
        }

        sink.lines.clear()
        asyncio.run(
            dispatch(
                CommandContext(
                    verb="/security",
                    arg="scope",
                    arg2="clear",
                    session=object(),
                    sink=sink,
                )
            )
        )
        assert sink.lines and "cleared" in sink.lines[-1]
        assert "/security" in COMMANDS
        assert registry.snapshot_specs() == ()
    finally:
        manager.shutdown()
        unregister_owned_commands("security")


def test_passive_scope_does_not_expose_active_tool_to_the_model(tmp_path: Path) -> None:
    extension = SecurityExtension(clock=lambda: 1000.0)
    registry = ToolRegistry()
    manager = ExtensionManager(
        registry,
        runtime_home=tmp_path / "runtime",
        entry_points=[_EntryPoint(extension)],
        core_version="0.3.0",
    )
    try:
        assert manager.enable("security").state is ExtensionState.ENABLED
        scope_path = tmp_path / "scope.json"
        _scope_file(scope_path, active=False)
        assert extension.scope_manager is not None

        extension.scope_manager.set_scope(scope_path)

        assert {spec.name for spec in registry.snapshot_specs()} == {
            "security_passive_recon"
        }
    finally:
        manager.shutdown()
