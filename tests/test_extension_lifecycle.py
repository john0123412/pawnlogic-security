"""Discovery must not execute the Extension; enablement must be explicit."""

from __future__ import annotations

import importlib.metadata as metadata
from pathlib import Path

import pytest
from core.extension_contracts import (
    ExtensionContext,
    ExtensionContributions,
    ExtensionManifest,
)
from core.network_policy import NetworkPolicy
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


def make_context(tmp_path: Path) -> ExtensionContext:
    return ExtensionContext(
        name=EXTENSION_NAME,
        core_version="0.3.0",
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
    assert manifest.core_version_spec == ">=0.3,<0.4"
    assert manifest.api_version == API_VERSION


def test_start_returns_tool_contributions_the_host_can_register(tmp_path: Path):
    extension = build_extension()
    contributions = extension.start(make_context(tmp_path))

    assert isinstance(contributions, ExtensionContributions)
    assert contributions.tools
    assert all(isinstance(spec, ToolSpec) for spec in contributions.tools)
    names = {spec.name for spec in contributions.tools}
    assert names == {"security_passive_recon", "security_active_discovery"}
    assert extension.started is True


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


def test_a_failing_start_leaves_nothing_registered(tmp_path: Path):
    """A partial start must not hand the host half a tool set."""

    class ExplodingPolicy(NetworkPolicy):
        def __init__(self) -> None:
            raise RuntimeError("policy construction failed")

    extension = SecurityExtension(policy=None)
    context = make_context(tmp_path)

    # Force the failure inside start() by making ToolSpec construction fail.
    import pawnlogic_security.extension as module

    original = module.NetworkPolicy
    module.NetworkPolicy = ExplodingPolicy  # type: ignore[misc]
    try:
        with pytest.raises(RuntimeError):
            extension.start(context)
    finally:
        module.NetworkPolicy = original  # type: ignore[misc]

    assert extension.started is False
    assert extension.evidence is None
    assert context.tools.registered == []  # type: ignore[attr-defined]


def test_tools_carry_a_real_trust_boundary_and_capability(tmp_path: Path):
    contributions = build_extension().start(make_context(tmp_path))
    for spec in contributions.tools:
        assert spec.capabilities == frozenset({"network"})
        assert spec.trust.value == "private_network"
