"""Mutation-sensitive checks for the PawnLogic compatibility workflow."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CI_WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"


def _workflow() -> str:
    return CI_WORKFLOW.read_text(encoding="utf-8")


def test_ci_resolves_explicit_oldest_and_newest_03_lanes() -> None:
    workflow = _workflow()

    oldest = workflow.index("lane: oldest")
    newest = workflow.index("lane: newest")
    assert oldest < newest

    oldest_block = workflow[oldest:newest]
    newest_block = workflow[newest:]
    assert 'requirement: "pawnlogic==0.3.0"' in oldest_block
    assert (
        "source-ref: ${{ vars.PAWNLOGIC_OLDEST_03_REF || 'main' }}"
        in oldest_block
    )
    assert 'requirement: "pawnlogic>=0.3,<0.4"' in newest_block
    assert (
        "source-ref: ${{ inputs.core-ref || "
        "vars.PAWNLOGIC_NEWEST_03_REF || 'main' }}"
        in newest_block
    )
    assert "release/0.3.0-prep" not in workflow

    pypi_attempt = workflow.index("Try the supported core release from PyPI")
    source_checkout = workflow.index("Build the core fallback from source")
    assert pypi_attempt < source_checkout
    assert "continue-on-error: true" in workflow[pypi_attempt:source_checkout]
    assert "if: steps.pypi-core.outcome == 'failure'" in workflow[source_checkout:]


def test_ci_keeps_each_core_lane_in_a_distinct_artifact() -> None:
    workflow = _workflow()

    assert "name: core-wheel-${{ matrix.core.lane }}" in workflow
    assert "name: core-wheel-newest" in workflow
    assert "name: core-wheel-${{ matrix.core-lane }}" in workflow
    assert "core-lane: [oldest, newest]" in workflow


def test_ci_cross_tests_supported_python_versions_and_core_lanes() -> None:
    workflow = _workflow()
    test_job = workflow[workflow.index("  test:") :]

    assert 'python-version: ["3.10", "3.11", "3.12"]' in test_job
    assert "core-lane: [oldest, newest]" in test_job
    assert "needs: [lint, core-wheel]" in test_job
    assert "python -m pytest -q --tb=short" in test_job
