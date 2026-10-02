"""Mutation-sensitive checks for the package release workflow."""

from __future__ import annotations

import re
import runpy
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RELEASE_WORKFLOW = ROOT / ".github" / "workflows" / "release.yml"


def _workflow() -> str:
    return RELEASE_WORKFLOW.read_text(encoding="utf-8")


def _job_block(workflow: str, job: str) -> str:
    match = re.search(
        rf"^  {re.escape(job)}:\n(.*?)(?=^  [a-z0-9-]+:\n|\Z)",
        workflow,
        flags=re.MULTILINE | re.DOTALL,
    )
    assert match is not None, f"job {job!r} not found"
    return match.group(0)


def test_release_has_only_manual_testpypi_and_tag_production_entrypoints() -> None:
    workflow = _workflow()
    trigger_block = workflow[workflow.index("on:") : workflow.index("concurrency:")]

    assert "workflow_dispatch:" in trigger_block
    assert "target:" in trigger_block
    assert "default: testpypi" in trigger_block
    assert "options: [testpypi]" in trigger_block
    assert 'tags: ["v*"]' in trigger_block
    assert "release:" not in trigger_block
    assert "published" not in trigger_block


def test_tag_is_on_main_and_matches_package_before_artifacts_are_built() -> None:
    workflow = _workflow()

    checkout = workflow.index("fetch-depth: 0")
    tag_check = workflow.index("if: startsWith(github.ref, 'refs/tags/v')")
    ancestry_check = workflow.index(
        'git merge-base --is-ancestor "$GITHUB_SHA" "origin/main"'
    )
    changelog_check = workflow.index("Validate the matching changelog section")
    build = workflow.index("python -m build")
    assert checkout < ancestry_check < tag_check < changelog_check < build

    validation = workflow[checkout:build]
    assert 'EXPECTED_TAG="v${PACKAGE_VERSION}"' in validation
    assert '"$GITHUB_REF_NAME" != "$EXPECTED_TAG"' in validation
    assert "git fetch --no-tags origin main" in validation
    assert 'rf"^## \\[{re.escape(version)}\\](?:\\s+-\\s+.*)?$"' in validation
    assert "release section for {version} is empty" in validation


def test_testpypi_and_production_build_only_from_main_history() -> None:
    workflow = _workflow()
    build = _job_block(workflow, "build")

    ancestry = 'git merge-base --is-ancestor "$GITHUB_SHA" "origin/main"'
    assert ancestry in build
    assert build.index(ancestry) < build.index("python -m build")
    ancestry_prefix = build[: build.index(ancestry)]
    assert "if: startsWith(github.ref, 'refs/tags/v')" not in ancestry_prefix.split(
        "- name: Verify release source is on main", 1
    )[-1]


def test_build_exports_exact_wheel_and_sdist_identity() -> None:
    workflow = _workflow()

    assert "python tools/verify_release_artifacts.py" in workflow
    assert "version: ${{ steps.artifacts.outputs.version }}" in workflow
    assert "wheel-file: ${{ steps.artifacts.outputs.wheel-file }}" in workflow
    assert "wheel-sha256: ${{ steps.artifacts.outputs.wheel-sha256 }}" in workflow
    assert "path: dist/*" in workflow


def test_testpypi_upload_and_hash_pinned_smoke_are_separate() -> None:
    workflow = _workflow()
    publish = _job_block(workflow, "publish-testpypi")
    smoke = _job_block(workflow, "smoke-testpypi")

    assert "needs: build" in publish
    assert (
        "if: github.event_name == 'workflow_dispatch' && inputs.target == 'testpypi'"
        in publish
    )
    assert "environment: testpypi" in publish
    assert "id-token: write" in publish
    assert "gh-action-pypi-publish@release/v1" in publish
    assert "password:" not in publish
    assert "release_smoke.py" not in publish

    assert "needs: [build, publish-testpypi]" in smoke
    assert "https://test.pypi.org/simple/" in smoke
    assert "EXPECTED_VERSION: ${{ needs.build.outputs.version }}" in smoke
    assert (
        "EXPECTED_WHEEL_SHA256: ${{ needs.build.outputs.wheel-sha256 }}" in smoke
    )
    assert "--version \"$EXPECTED_VERSION\"" in smoke
    assert "--wheel-sha256 \"$EXPECTED_WHEEL_SHA256\"" in smoke
    assert '--extra-index-url "https://pypi.org/simple/"' in smoke


def test_production_is_upload_then_smoke_then_github_release() -> None:
    workflow = _workflow()
    publish = _job_block(workflow, "publish-pypi")
    smoke = _job_block(workflow, "smoke-pypi")
    release = _job_block(workflow, "github-release")

    assert "needs: build" in publish
    assert "environment: pypi" in publish
    assert "id-token: write" in publish
    assert "password:" not in publish
    assert "release_smoke.py" not in publish
    assert "needs: [build, publish-pypi]" in smoke
    assert "https://pypi.org/simple/" in smoke
    assert "EXPECTED_VERSION: ${{ needs.build.outputs.version }}" in smoke
    assert (
        "EXPECTED_WHEEL_SHA256: ${{ needs.build.outputs.wheel-sha256 }}" in smoke
    )
    assert "--version \"$EXPECTED_VERSION\"" in smoke
    assert "--wheel-sha256 \"$EXPECTED_WHEEL_SHA256\"" in smoke
    assert "--extra-index-url" not in smoke
    assert "needs: [build, smoke-pypi]" in release
    assert "permissions:\n      contents: write" in release
    assert "gh release create" in release

    assert workflow.count("id-token: write") == 2
    assert workflow.index("  publish-pypi:") < workflow.index("  smoke-pypi:")
    assert workflow.index("  smoke-pypi:") < workflow.index("  github-release:")


def test_release_smoke_rejects_a_stale_wheel_hash(tmp_path: Path) -> None:
    module = runpy.run_path(ROOT / "tools" / "release_smoke.py")
    wheel = tmp_path / "pawnlogic_security-0.1.0-py3-none-any.whl"
    wheel.write_bytes(b"stale wheel")

    try:
        module["verify_wheel"](wheel, "0.1.0", "0" * 64)
    except ValueError as error:
        assert "sha256" in str(error)
    else:
        raise AssertionError("a stale wheel hash must fail the release smoke")


def test_release_smoke_installs_and_checks_inside_a_fresh_venv(
    tmp_path: Path, monkeypatch
) -> None:
    module = runpy.run_path(ROOT / "tools" / "release_smoke.py")
    wheel = tmp_path / "pawnlogic_security-0.1.0-py3-none-any.whl"
    wheel.write_bytes(b"verified wheel")
    environment_dir = tmp_path / "smoke-venv"
    created: list[Path] = []
    calls: list[tuple[list[str], dict[str, object]]] = []

    class FakeEnvBuilder:
        def __init__(self, *, with_pip: bool) -> None:
            assert with_pip is True

        def create(self, path: Path) -> None:
            created.append(path)
            (path / "bin").mkdir(parents=True)

    def fake_run(command: list[str], **kwargs: object) -> None:
        calls.append((command, kwargs))

    monkeypatch.setattr(module["venv"], "EnvBuilder", FakeEnvBuilder)
    monkeypatch.setattr(module["subprocess"], "run", fake_run)

    module["_install_and_verify"](
        wheel,
        "0.1.0",
        index_url="https://test.pypi.org/simple/",
        extra_index_url="https://pypi.org/simple/",
        environment_dir=environment_dir,
    )

    assert created == [environment_dir]
    venv_python = str(environment_dir / "bin" / "python")
    install = calls[0][0]
    assert install[:4] == [venv_python, "-m", "pip", "install"]
    assert "--no-deps" not in install
    assert ["--index-url", "https://test.pypi.org/simple/"] == install[
        install.index("--index-url") : install.index("--index-url") + 2
    ]
    assert ["--extra-index-url", "https://pypi.org/simple/"] == install[
        install.index("--extra-index-url") : install.index("--extra-index-url") + 2
    ]
    assert str(wheel) in install

    verify = calls[1][0]
    assert verify[0] == venv_python
    assert "import core" in verify[2]
    assert "pawnlogic_security.__version__" in verify[2]
    assert "pawnlogic>=0.4,<0.5" in verify[2]
    assert "core_parts[0] == '0'" in verify[2]
    assert "core_parts[1] == '4'" in verify[2]

    cli = calls[2][0]
    assert cli == [str(environment_dir / "bin" / "pawn-security"), "--help"]
    assert all(kwargs["check"] is True for _, kwargs in calls)

    source = (ROOT / "tools" / "release_smoke.py").read_text(encoding="utf-8")
    main = source[source.index("def main()") :]
    assert main.index("verify_wheel(") < main.index("_install_and_verify(")


def test_artifact_verifier_rejects_more_than_wheel_and_sdist(tmp_path: Path) -> None:
    module = runpy.run_path(ROOT / "tools" / "verify_release_artifacts.py")
    (tmp_path / "pawnlogic_security-0.1.0-py3-none-any.whl").write_bytes(b"wheel")
    (tmp_path / "pawnlogic_security-0.1.0.tar.gz").write_bytes(b"sdist")
    (tmp_path / "unexpected.txt").write_text("extra", encoding="utf-8")

    try:
        module["verify_dist"](tmp_path)
    except ValueError as error:
        assert "exactly one wheel and one sdist" in str(error)
    else:
        raise AssertionError("an extra release artifact must fail verification")


def test_artifact_verifier_rejects_mismatched_versions(tmp_path: Path) -> None:
    module = runpy.run_path(ROOT / "tools" / "verify_release_artifacts.py")
    (tmp_path / "pawnlogic_security-0.1.0-py3-none-any.whl").write_bytes(b"wheel")
    (tmp_path / "pawnlogic_security-0.1.1.tar.gz").write_bytes(b"sdist")

    try:
        module["verify_dist"](tmp_path)
    except ValueError as error:
        assert "does not match" in str(error)
    else:
        raise AssertionError("mismatched artifact versions must fail verification")
