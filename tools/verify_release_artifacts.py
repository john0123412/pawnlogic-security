"""Validate release artifacts and expose their immutable identity to Actions."""

from __future__ import annotations

import argparse
import hashlib
import re
from dataclasses import dataclass
from pathlib import Path

WHEEL_PATTERN = re.compile(
    r"^pawnlogic_security-(?P<version>[^-]+)-[^-]+-[^-]+-[^-]+\.whl$"
)
SDIST_PATTERN = re.compile(r"^pawnlogic_security-(?P<version>.+)\.tar\.gz$")


@dataclass(frozen=True)
class ReleaseArtifacts:
    version: str
    wheel: Path
    sdist: Path
    wheel_sha256: str


def verify_dist(dist: Path) -> ReleaseArtifacts:
    files = sorted(path for path in dist.iterdir() if path.is_file())
    wheels = [path for path in files if path.suffix == ".whl"]
    sdists = [path for path in files if path.name.endswith(".tar.gz")]
    if len(files) != 2 or len(wheels) != 1 or len(sdists) != 1:
        raise ValueError(
            "dist must contain exactly one wheel and one sdist; "
            f"found {[path.name for path in files]}"
        )

    wheel_match = WHEEL_PATTERN.fullmatch(wheels[0].name)
    sdist_match = SDIST_PATTERN.fullmatch(sdists[0].name)
    if wheel_match is None or sdist_match is None:
        raise ValueError("release artifacts do not use pawnlogic-security filenames")

    wheel_version = wheel_match.group("version")
    sdist_version = sdist_match.group("version")
    if wheel_version != sdist_version:
        raise ValueError(
            f"wheel version {wheel_version} does not match sdist version {sdist_version}"
        )

    digest = hashlib.sha256(wheels[0].read_bytes()).hexdigest()
    return ReleaseArtifacts(wheel_version, wheels[0], sdists[0], digest)


def _write_github_outputs(path: Path, artifacts: ReleaseArtifacts) -> None:
    with path.open("a", encoding="utf-8") as output:
        output.write(f"version={artifacts.version}\n")
        output.write(f"wheel-file={artifacts.wheel.name}\n")
        output.write(f"wheel-sha256={artifacts.wheel_sha256}\n")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dist", type=Path, default=Path("dist"))
    parser.add_argument("--github-output", type=Path)
    args = parser.parse_args()

    artifacts = verify_dist(args.dist)
    print(f"wheel: {artifacts.wheel.name}")
    print(f"sdist: {artifacts.sdist.name}")
    print(f"wheel sha256: {artifacts.wheel_sha256}")
    if args.github_output is not None:
        _write_github_outputs(args.github_output, artifacts)


if __name__ == "__main__":
    main()
