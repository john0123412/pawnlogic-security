"""The ``pawn-security`` command.

This is intentionally thin. It reports what the distribution provides and how
to enable it inside a PawnLogic host; it does not perform security work, and it
cannot enable itself.
"""

from __future__ import annotations

import argparse
from collections.abc import Sequence

from pawnlogic_security import __version__
from pawnlogic_security.extension import EXTENSION_NAME, MANIFEST


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pawn-security",
        description=(
            "Inspect the PawnLogic security Extension. Enable it from inside "
            "PawnLogic with: /extension enable " + EXTENSION_NAME
        ),
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"pawnlogic-security {__version__}",
    )
    parser.add_argument(
        "--manifest",
        action="store_true",
        help="Print the Extension manifest the host will validate.",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.manifest:
        print(f"name:              {MANIFEST.name}")
        print(f"version:           {MANIFEST.version}")
        print(f"core_version_spec: {MANIFEST.core_version_spec}")
        print(f"api_version:       {MANIFEST.api_version}")
        print(f"capabilities:      {', '.join(sorted(MANIFEST.capabilities))}")
        return 0

    print(f"pawnlogic-security {__version__}")
    print(f"Extension name: {EXTENSION_NAME}")
    print("This Extension stays disabled until it is explicitly enabled.")
    print(f"Enable it inside PawnLogic with: /extension enable {EXTENSION_NAME}")
    print(
        "Active operations additionally require an Engagement Scope that names "
        "the target and permits active work."
    )
    return 0


if __name__ == "__main__":  # pragma: no cover - module entry point
    raise SystemExit(main())
