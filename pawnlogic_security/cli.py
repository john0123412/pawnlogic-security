"""The ``pawn-security`` command.

This is intentionally thin. It reports what the distribution provides and how
to enable it inside a PawnLogic host; it does not perform security work, and it
cannot enable itself.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

from pawnlogic_security import __version__
from pawnlogic_security.extension import EXTENSION_NAME, MANIFEST
from pawnlogic_security.scope import from_scope_file
from pawnlogic_security.scope_file import load as load_scope_file


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

    subparsers = parser.add_subparsers(dest="command")

    scope_parser = subparsers.add_parser(
        "scope",
        help="Manage Engagement Scope files.",
    )
    scope_sub = scope_parser.add_subparsers(dest="scope_command")

    validate_parser = scope_sub.add_parser(
        "validate",
        help="Validate a scope file and report any issues.",
    )
    validate_parser.add_argument(
        "file",
        help="Path to the scope JSON file.",
    )

    return parser


def _cmd_scope_validate(file: str) -> int:
    """Validate a scope file and print a summary or the errors."""
    path = Path(file).expanduser()
    if not path.is_file():
        print(f"error: file not found: {path}", file=sys.stderr)
        return 1
    try:
        scope_file = load_scope_file(path)
    except ValueError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1

    # Also try building a full EngagementScope to catch validation errors
    # in the conversion step (CIDR normalization, etc.).
    try:
        scope = from_scope_file(scope_file, clock=0.0)
    except (ValueError, TypeError) as error:
        print(f"error: scope construction failed: {error}", file=sys.stderr)
        return 1

    print(f"identifier:  {scope.identifier}")
    print(f"authorized:  {scope.authorized_by}")
    print(f"expires at:  {scope.expires_at}")
    print(f"targets:     {len(scope.targets)}")
    if scope.exclude:
        print(f"exclude:     {len(scope.exclude)} entries")
    if scope.allow_active:
        print("active:      yes")
    if scope.max_requests:
        print(f"max_req:     {scope.max_requests}")
    if scope.max_concurrency:
        print(f"max_concur:  {scope.max_concurrency}")
    if scope.max_duration:
        print(f"max_dur:     {scope.max_duration}s")
    if scope.evidence_dir:
        print(f"evidence:    {scope.evidence_dir}")
    if scope.ports:
        print(f"ports:       {len(scope.ports)} entries")
    if scope_file.actions:
        print(f"actions:     {', '.join(sorted(scope_file.actions))}")
    print("scope file is valid")
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.command == "scope":
        if args.scope_command == "validate":
            return _cmd_scope_validate(args.file)
        # `pawn-security scope` with no subcommand shows scope help.
        build_parser().parse_args([*argv, "--help"] if argv else ["scope", "--help"])
        return 0  # pragma: no cover

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
