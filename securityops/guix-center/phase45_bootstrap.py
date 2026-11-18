#!/usr/bin/env python3
# CodeMark v1 project=4c63e0fe-589c-4944-8449-97e211a38b72 file=7ce80a64eb0c513cb8d6f2f8f14dcc51 owner="Cristian Cezar Mois\u00e9s"
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Command-line entry point for the Phase 45 concrete execution harness."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys

if __package__ in {None, ""}:  # pragma: no cover - installed sibling layout
    script_dir = Path(__file__).resolve().parent
    package_root = script_dir.parent
    for candidate in (package_root, script_dir):
        if os.fspath(candidate) not in sys.path:
            sys.path.insert(0, os.fspath(candidate))
    import phase45_execution as phase45
else:
    from . import phase45_execution as phase45


def _print(value: object) -> None:
    print(json.dumps(value, sort_keys=True, separators=(",", ":")))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="securityops-phase45-execute")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("contract")
    sub.add_parser("schema")
    sub.add_parser("capabilities")
    sub.add_parser("selftest")
    sub.add_parser("blocked-observation")
    execute = sub.add_parser("execute")
    execute.add_argument("--runtime-root", type=Path, required=True)
    execute.add_argument("--os-root", type=Path, required=True)
    execute.add_argument("--output", type=Path, required=True)
    execute.add_argument("--matrix-rows", type=int, default=50_000)
    execute.add_argument("--soak-seconds", type=float, default=5.0)
    args = parser.parse_args(argv)
    try:
        if args.command == "contract":
            value = phase45.phase45_contract()
        elif args.command == "schema":
            value = phase45.execution_report_schema()
        elif args.command == "capabilities":
            value = phase45.phase38.capability_attestation(include_versions=True)
        elif args.command == "selftest":
            value = phase45.phase45_selftest()
        elif args.command == "blocked-observation":
            value = phase45.blocked_observation()
        else:
            value = phase45.execute_phase45(
                runtime_root=args.runtime_root,
                securityops_os_root=args.os_root,
                output_root=args.output,
                matrix_rows=args.matrix_rows,
                soak_seconds=args.soak_seconds,
            )
        _print(value)
        return 0
    except (OSError, phase45.PolicyError, ValueError) as exc:
        print(f"securityops-phase45-execute: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
