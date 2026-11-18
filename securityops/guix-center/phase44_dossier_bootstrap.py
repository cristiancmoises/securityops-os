# CodeMark v1 project=4c63e0fe-589c-4944-8449-97e211a38b72 file=3b5cdd960e3b54709009ebb238971cd5 owner="Cristian Cezar Mois\u00e9s"
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Security Ops OS Phase 44 Gate 1 dossier/vault CLI."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
from typing import Any, Mapping

if __package__ in {None, ""}:  # pragma: no cover - installed sibling layout
    script_dir = Path(__file__).resolve().parent
    package_root = script_dir.parent
    for candidate in (package_root, script_dir):
        if os.fspath(candidate) not in sys.path:
            sys.path.insert(0, os.fspath(candidate))
    import phase40_owner_trust as phase40
    import phase41_owner_ceremony as phase41
    import phase44_gate1_dossier as dossier
else:
    from . import phase40_owner_trust as phase40
    from . import phase41_owner_ceremony as phase41
    from . import phase44_gate1_dossier as dossier


def _load_json(path: Path, *, context: str, maximum: int = dossier.MAX_JSON_BYTES) -> dict[str, Any]:
    _, payload = phase40.measure_file(path, maximum=maximum, context=context)
    return dossier._strict_json(payload, context)  # type: ignore[attr-defined]


def _write_json(path: Path, value: Mapping[str, Any], *, mode: int = 0o600) -> None:
    phase41._atomic_write(path, dossier.canonical_json_bytes(value) + b"\n", mode=mode)  # type: ignore[attr-defined]


def command_contract(_args: argparse.Namespace) -> dict[str, Any]:
    return dossier.gate1_dossier_contract()


def command_schemas(_args: argparse.Namespace) -> dict[str, Any]:
    return {
        "format": "securityops-phase44-gate1-dossier-schema-closure/1",
        "manifest": dossier.manifest_schema(),
        "vault_ready": dossier.ready_schema(),
        "readiness": dossier.readiness_schema(),
        "gate1_approved": False,
        "production_gates_approved": 0,
        "production_dispatch_allowed": False,
        "iso_release_allowed": False,
    }


def command_selftest(_args: argparse.Namespace) -> dict[str, Any]:
    return dossier.phase44_selftest()


def command_observe(_args: argparse.Namespace) -> dict[str, Any]:
    return dossier.blocked_observation()


def command_generate_kit(args: argparse.Namespace) -> dict[str, Any]:
    return dossier.generate_operator_kit(args.destination)


def command_create_manifest(args: argparse.Namespace) -> dict[str, Any]:
    value = dossier.create_dossier_manifest(
        input_root=args.input_root,
        dossier_id=args.dossier_id,
        created_unix=args.created_unix,
        expires_unix=args.expires_unix,
        challenge_nonce=args.challenge_nonce,
        fixture_mode=args.fixture,
    )
    _write_json(args.output, value, mode=0o400)
    return value


def command_stage(args: argparse.Namespace) -> dict[str, Any]:
    manifest = _load_json(args.manifest, context="Phase 44 dossier manifest")
    return dossier.stage_dossier(
        input_root=args.input_root,
        manifest=manifest,
        destination=args.destination,
        now_unix=args.now_unix,
    ).to_dict()


def command_verify_vault(args: argparse.Namespace) -> dict[str, Any]:
    return dossier.verify_dossier_vault(args.vault, now_unix=args.now_unix).to_dict()


def command_create_readiness(args: argparse.Namespace) -> dict[str, Any]:
    vault = dossier.verify_dossier_vault(args.vault, now_unix=args.now_unix)
    value = dossier.create_readiness_report(vault)
    _write_json(args.output, value, mode=0o400)
    return value


def command_verify_readiness(args: argparse.Namespace) -> dict[str, Any]:
    vault = dossier.verify_dossier_vault(args.vault, now_unix=args.now_unix)
    report = _load_json(args.report, context="Phase 44 Gate 1 readiness report")
    return dossier.verify_readiness_report(vault, report)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name, handler in (
        ("contract", command_contract),
        ("schemas", command_schemas),
        ("selftest", command_selftest),
        ("observe", command_observe),
    ):
        item = commands.add_parser(name)
        item.set_defaults(handler=handler)

    item = commands.add_parser("generate-kit")
    item.add_argument("destination", type=Path)
    item.set_defaults(handler=command_generate_kit)

    item = commands.add_parser("create-manifest")
    item.add_argument("--input-root", type=Path, required=True)
    item.add_argument("--dossier-id", required=True)
    item.add_argument("--created-unix", type=int, required=True)
    item.add_argument("--expires-unix", type=int, required=True)
    item.add_argument("--challenge-nonce", required=True)
    item.add_argument("--fixture", action="store_true")
    item.add_argument("--output", type=Path, required=True)
    item.set_defaults(handler=command_create_manifest)

    item = commands.add_parser("stage")
    item.add_argument("--input-root", type=Path, required=True)
    item.add_argument("--manifest", type=Path, required=True)
    item.add_argument("--destination", type=Path, required=True)
    item.add_argument("--now-unix", type=int)
    item.set_defaults(handler=command_stage)

    item = commands.add_parser("verify-vault")
    item.add_argument("vault", type=Path)
    item.add_argument("--now-unix", type=int)
    item.set_defaults(handler=command_verify_vault)

    item = commands.add_parser("create-readiness")
    item.add_argument("vault", type=Path)
    item.add_argument("--now-unix", type=int)
    item.add_argument("--output", type=Path, required=True)
    item.set_defaults(handler=command_create_readiness)

    item = commands.add_parser("verify-readiness")
    item.add_argument("vault", type=Path)
    item.add_argument("--report", type=Path, required=True)
    item.add_argument("--now-unix", type=int)
    item.set_defaults(handler=command_verify_readiness)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
        result = args.handler(args)
    except (dossier.PolicyError, OSError, ValueError) as exc:
        print(f"securityops-phase44-dossier: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
