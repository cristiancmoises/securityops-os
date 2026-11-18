# CodeMark v1 project=4c63e0fe-589c-4944-8449-97e211a38b72 file=6b1b811d8a235bd2be1f6ca286e0dd3c owner="Cristian Cezar Mois\u00e9s"
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Security Ops OS Phase 44 offline admission and evidence-vault CLI."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
from typing import Any, Mapping

if __package__ in {None, ""}:  # pragma: no cover - installed script path
    script_dir = Path(__file__).resolve().parent
    package_root = script_dir.parent
    for candidate in (package_root, script_dir):
        if os.fspath(candidate) not in sys.path:
            sys.path.insert(0, os.fspath(candidate))
    import phase40_owner_trust as phase40
    import phase41_owner_ceremony as phase41
    import phase44_offline_admission as admission
else:
    from . import phase40_owner_trust as phase40
    from . import phase41_owner_ceremony as phase41
    from . import phase44_offline_admission as admission


def _load_json(path: Path, *, context: str, maximum: int = 32 * 1024 * 1024) -> dict[str, Any]:
    _, payload = phase40.measure_file(path, maximum=maximum, context=context)
    return admission._strict_json(payload, context)  # type: ignore[attr-defined]


def _write_json(path: Path, value: Mapping[str, Any], *, mode: int = 0o600) -> None:
    phase41._atomic_write(  # type: ignore[attr-defined]
        path, admission.canonical_json_bytes(value) + b"\n", mode=mode)


def command_contract(_args: argparse.Namespace) -> dict[str, Any]:
    return admission.offline_admission_contract()


def command_schemas(_args: argparse.Namespace) -> dict[str, Any]:
    return {
        "format": "securityops-phase44-schema-closure/1",
        "station_attestation": admission.station_attestation_schema(),
        "evidence_vault": admission.vault_manifest_schema(),
        "gate1_admission_dossier": admission.admission_dossier_schema(),
        "admission_ledger": admission.admission_ledger_schema(),
        "production_gates_approved": 0,
        "production_dispatch_allowed": False,
        "iso_release_allowed": False,
    }


def command_selftest(_args: argparse.Namespace) -> dict[str, Any]:
    return admission.phase44_selftest()


def command_observe(_args: argparse.Namespace) -> dict[str, Any]:
    return admission.blocked_observation()


def command_generate_kit(args: argparse.Namespace) -> dict[str, Any]:
    return admission.generate_operator_kit(args.destination)


def command_create_attestation(args: argparse.Namespace) -> dict[str, Any]:
    document = admission.create_station_attestation(
        sequence=args.sequence,
        created_unix=args.created_unix,
        expires_unix=args.expires_unix,
        station_role=args.station_role,
        station_id=args.station_id,
        challenge_nonce=args.challenge_nonce,
        transfer_id=args.transfer_id,
        package_manifest_digest=args.package_manifest_digest,
        custody_ledger_digest=args.custody_ledger_digest,
        preflight_digest=args.preflight_digest,
        source_snapshot_manifest_digest=args.source_snapshot_manifest_digest,
        station_boot_id_digest=args.station_boot_id_digest,
        station_kernel_release_digest=args.station_kernel_release_digest,
        station_executable_manifest_digest=args.station_executable_manifest_digest,
        station_storage_manifest_digest=args.station_storage_manifest_digest,
        operator_primary_fingerprint=args.operator_primary_fingerprint,
        operator_signing_fingerprint=args.operator_signing_fingerprint,
        operator_keyring_sha256=args.operator_keyring_sha256,
        fixture_mode=args.fixture,
    )
    _write_json(args.output, document, mode=0o400)
    return {
        "format": "securityops-phase44-station-attestation-publication/1",
        "attestation_digest": document["attestation_digest"],
        "output": os.fspath(args.output.absolute()),
        "signature_present": False,
        "station_authenticated": False,
        "gate1_approved": False,
        "production_gates_approved": 0,
        "production_dispatch_allowed": False,
        "iso_release_allowed": False,
    }


def command_verify_attestation(args: argparse.Namespace) -> dict[str, Any]:
    verified = admission.verify_signed_station_attestation(
        attestation_path=args.attestation,
        signature_path=args.signature,
        keyring_path=args.keyring,
        expected_operator_primary_fingerprint=args.operator_primary_fingerprint,
        expected_operator_signing_fingerprint=args.operator_signing_fingerprint,
        expected_operator_keyring_sha256=args.operator_keyring_sha256,
        now_unix=args.now,
        gpgv_executable=args.gpgv,
        gpg_executable=args.gpg,
    )
    result = verified.to_dict()
    if args.output is not None:
        _write_json(args.output, result, mode=0o600)
    return result


def command_materialize_vault(args: argparse.Namespace) -> dict[str, Any]:
    verified = admission.materialize_evidence_vault(
        source_root=args.source,
        vault_parent=args.destination,
        created_unix=args.created_unix,
        challenge_nonce=args.challenge_nonce,
        transfer_id=args.transfer_id,
        package_manifest_digest=args.package_manifest_digest,
        custody_ledger_digest=args.custody_ledger_digest,
        preflight_digest=args.preflight_digest,
        source_snapshot_manifest_digest=args.source_snapshot_manifest_digest,
        fixture_mode=args.fixture,
    )
    return {
        "format": "securityops-phase44-evidence-vault-publication/1",
        "path": os.fspath(verified.path),
        "manifest": verified.manifest,
        "gate1_approved": False,
        "production_gates_approved": 0,
        "production_dispatch_allowed": False,
        "iso_release_allowed": False,
    }


def command_verify_vault(args: argparse.Namespace) -> dict[str, Any]:
    verified = admission.verify_evidence_vault(args.vault)
    return {
        "format": "securityops-phase44-evidence-vault-verification/1",
        "path": os.fspath(verified.path),
        "manifest": verified.manifest,
        "gate1_approved": False,
        "production_gates_approved": 0,
        "production_dispatch_allowed": False,
        "iso_release_allowed": False,
    }


def command_verify_dossier(args: argparse.Namespace) -> dict[str, Any]:
    dossier = _load_json(args.dossier, context="Phase 44 Gate 1 admission dossier")
    return admission.parse_admission_dossier(dossier)


def command_verify_ledger(args: argparse.Namespace) -> dict[str, Any]:
    ledger = _load_json(
        args.ledger, context="Phase 44 admission ledger",
        maximum=admission.MAX_LEDGER_BYTES)
    return admission.parse_admission_ledger(ledger)


def command_publish_dossier(args: argparse.Namespace) -> dict[str, Any]:
    dossier = _load_json(args.dossier, context="Phase 44 Gate 1 admission dossier")
    return admission.publish_admission_dossier(
        args.ledger, dossier, quarantine=args.quarantine)


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

    item = commands.add_parser("create-attestation")
    item.add_argument("--sequence", type=int, required=True)
    item.add_argument("--created-unix", type=int, required=True)
    item.add_argument("--expires-unix", type=int, required=True)
    item.add_argument("--station-role", choices=admission.STATION_ROLES, required=True)
    item.add_argument("--station-id", required=True)
    item.add_argument("--challenge-nonce", required=True)
    item.add_argument("--transfer-id", required=True)
    item.add_argument("--package-manifest-digest", required=True)
    item.add_argument("--custody-ledger-digest", required=True)
    item.add_argument("--preflight-digest", required=True)
    item.add_argument("--source-snapshot-manifest-digest", required=True)
    item.add_argument("--station-boot-id-digest", required=True)
    item.add_argument("--station-kernel-release-digest", required=True)
    item.add_argument("--station-executable-manifest-digest", required=True)
    item.add_argument("--station-storage-manifest-digest", required=True)
    item.add_argument("--operator-primary-fingerprint", required=True)
    item.add_argument("--operator-signing-fingerprint", required=True)
    item.add_argument("--operator-keyring-sha256", required=True)
    item.add_argument("--fixture", action="store_true")
    item.add_argument("--output", type=Path, required=True)
    item.set_defaults(handler=command_create_attestation)

    item = commands.add_parser("verify-attestation")
    item.add_argument("--attestation", type=Path, required=True)
    item.add_argument("--signature", type=Path, required=True)
    item.add_argument("--keyring", type=Path, required=True)
    item.add_argument("--operator-primary-fingerprint", required=True)
    item.add_argument("--operator-signing-fingerprint", required=True)
    item.add_argument("--operator-keyring-sha256", required=True)
    item.add_argument("--now", type=int, required=True)
    item.add_argument("--gpgv", default="/usr/bin/gpgv")
    item.add_argument("--gpg", default="/usr/bin/gpg")
    item.add_argument("--output", type=Path)
    item.set_defaults(handler=command_verify_attestation)

    item = commands.add_parser("materialize-vault")
    item.add_argument("--source", type=Path, required=True)
    item.add_argument("--destination", type=Path, required=True)
    item.add_argument("--created-unix", type=int, required=True)
    item.add_argument("--challenge-nonce", required=True)
    item.add_argument("--transfer-id", required=True)
    item.add_argument("--package-manifest-digest", required=True)
    item.add_argument("--custody-ledger-digest", required=True)
    item.add_argument("--preflight-digest", required=True)
    item.add_argument("--source-snapshot-manifest-digest", required=True)
    item.add_argument("--fixture", action="store_true")
    item.set_defaults(handler=command_materialize_vault)

    item = commands.add_parser("verify-vault")
    item.add_argument("vault", type=Path)
    item.set_defaults(handler=command_verify_vault)

    item = commands.add_parser("verify-dossier")
    item.add_argument("dossier", type=Path)
    item.set_defaults(handler=command_verify_dossier)

    item = commands.add_parser("verify-ledger")
    item.add_argument("ledger", type=Path)
    item.set_defaults(handler=command_verify_ledger)

    item = commands.add_parser("publish-dossier")
    item.add_argument("--dossier", type=Path, required=True)
    item.add_argument("--ledger", type=Path, required=True)
    item.add_argument("--quarantine", action="store_true")
    item.set_defaults(handler=command_publish_dossier)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
        result = args.handler(args)
    except (phase40.PolicyError, OSError, ValueError) as exc:
        print(f"securityops-phase44-admission: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
