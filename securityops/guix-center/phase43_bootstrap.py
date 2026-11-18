# CodeMark v1 project=4c63e0fe-589c-4944-8449-97e211a38b72 file=cc9ceed3fa30528a88b456aa41c6c21f owner="Cristian Cezar Mois\u00e9s"
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Security Ops OS Phase 43 offline custody and Gate 1 preflight CLI."""
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
    import phase42_media as media
    import phase43_offline_custody as custody
else:
    from . import phase40_owner_trust as phase40
    from . import phase41_owner_ceremony as phase41
    from . import phase42_media as media
    from . import phase43_offline_custody as custody


def _load_json(path: Path, *, context: str, maximum: int = 32 * 1024 * 1024) -> dict[str, Any]:
    _, payload = phase40.measure_file(path, maximum=maximum, context=context)
    return custody._strict_json(payload, context)  # type: ignore[attr-defined]


def _write_json(path: Path, value: Mapping[str, Any], *, mode: int = 0o600) -> None:
    phase41._atomic_write(  # type: ignore[attr-defined]
        path, custody.canonical_json_bytes(value) + b"\n", mode=mode)


def command_contract(_args: argparse.Namespace) -> dict[str, Any]:
    return custody.offline_custody_contract()


def command_schemas(_args: argparse.Namespace) -> dict[str, Any]:
    return {
        "format": "securityops-phase43-schema-closure/1",
        "custody_event": custody.event_schema(),
        "custody_ledger": custody.ledger_schema(),
        "gate1_preflight": custody.preflight_schema(),
        "production_gates_approved": 0,
        "production_dispatch_allowed": False,
        "iso_release_allowed": False,
    }


def command_selftest(_args: argparse.Namespace) -> dict[str, Any]:
    return custody.phase43_selftest()


def command_observe(_args: argparse.Namespace) -> dict[str, Any]:
    return custody.blocked_observation()


def command_generate_kit(args: argparse.Namespace) -> dict[str, Any]:
    return custody.generate_operator_kit(args.destination)


def command_create_event(args: argparse.Namespace) -> dict[str, Any]:
    verified = media.verify_media_package(args.package, now_unix=args.now)
    review = media.create_review_report(verified)
    event = custody.create_custody_event(
        verified_media=verified,
        review=review,
        sequence=args.sequence,
        created_unix=args.created_unix,
        expires_unix=args.expires_unix,
        challenge_nonce=args.challenge_nonce,
        transfer_id=args.transfer_id,
        event_type=args.event_type,
        station_id=args.station_id,
        operator_primary_fingerprint=args.operator_primary_fingerprint,
        operator_signing_fingerprint=args.operator_signing_fingerprint,
        operator_keyring_sha256=args.operator_keyring_sha256,
        previous_event_digest=args.previous_event_digest,
        fixture_mode=args.fixture,
    )
    _write_json(args.output, event, mode=0o400)
    return {
        "format": "securityops-phase43-custody-event-publication/1",
        "event_digest": event["event_digest"],
        "output": os.fspath(args.output.absolute()),
        "signature_present": False,
        "operator_authenticated": False,
        "gate1_approved": False,
        "production_gates_approved": 0,
        "production_dispatch_allowed": False,
        "iso_release_allowed": False,
    }


def command_verify_event(args: argparse.Namespace) -> dict[str, Any]:
    verified = custody.verify_signed_custody_event(
        event_path=args.event,
        signature_path=args.signature,
        keyring_path=args.keyring,
        expected_operator_primary_fingerprint=args.operator_primary_fingerprint,
        expected_operator_signing_fingerprint=args.operator_signing_fingerprint,
        expected_operator_keyring_sha256=args.operator_keyring_sha256,
        now_unix=args.now,
        gpgv_executable=args.gpgv,
        gpg_executable=args.gpg,
    )
    result: dict[str, Any] = {
        "format": "securityops-phase43-custody-event-admission/1",
        "verification": verified.to_dict(),
        "ledger": None,
        "gate1_approved": False,
        "production_gates_approved": 0,
        "production_dispatch_allowed": False,
        "iso_release_allowed": False,
    }
    if args.ledger is not None:
        result["ledger"] = custody.publish_custody_event(args.ledger, verified)
    if args.verification_output is not None:
        _write_json(args.verification_output, verified.to_dict(), mode=0o600)
    return result


def command_verify_ledger(args: argparse.Namespace) -> dict[str, Any]:
    value = _load_json(args.ledger, context="Phase 43 custody ledger", maximum=custody.MAX_LEDGER_BYTES)
    parsed = custody.parse_custody_ledger(value)
    return {
        "format": "securityops-phase43-custody-ledger-verification/1",
        "ledger": parsed,
        "gate1_approved": False,
        "production_gates_approved": 0,
        "production_dispatch_allowed": False,
        "iso_release_allowed": False,
    }


def command_verify_preflight(args: argparse.Namespace) -> dict[str, Any]:
    value = _load_json(args.preflight, context="Phase 43 Gate 1 preflight")
    return custody.parse_gate1_preflight(value)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name, handler in (
        ("contract", command_contract), ("schemas", command_schemas),
        ("selftest", command_selftest), ("observe", command_observe),
    ):
        item = commands.add_parser(name)
        item.set_defaults(handler=handler)

    item = commands.add_parser("generate-kit")
    item.add_argument("destination", type=Path)
    item.set_defaults(handler=command_generate_kit)

    item = commands.add_parser("create-event")
    item.add_argument("--package", type=Path, required=True)
    item.add_argument("--now", type=int, required=True)
    item.add_argument("--sequence", type=int, required=True)
    item.add_argument("--created-unix", type=int, required=True)
    item.add_argument("--expires-unix", type=int, required=True)
    item.add_argument("--challenge-nonce", required=True)
    item.add_argument("--transfer-id", required=True)
    item.add_argument("--event-type", choices=tuple(custody.EVENT_ROLE), required=True)
    item.add_argument("--station-id", required=True)
    item.add_argument("--operator-primary-fingerprint", required=True)
    item.add_argument("--operator-signing-fingerprint", required=True)
    item.add_argument("--operator-keyring-sha256", required=True)
    item.add_argument("--previous-event-digest", default=custody.ZERO_SHA)
    item.add_argument("--fixture", action="store_true")
    item.add_argument("--output", type=Path, required=True)
    item.set_defaults(handler=command_create_event)

    item = commands.add_parser("verify-event")
    item.add_argument("--event", type=Path, required=True)
    item.add_argument("--signature", type=Path, required=True)
    item.add_argument("--keyring", type=Path, required=True)
    item.add_argument("--operator-primary-fingerprint", required=True)
    item.add_argument("--operator-signing-fingerprint", required=True)
    item.add_argument("--operator-keyring-sha256", required=True)
    item.add_argument("--now", type=int, required=True)
    item.add_argument("--gpgv", default="/usr/bin/gpgv")
    item.add_argument("--gpg", default="/usr/bin/gpg")
    item.add_argument("--ledger", type=Path)
    item.add_argument("--verification-output", type=Path)
    item.set_defaults(handler=command_verify_event)

    item = commands.add_parser("verify-ledger")
    item.add_argument("--ledger", type=Path, required=True)
    item.set_defaults(handler=command_verify_ledger)

    item = commands.add_parser("verify-preflight")
    item.add_argument("--preflight", type=Path, required=True)
    item.set_defaults(handler=command_verify_preflight)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
        result = args.handler(args)
    except (phase40.PolicyError, OSError, ValueError) as exc:
        print(f"securityops-phase43-custody: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
