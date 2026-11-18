# CodeMark v1 project=4c63e0fe-589c-4944-8449-97e211a38b72 file=61b2156b84e55461b2847b25e01452b4 owner="Cristian Cezar Mois\u00e9s"
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Security Ops OS Phase 42 offline-media and witnessed-ceremony CLI."""
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
    import phase42_media as media
    import phase42_offline_ceremony as ceremony
else:
    from . import phase40_owner_trust as phase40
    from . import phase42_media as media
    from . import phase42_offline_ceremony as ceremony


def _load_json(path: Path, *, context: str, maximum: int = 32 * 1024 * 1024) -> dict[str, Any]:
    _, payload = phase40.measure_file(path, maximum=maximum, context=context)
    return ceremony._strict_json(payload, context)  # type: ignore[attr-defined]


def _write_json(path: Path, value: Mapping[str, Any], *, mode: int = 0o600) -> None:
    payload = ceremony.canonical_json_bytes(value) + b"\n"
    ceremony._atomic_write(path, payload, mode=mode)  # type: ignore[attr-defined]


def _role_paths(values: list[str] | None, *, allowed: set[str]) -> dict[str, Path]:
    result: dict[str, Path] = {}
    for raw in values or []:
        if "=" not in raw:
            raise phase40.PolicyError("Phase 42 payload must use ROLE=PATH")
        role, path = raw.split("=", 1)
        if role not in allowed or role in result or not path:
            raise phase40.PolicyError("Phase 42 payload role is invalid or duplicated")
        result[role] = Path(path)
    return result


def command_contract(_args: argparse.Namespace) -> dict[str, Any]:
    return ceremony.offline_ceremony_contract()


def command_schemas(_args: argparse.Namespace) -> dict[str, Any]:
    return {
        "format": "securityops-phase42-schema-closure/1",
        "media_manifest": media.manifest_schema(),
        "media_ready": media.ready_schema(),
        "media_review": media.review_schema(),
        "witness_checkpoint": ceremony.checkpoint_schema(),
        "witness_ledger": ceremony.witness_ledger_schema(),
        "ceremony_transcript": ceremony.transcript_schema(),
        "production_gates_approved": 0,
        "production_dispatch_allowed": False,
        "iso_release_allowed": False,
    }


def command_selftest(_args: argparse.Namespace) -> dict[str, Any]:
    return ceremony.phase42_selftest()


def command_observe(_args: argparse.Namespace) -> dict[str, Any]:
    return ceremony.blocked_observation()


def command_generate_kit(args: argparse.Namespace) -> dict[str, Any]:
    return ceremony.generate_operator_kit(args.destination)


def command_export_media(args: argparse.Namespace) -> dict[str, Any]:
    allowed = {role for role, _ in media.PACKAGE_PROFILES[args.profile]}
    payloads = _role_paths(args.payload, allowed=allowed)
    return media.export_media_package(
        destination=args.destination,
        profile=args.profile,
        payload_paths=payloads,
        package_sequence=args.sequence,
        created_unix=args.created_unix,
        expires_unix=args.expires_unix,
        challenge_nonce=args.challenge_nonce,
        previous_package_digest=args.previous_package_digest,
        chunk_bytes=args.chunk_bytes,
        maximum_media_bytes=args.maximum_media_bytes,
        fixture_mode=args.fixture,
    )


def _publish_review(args: argparse.Namespace, verified: media.VerifiedMediaPackage) -> dict[str, Any]:
    review = media.create_review_report(verified)
    if getattr(args, "review_output", None) is not None:
        _write_json(args.review_output, review, mode=0o600)
    return review


def command_verify_media(args: argparse.Namespace) -> dict[str, Any]:
    verified = media.verify_media_package(args.package, now_unix=args.now)
    return {
        "format": "securityops-phase42-media-verification-result/1",
        "verification": verified.to_dict(),
        "review": _publish_review(args, verified),
        "production_gates_approved": 0,
        "production_dispatch_allowed": False,
        "iso_release_allowed": False,
    }


def command_import_media(args: argparse.Namespace) -> dict[str, Any]:
    verified = media.import_media_package(args.package, args.destination, now_unix=args.now)
    return {
        "format": "securityops-phase42-media-import-result/1",
        "verification": verified.to_dict(),
        "review": _publish_review(args, verified),
        "materialized_directory": verified.materialized_directory,
        "owner_authority_created": False,
        "gate1_approved": False,
        "production_gates_approved": 0,
        "production_dispatch_allowed": False,
        "iso_release_allowed": False,
    }


def command_create_witness(args: argparse.Namespace) -> dict[str, Any]:
    state = _load_json(args.ceremony_state, context="Phase 42 ceremony state")
    store = _load_json(args.ceremony_store, context="Phase 42 ceremony store")
    trust = _load_json(args.trust_state, context="Phase 42 trust state")
    value = ceremony.create_witness_checkpoint(
        witness_id=args.witness_id,
        witness_primary_fingerprint=args.witness_primary_fingerprint,
        witness_signing_fingerprint=args.witness_signing_fingerprint,
        witness_keyring_sha256=args.witness_keyring_sha256,
        sequence=args.sequence,
        created_unix=args.created_unix,
        expires_unix=args.expires_unix,
        challenge_nonce=args.challenge_nonce,
        ceremony_state=state,
        ceremony_store=store,
        trust_state=trust,
        previous_checkpoint_digest=args.previous_checkpoint_digest,
        media_package_digest=args.media_package_digest,
        fixture_mode=args.fixture,
    )
    _write_json(args.output, value, mode=0o400)
    return {
        "format": "securityops-phase42-witness-checkpoint-publication/1",
        "checkpoint_digest": value["checkpoint_digest"],
        "output": os.fspath(args.output.absolute()),
        "signature_present": False,
        "witness_authenticated": False,
        "gate1_approved": False,
        "production_gates_approved": 0,
        "production_dispatch_allowed": False,
        "iso_release_allowed": False,
    }


def _verify_witness_from_args(args: argparse.Namespace) -> tuple[ceremony.VerifiedWitnessCheckpoint, dict[str, Any], dict[str, Any]]:
    state = _load_json(args.ceremony_state, context="Phase 42 ceremony state")
    store = _load_json(args.ceremony_store, context="Phase 42 ceremony store")
    trust = _load_json(args.trust_state, context="Phase 42 trust state")
    verified = ceremony.verify_signed_witness_checkpoint(
        checkpoint_path=args.checkpoint,
        signature_path=args.signature,
        keyring_path=args.keyring,
        expected_witness_primary_fingerprint=args.witness_primary_fingerprint,
        expected_witness_signing_fingerprint=args.witness_signing_fingerprint,
        expected_witness_keyring_sha256=args.witness_keyring_sha256,
        ceremony_state=state,
        ceremony_store=store,
        trust_state=trust,
        now_unix=args.now,
        gpgv_executable=args.gpgv,
    )
    return verified, store, trust


def command_verify_witness(args: argparse.Namespace) -> dict[str, Any]:
    verified, store, trust = _verify_witness_from_args(args)
    if args.verification_output is not None:
        _write_json(args.verification_output, verified.to_dict())
    ledger = None
    if args.ledger is not None:
        ledger = ceremony.publish_witness_ledger(args.ledger, verified)
    recovery = None
    if args.recovery_destination is not None:
        recovery = ceremony.witnessed_recovery(
            destination=args.recovery_destination,
            checkpoint_store=store,
            trust_state=trust,
            verified_witness=verified,
            minimum_sequence=args.minimum_sequence,
            fixture_drill=args.fixture_drill,
        )
    return {
        "format": "securityops-phase42-witness-admission/1",
        "verification": verified.to_dict(),
        "ledger_digest": "" if ledger is None else ledger["ledger_digest"],
        "recovery": recovery,
        "gate1_approved": False,
        "production_gates_approved": 0,
        "production_dispatch_allowed": False,
        "iso_release_allowed": False,
    }


def command_create_transcript(args: argparse.Namespace) -> dict[str, Any]:
    verified_witness, _, _ = _verify_witness_from_args(args)
    verifications = [
        _load_json(path, context="Phase 42 transition verification")
        for path in args.transition_verification
    ]
    states = [
        _load_json(path, context="Phase 42 transcript ceremony state")
        for path in args.transcript_state
    ]
    final_store = _load_json(args.final_ceremony_store, context="Phase 42 final ceremony store")
    final_trust = _load_json(args.final_trust_state, context="Phase 42 final trust state")
    transcript = ceremony.create_ceremony_transcript(
        transcript_id=args.transcript_id,
        created_unix=args.created_unix,
        challenge_nonce=args.transcript_challenge_nonce,
        transition_verifications=verifications,
        ceremony_states=states,
        final_ceremony_store=final_store,
        final_trust_state=final_trust,
        verified_witness=verified_witness,
        media_package_digests=args.media_package_digest,
    )
    _write_json(args.output, transcript, mode=0o400)
    return {
        "format": "securityops-phase42-transcript-publication/1",
        "transcript_digest": transcript["transcript_digest"],
        "output": os.fspath(args.output.absolute()),
        "owner_signature_present": False,
        "witness_signature_present": False,
        "transcript_alone_can_close_gate1": False,
        "gate1_approved": False,
        "production_gates_approved": 0,
        "production_dispatch_allowed": False,
        "iso_release_allowed": False,
    }


def command_verify_transcript(args: argparse.Namespace) -> dict[str, Any]:
    verified = ceremony.verify_signed_ceremony_transcript(
        transcript_path=args.transcript,
        owner_signature_path=args.owner_signature,
        owner_keyring_path=args.owner_keyring,
        witness_signature_path=args.witness_signature,
        witness_keyring_path=args.witness_keyring,
        expected_owner_signing_fingerprint=args.owner_signing_fingerprint,
        expected_owner_keyring_sha256=args.owner_keyring_sha256,
        expected_witness_signing_fingerprint=args.witness_signing_fingerprint,
        expected_witness_keyring_sha256=args.witness_keyring_sha256,
        gpgv_executable=args.gpgv,
    )
    if args.verification_output is not None:
        _write_json(args.verification_output, verified.to_dict())
    return verified.to_dict()


def _add_witness_verification_arguments(item: argparse.ArgumentParser) -> None:
    item.add_argument("--checkpoint", type=Path, required=True)
    item.add_argument("--signature", type=Path, required=True)
    item.add_argument("--keyring", type=Path, required=True)
    item.add_argument("--witness-primary-fingerprint", required=True)
    item.add_argument("--witness-signing-fingerprint", required=True)
    item.add_argument("--witness-keyring-sha256", required=True)
    item.add_argument("--ceremony-state", type=Path, required=True)
    item.add_argument("--ceremony-store", type=Path, required=True)
    item.add_argument("--trust-state", type=Path, required=True)
    item.add_argument("--now", type=int, required=True)
    item.add_argument("--gpgv", default="/usr/bin/gpgv")


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

    item = commands.add_parser("export-media")
    item.add_argument("--destination", type=Path, required=True)
    item.add_argument("--profile", choices=tuple(media.PACKAGE_PROFILES), required=True)
    item.add_argument("--payload", action="append", required=True, help="ROLE=PATH")
    item.add_argument("--sequence", type=int, required=True)
    item.add_argument("--created-unix", type=int, required=True)
    item.add_argument("--expires-unix", type=int, required=True)
    item.add_argument("--challenge-nonce", required=True)
    item.add_argument("--previous-package-digest", default=media.ZERO_SHA)
    item.add_argument("--chunk-bytes", type=int, default=media.MAX_CHUNK_BYTES)
    item.add_argument("--maximum-media-bytes", type=int, default=media.MAX_MEDIA_BYTES)
    item.add_argument("--fixture", action="store_true")
    item.set_defaults(handler=command_export_media)

    for name, handler in (("verify-media", command_verify_media), ("import-media", command_import_media)):
        item = commands.add_parser(name)
        item.add_argument("--package", type=Path, required=True)
        item.add_argument("--now", type=int, required=True)
        item.add_argument("--review-output", type=Path)
        if name == "import-media":
            item.add_argument("--destination", type=Path, required=True)
        item.set_defaults(handler=handler)

    item = commands.add_parser("create-witness")
    item.add_argument("--witness-id", required=True)
    item.add_argument("--witness-primary-fingerprint", required=True)
    item.add_argument("--witness-signing-fingerprint", required=True)
    item.add_argument("--witness-keyring-sha256", required=True)
    item.add_argument("--sequence", type=int, required=True)
    item.add_argument("--created-unix", type=int, required=True)
    item.add_argument("--expires-unix", type=int, required=True)
    item.add_argument("--challenge-nonce", required=True)
    item.add_argument("--ceremony-state", type=Path, required=True)
    item.add_argument("--ceremony-store", type=Path, required=True)
    item.add_argument("--trust-state", type=Path, required=True)
    item.add_argument("--previous-checkpoint-digest", default=ceremony.ZERO_SHA)
    item.add_argument("--media-package-digest", required=True)
    item.add_argument("--fixture", action="store_true")
    item.add_argument("--output", type=Path, required=True)
    item.set_defaults(handler=command_create_witness)

    item = commands.add_parser("verify-witness")
    _add_witness_verification_arguments(item)
    item.add_argument("--verification-output", type=Path)
    item.add_argument("--ledger", type=Path)
    item.add_argument("--recovery-destination", type=Path)
    item.add_argument("--minimum-sequence", type=int, default=1)
    item.add_argument("--fixture-drill", action="store_true")
    item.set_defaults(handler=command_verify_witness)

    item = commands.add_parser("create-transcript")
    _add_witness_verification_arguments(item)
    item.add_argument("--transcript-id", required=True)
    item.add_argument("--created-unix", type=int, required=True)
    item.add_argument("--transcript-challenge-nonce", required=True)
    item.add_argument("--transition-verification", type=Path, action="append", required=True)
    item.add_argument("--transcript-state", type=Path, action="append", required=True)
    item.add_argument("--final-ceremony-store", type=Path, required=True)
    item.add_argument("--final-trust-state", type=Path, required=True)
    item.add_argument("--media-package-digest", action="append", required=True)
    item.add_argument("--output", type=Path, required=True)
    item.set_defaults(handler=command_create_transcript)

    item = commands.add_parser("verify-transcript")
    item.add_argument("--transcript", type=Path, required=True)
    item.add_argument("--owner-signature", type=Path, required=True)
    item.add_argument("--owner-keyring", type=Path, required=True)
    item.add_argument("--witness-signature", type=Path, required=True)
    item.add_argument("--witness-keyring", type=Path, required=True)
    item.add_argument("--owner-signing-fingerprint", required=True)
    item.add_argument("--owner-keyring-sha256", required=True)
    item.add_argument("--witness-signing-fingerprint", required=True)
    item.add_argument("--witness-keyring-sha256", required=True)
    item.add_argument("--gpgv", default="/usr/bin/gpgv")
    item.add_argument("--verification-output", type=Path)
    item.set_defaults(handler=command_verify_transcript)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
        result = args.handler(args)
    except (phase40.PolicyError, OSError, ValueError) as exc:
        print(f"securityops-phase42-ceremony: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
