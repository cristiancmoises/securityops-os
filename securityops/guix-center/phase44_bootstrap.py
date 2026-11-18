# CodeMark v1 project=4c63e0fe-589c-4944-8449-97e211a38b72 file=c9a9aa624a5e5421870535ff0ba36932 owner="Cristian Cezar Mois\u00e9s"
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Security Ops OS Phase 44 multi-party Gate 1 closure CLI."""
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
    import phase44_gate1_closure as closure
else:
    from . import phase40_owner_trust as phase40
    from . import phase41_owner_ceremony as phase41
    from . import phase44_gate1_closure as closure


def _load_json(path: Path, *, context: str, maximum: int = closure.MAX_JSON_BYTES) -> dict[str, Any]:
    _, payload = phase40.measure_file(path, maximum=maximum, context=context)
    return closure._strict_json(payload, context)  # type: ignore[attr-defined]


def _write_json(path: Path, value: Mapping[str, Any], *, mode: int = 0o600) -> None:
    phase41._atomic_write(path, closure.canonical_json_bytes(value) + b"\n", mode=mode)  # type: ignore[attr-defined]


def command_contract(_args: argparse.Namespace) -> dict[str, Any]:
    return closure.phase44_contract()


def command_schemas(_args: argparse.Namespace) -> dict[str, Any]:
    return {
        "format": "securityops-phase44-schema-closure/1",
        "local_pin_policy": closure.local_pin_policy_schema(),
        "authority_pinset": closure.authority_pinset_schema(),
        "authority_pinset_verification": closure.pinset_verification_schema(),
        "admission_envelope": closure.admission_envelope_schema(),
        "envelope_verification": closure.envelope_verification_schema(),
        "final_receipt": closure.final_receipt_schema(),
        "final_ledger": closure.final_ledger_schema(),
        "production_gates_approved": 0,
        "production_dispatch_allowed": False,
        "iso_release_allowed": False,
    }


def command_selftest(_args: argparse.Namespace) -> dict[str, Any]:
    return closure.phase44_selftest()


def command_observe(_args: argparse.Namespace) -> dict[str, Any]:
    return closure.blocked_observation()


def command_generate_kit(args: argparse.Namespace) -> dict[str, Any]:
    return closure.generate_operator_kit(args.destination)


def command_create_local_pins(args: argparse.Namespace) -> dict[str, Any]:
    request = _load_json(args.request, context="Phase 44 local pin request")
    if set(request) != {"roles"}:
        raise closure.PolicyError("Phase 44 local pin request must contain only roles")
    result = closure.create_local_pin_policy(roles=request["roles"])
    _write_json(args.output, result, mode=0o400)
    return result


def command_create_pinset(args: argparse.Namespace) -> dict[str, Any]:
    policy = _load_json(args.local_pins, context="Phase 44 local pin policy")
    result = closure.create_authority_pinset(
        local_pin_policy=policy,
        generation=args.generation,
        created_unix=args.created_unix,
        expires_unix=args.expires_unix,
        challenge_nonce=args.challenge_nonce,
        previous_pinset_digest=args.previous_pinset_digest,
        fixture_mode=args.fixture,
    )
    _write_json(args.output, result, mode=0o400)
    return result


def _verify_pinset(args: argparse.Namespace) -> closure.VerifiedAuthorityPinset:
    policy = _load_json(args.local_pins, context="Phase 44 local pin policy")
    return closure.verify_signed_authority_pinset(
        pinset_path=args.pinset,
        owner_signature_path=args.pinset_owner_signature,
        owner_keyring_path=args.owner_keyring,
        witness_signature_path=args.pinset_witness_signature,
        witness_keyring_path=args.witness_keyring,
        local_pin_policy=policy,
        now_unix=args.now,
        gpgv_executable=args.gpgv,
        gpg_executable=args.gpg,
    )


def command_verify_pinset(args: argparse.Namespace) -> dict[str, Any]:
    verified = _verify_pinset(args)
    value = verified.to_dict()
    if args.output is not None:
        _write_json(args.output, value)
    return value


def command_create_envelope(args: argparse.Namespace) -> dict[str, Any]:
    verified = _verify_pinset(args)
    result = closure.create_admission_envelope(
        created_unix=args.created_unix,
        expires_unix=args.expires_unix,
        envelope_id=args.envelope_id,
        verified_pinset=verified,
        phase43_preflight=_load_json(args.preflight, context="Phase 43 Gate 1 preflight"),
        custody_ledger=_load_json(args.custody_ledger, context="Phase 43 custody ledger", maximum=closure.MAX_LEDGER_BYTES),
        trust_state=_load_json(args.trust_state, context="Phase 40 trust state"),
        ceremony_state=_load_json(args.ceremony_state, context="Phase 41 ceremony state"),
        gate_job=_load_json(args.gate_job, context="Phase 39 Gate 1 job"),
        witness_checkpoint=_load_json(args.witness_checkpoint, context="Phase 42 witness checkpoint"),
    )
    _write_json(args.output, result, mode=0o400)
    return result


def _verify_envelope(args: argparse.Namespace) -> closure.VerifiedAdmissionEnvelope:
    pinset = _verify_pinset(args)
    return closure.verify_signed_admission_envelope(
        envelope_path=args.envelope,
        owner_signature_path=args.envelope_owner_signature,
        owner_keyring_path=args.owner_keyring,
        witness_signature_path=args.envelope_witness_signature,
        witness_keyring_path=args.witness_keyring,
        verified_pinset=pinset,
        now_unix=args.now,
        gpgv_executable=args.gpgv,
        gpg_executable=args.gpg,
    )


def command_verify_envelope(args: argparse.Namespace) -> dict[str, Any]:
    verified = _verify_envelope(args)
    value = verified.to_dict()
    if args.output is not None:
        _write_json(args.output, value)
    return value


def command_create_final_receipt(args: argparse.Namespace) -> dict[str, Any]:
    verified = _verify_envelope(args)
    result = closure.create_final_gate1_receipt(
        created_unix=args.created_unix,
        verified_envelope=verified,
        phase43_preflight=_load_json(args.preflight, context="Phase 43 Gate 1 preflight"),
        phase41_decision=_load_json(args.phase41_decision, context="Phase 41 Gate 1 decision"),
        phase41_decision_ledger=_load_json(args.phase41_decision_ledger, context="Phase 41 Gate 1 decision ledger", maximum=closure.MAX_LEDGER_BYTES),
    )
    if args.output is not None:
        _write_json(args.output, result)
    if args.final_ledger is not None:
        closure.publish_final_receipt(args.final_ledger, result)
    return result


def command_verify_final_receipt(args: argparse.Namespace) -> dict[str, Any]:
    return closure.parse_final_gate1_receipt(_load_json(args.receipt, context="Phase 44 final receipt"))


def command_verify_final_ledger(args: argparse.Namespace) -> dict[str, Any]:
    return closure.parse_final_ledger(_load_json(args.ledger, context="Phase 44 final ledger", maximum=closure.MAX_LEDGER_BYTES))


def _add_pinset_verification_arguments(item: argparse.ArgumentParser) -> None:
    item.add_argument("--local-pins", type=Path, required=True)
    item.add_argument("--pinset", type=Path, required=True)
    item.add_argument("--pinset-owner-signature", type=Path, required=True)
    item.add_argument("--pinset-witness-signature", type=Path, required=True)
    item.add_argument("--owner-keyring", type=Path, required=True)
    item.add_argument("--witness-keyring", type=Path, required=True)
    item.add_argument("--now", type=int, required=True)
    item.add_argument("--gpgv", default="/usr/bin/gpgv")
    item.add_argument("--gpg", default="/usr/bin/gpg")


def _add_envelope_verification_arguments(item: argparse.ArgumentParser) -> None:
    _add_pinset_verification_arguments(item)
    item.add_argument("--envelope", type=Path, required=True)
    item.add_argument("--envelope-owner-signature", type=Path, required=True)
    item.add_argument("--envelope-witness-signature", type=Path, required=True)


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

    item = commands.add_parser("create-local-pins")
    item.add_argument("--request", type=Path, required=True)
    item.add_argument("--output", type=Path, required=True)
    item.set_defaults(handler=command_create_local_pins)

    item = commands.add_parser("create-pinset")
    item.add_argument("--local-pins", type=Path, required=True)
    item.add_argument("--generation", type=int, required=True)
    item.add_argument("--created-unix", type=int, required=True)
    item.add_argument("--expires-unix", type=int, required=True)
    item.add_argument("--challenge-nonce", required=True)
    item.add_argument("--previous-pinset-digest", default=closure.ZERO_SHA)
    item.add_argument("--fixture", action="store_true")
    item.add_argument("--output", type=Path, required=True)
    item.set_defaults(handler=command_create_pinset)

    item = commands.add_parser("verify-pinset")
    _add_pinset_verification_arguments(item)
    item.add_argument("--output", type=Path)
    item.set_defaults(handler=command_verify_pinset)

    item = commands.add_parser("create-envelope")
    _add_pinset_verification_arguments(item)
    item.add_argument("--created-unix", type=int, required=True)
    item.add_argument("--expires-unix", type=int, required=True)
    item.add_argument("--envelope-id", required=True)
    item.add_argument("--preflight", type=Path, required=True)
    item.add_argument("--custody-ledger", type=Path, required=True)
    item.add_argument("--trust-state", type=Path, required=True)
    item.add_argument("--ceremony-state", type=Path, required=True)
    item.add_argument("--gate-job", type=Path, required=True)
    item.add_argument("--witness-checkpoint", type=Path, required=True)
    item.add_argument("--output", type=Path, required=True)
    item.set_defaults(handler=command_create_envelope)

    item = commands.add_parser("verify-envelope")
    _add_envelope_verification_arguments(item)
    item.add_argument("--output", type=Path)
    item.set_defaults(handler=command_verify_envelope)

    item = commands.add_parser("create-final-receipt")
    _add_envelope_verification_arguments(item)
    item.add_argument("--created-unix", type=int, required=True)
    item.add_argument("--preflight", type=Path, required=True)
    item.add_argument("--phase41-decision", type=Path, required=True)
    item.add_argument("--phase41-decision-ledger", type=Path, required=True)
    item.add_argument("--output", type=Path)
    item.add_argument("--final-ledger", type=Path)
    item.set_defaults(handler=command_create_final_receipt)

    item = commands.add_parser("verify-final-receipt")
    item.add_argument("--receipt", type=Path, required=True)
    item.set_defaults(handler=command_verify_final_receipt)

    item = commands.add_parser("verify-final-ledger")
    item.add_argument("--ledger", type=Path, required=True)
    item.set_defaults(handler=command_verify_final_ledger)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
        result = args.handler(args)
    except (closure.PolicyError, OSError, ValueError) as exc:
        print(f"securityops-phase44-gate1: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
