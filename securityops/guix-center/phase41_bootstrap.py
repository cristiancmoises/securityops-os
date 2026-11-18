# CodeMark v1 project=4c63e0fe-589c-4944-8449-97e211a38b72 file=b930ad9555b957718160359da4287b42 owner="Cristian Cezar Mois\u00e9s"
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Command line interface for the Phase 41 owner ceremony and Gate 1 boundary."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
from typing import Any, Mapping

if __package__ in {None, ""}:  # pragma: no cover - direct execution
    script_dir = Path(__file__).resolve().parent
    package_root = script_dir.parent
    for candidate in (package_root, script_dir):
        if os.fspath(candidate) not in sys.path:
            sys.path.insert(0, os.fspath(candidate))
    import phase40_owner_trust as phase40
    import phase41_gate1_execution as gate1
    import phase41_owner_ceremony as ceremony
else:  # pragma: no cover - imported package path
    from . import phase40_owner_trust as phase40
    from . import phase41_gate1_execution as gate1
    from . import phase41_owner_ceremony as ceremony


def _load_json(path: Path | None, *, context: str, maximum: int = 16 * 1024 * 1024) -> dict[str, Any] | None:
    if path is None:
        return None
    _, payload = phase40.measure_file(path, maximum=maximum, context=context)
    try:
        value = json.loads(payload.decode("utf-8", errors="strict"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise phase40.PolicyError(f"{context} is not valid JSON") from exc
    if type(value) is not dict:
        raise phase40.PolicyError(f"{context} is not an object")
    return value


def _write_json(path: Path, value: Mapping[str, Any], *, mode: int = 0o600) -> None:
    if path.exists() or path.is_symlink():
        raise phase40.PolicyError("Phase 41 output already exists")
    path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    payload = json.dumps(
        value, sort_keys=True, indent=2, ensure_ascii=False).encode("utf-8") + b"\n"
    fd = os.open(
        path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
        mode)
    try:
        os.fchmod(fd, mode)
        view = memoryview(payload)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise phase40.PolicyError("Phase 41 output write did not complete")
            view = view[written:]
        os.fsync(fd)
    finally:
        os.close(fd)


def _role_map(values: list[str] | None, *, context: str) -> dict[str, Path]:
    result: dict[str, Path] = {}
    for raw in values or []:
        if "=" not in raw:
            raise phase40.PolicyError(f"{context} must use ROLE=PATH")
        role, raw_path = raw.split("=", 1)
        if role not in ceremony.SIGNATURE_ROLES or role in result or not raw_path:
            raise phase40.PolicyError(f"{context} role is invalid or duplicated")
        result[role] = Path(raw_path)
    return result


def command_contract(args: argparse.Namespace) -> dict[str, Any]:
    if args.kind == "ceremony":
        return ceremony.ceremony_contract()
    if args.kind == "gate1":
        return gate1.gate1_execution_contract()
    return {
        "format": "securityops-phase41-contract-closure/1",
        "ceremony": ceremony.ceremony_contract(),
        "gate1": gate1.gate1_execution_contract(),
        "production_gates_approved": 0,
        "production_dispatch_allowed": False,
        "iso_release_allowed": False,
    }


def command_schemas(_args: argparse.Namespace) -> dict[str, Any]:
    return {
        "format": "securityops-phase41-schema-closure/1",
        "transition": ceremony.transition_schema(),
        "ceremony_state": ceremony.state_schema(),
        "ceremony_store": ceremony.store_schema(),
        "gate1_decision": gate1.decision_schema(),
        "gate1_ledger": gate1.ledger_schema(),
        "production_gates_approved": 0,
        "production_dispatch_allowed": False,
        "iso_release_allowed": False,
    }


def command_selftest(_args: argparse.Namespace) -> dict[str, Any]:
    return {
        "format": "securityops-phase41-selftest-closure/1",
        "ceremony": ceremony.phase41_selftest(),
        "gate1": gate1.phase41_gate1_selftest(),
        "production_gates_approved": 0,
        "production_dispatch_allowed": False,
        "iso_release_allowed": False,
    }


def command_observe(_args: argparse.Namespace) -> dict[str, Any]:
    return {
        "format": "securityops-phase41-local-observation/1",
        "ceremony": ceremony.blocked_ceremony_observation(),
        "gate1": gate1.blocked_gate1_observation(),
        "real_owner_authority_present": False,
        "production_gates_approved": 0,
        "production_dispatch_allowed": False,
        "iso_release_allowed": False,
        "iso_bytes_present": False,
    }


def command_generate_kit(args: argparse.Namespace) -> dict[str, Any]:
    return ceremony.generate_ceremony_kit(args.destination)


def command_create_transition(args: argparse.Namespace) -> dict[str, Any]:
    previous_ceremony = _load_json(
        args.previous_ceremony_state, context="Phase 41 previous ceremony state")
    previous_trust = _load_json(
        args.previous_trust_state, context="Phase 41 previous trust state")
    next_trust = _load_json(
        args.next_trust_state, context="Phase 41 next trust state")
    value = ceremony.create_transition(
        transition_type=args.transition_type,
        reason_code=args.reason_code,
        sequence=args.sequence,
        created_unix=args.created_unix,
        expires_unix=args.expires_unix,
        challenge_nonce=args.challenge_nonce,
        previous_ceremony_state=previous_ceremony,
        previous_trust_state=previous_trust,
        next_trust_state=next_trust,
        fixture_mode=args.fixture,
    )
    _write_json(args.output, value, mode=0o400)
    return {
        "format": "securityops-phase41-transition-publication/1",
        "transition_digest": value["transition_digest"],
        "required_signature_roles": value["required_signature_roles"],
        "output": os.fspath(args.output.absolute()),
        "signatures_present": False,
        "production_gates_approved": 0,
        "production_dispatch_allowed": False,
        "iso_release_allowed": False,
    }


def command_verify_transition(args: argparse.Namespace) -> dict[str, Any]:
    previous_ceremony = _load_json(
        args.previous_ceremony_state, context="Phase 41 previous ceremony state")
    previous_trust = _load_json(
        args.previous_trust_state, context="Phase 41 previous trust state")
    next_trust = _load_json(
        args.next_trust_state, context="Phase 41 next trust state")
    signatures = _role_map(args.signature, context="Phase 41 signature")
    keyrings = _role_map(args.keyring, context="Phase 41 keyring")
    verified = ceremony.verify_transition_signatures(
        transition_path=args.transition,
        signature_paths=signatures,
        keyring_paths=keyrings,
        previous_ceremony_state=previous_ceremony,
        previous_trust_state=previous_trust,
        next_trust_state=next_trust,
        now_unix=args.now,
        gpgv_executable=args.gpgv,
    )
    state = ceremony.create_ceremony_state(
        verified_transition=verified,
        previous_ceremony_state=previous_ceremony,
        previous_trust_state=previous_trust,
        next_trust_state=next_trust,
    )
    if args.verification_output is not None:
        _write_json(args.verification_output, verified.to_dict())
    if args.state_output is not None:
        _write_json(args.state_output, state)
    store = None
    if args.store is not None:
        store = ceremony.publish_ceremony_store(args.store, state)
    return {
        "format": "securityops-phase41-transition-admission/1",
        "verification": verified.to_dict(),
        "ceremony_state": state,
        "ceremony_store_digest": "" if store is None else store["store_digest"],
        "production_gates_approved": 0,
        "production_dispatch_allowed": False,
        "iso_release_allowed": False,
    }


def command_recover_store(args: argparse.Namespace) -> dict[str, Any]:
    checkpoint = _load_json(
        args.checkpoint, context="Phase 41 ceremony recovery checkpoint")
    assert checkpoint is not None
    value = ceremony.recover_ceremony_store(
        destination=args.destination,
        checkpoint=checkpoint,
        minimum_sequence=args.minimum_sequence,
        expected_state_digest=args.expected_state_digest,
    )
    return {
        "format": "securityops-phase41-ceremony-recovery/1",
        "store_digest": value["store_digest"],
        "highest_sequence": value["highest_sequence"],
        "state_digest": value["current_state"]["state_digest"],
        "production_gates_approved": 0,
        "production_dispatch_allowed": False,
        "iso_release_allowed": False,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)

    item = commands.add_parser("contract")
    item.add_argument("--kind", choices=("ceremony", "gate1", "all"), default="all")
    item.set_defaults(handler=command_contract)

    item = commands.add_parser("schemas")
    item.set_defaults(handler=command_schemas)

    item = commands.add_parser("selftest")
    item.set_defaults(handler=command_selftest)

    item = commands.add_parser("observe")
    item.set_defaults(handler=command_observe)

    item = commands.add_parser("generate-kit")
    item.add_argument("destination", type=Path)
    item.set_defaults(handler=command_generate_kit)

    item = commands.add_parser("create-transition")
    item.add_argument("--transition-type", choices=ceremony.TRANSITION_TYPES, required=True)
    item.add_argument("--reason-code", required=True)
    item.add_argument("--sequence", type=int, required=True)
    item.add_argument("--created-unix", type=int, required=True)
    item.add_argument("--expires-unix", type=int, required=True)
    item.add_argument("--challenge-nonce", required=True)
    item.add_argument("--previous-ceremony-state", type=Path)
    item.add_argument("--previous-trust-state", type=Path)
    item.add_argument("--next-trust-state", type=Path)
    item.add_argument("--fixture", action="store_true")
    item.add_argument("--output", type=Path, required=True)
    item.set_defaults(handler=command_create_transition)

    item = commands.add_parser("verify-transition")
    item.add_argument("--transition", type=Path, required=True)
    item.add_argument("--signature", action="append", help="ROLE=PATH")
    item.add_argument("--keyring", action="append", help="ROLE=PATH")
    item.add_argument("--previous-ceremony-state", type=Path)
    item.add_argument("--previous-trust-state", type=Path)
    item.add_argument("--next-trust-state", type=Path)
    item.add_argument("--now", type=int, required=True)
    item.add_argument("--gpgv", type=Path, default=Path("/usr/bin/gpgv"))
    item.add_argument("--verification-output", type=Path)
    item.add_argument("--state-output", type=Path)
    item.add_argument("--store", type=Path)
    item.set_defaults(handler=command_verify_transition)

    item = commands.add_parser("recover-store")
    item.add_argument("--checkpoint", type=Path, required=True)
    item.add_argument("--destination", type=Path, required=True)
    item.add_argument("--minimum-sequence", type=int, required=True)
    item.add_argument("--expected-state-digest", required=True)
    item.set_defaults(handler=command_recover_store)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        value = args.handler(args)
    except (phase40.PolicyError, OSError, ValueError) as exc:
        print(f"securityops-phase41-ceremony: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
