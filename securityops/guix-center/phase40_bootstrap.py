#!/usr/bin/env python3
# CodeMark v1 project=4c63e0fe-589c-4944-8449-97e211a38b72 file=cdc91ad7a6a0571984710ffdb21eed32 owner="Cristian Cezar Mois\u00e9s"
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Owner-controlled Phase 40 trust bootstrap and Gate 1 helper.

The program never creates, imports, or uses a secret signing key.  It verifies
owner-signed public policy objects, measures the exact authenticated input
closure, creates an unsigned Phase 39 Gate 1 job for offline owner signature,
and emits build-node evidence only from descriptor-bound inputs.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import time
from typing import Any, Mapping

SCRIPT_DIR = Path(__file__).resolve().parent
PACKAGE_ROOT = SCRIPT_DIR.parent
if str(PACKAGE_ROOT) not in sys.path:
    sys.path.insert(0, str(PACKAGE_ROOT))
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import phase39_owner_execution as phase39
import phase40_gate1_admission as gate1
import phase40_owner_trust as phase40

PIN_FORMAT = "securityops-phase40-owner-pins/1"
MAX_PIN_BYTES = 64 * 1024


def _canonical_pretty(value: Mapping[str, Any]) -> bytes:
    return json.dumps(
        value, sort_keys=True, indent=2, ensure_ascii=False,
    ).encode("utf-8") + b"\n"


def _write_json(path: Path, value: Mapping[str, Any], *, mode: int = 0o600) -> None:
    phase40._write_atomic(path.absolute(), _canonical_pretty(value), mode)  # noqa: SLF001


def _load_json(path: Path, *, maximum: int, context: str) -> dict[str, Any]:
    _, payload = phase40.measure_file(path, maximum=maximum, context=context)
    return phase40._strict_json(payload, context)  # noqa: SLF001


def _load_pins(path: Path) -> dict[str, Any]:
    value = _load_json(path, maximum=MAX_PIN_BYTES, context="Phase 40 local pin policy")
    fields = {
        "format", "owner_primary_fingerprint", "owner_signing_fingerprint",
        "owner_keyring_sha256", "build_node_primary_fingerprint",
        "build_node_signing_fingerprint", "build_node_keyring_sha256",
        "build_node_id", "production_gate_approved",
        "production_dispatch_allowed", "iso_release_allowed",
    }
    if set(value) != fields or value["format"] != PIN_FORMAT:
        raise phase40.PolicyError("Phase 40 local pin-policy fields are not closed")
    for name in (
        "owner_primary_fingerprint", "owner_signing_fingerprint",
        "build_node_primary_fingerprint", "build_node_signing_fingerprint",
    ):
        phase40._fingerprint(value[name], f"Phase 40 pin {name}")  # noqa: SLF001
    for name in ("owner_keyring_sha256", "build_node_keyring_sha256"):
        phase40._sha256(value[name], f"Phase 40 pin {name}")  # noqa: SLF001
    phase40._token(value["build_node_id"], "Phase 40 pinned build-node ID")  # noqa: SLF001
    if any(value[name] is not False for name in (
        "production_gate_approved", "production_dispatch_allowed",
        "iso_release_allowed",
    )):
        raise phase40.PolicyError("Phase 40 local pin policy promoted a release gate")
    return value


def _verify_bootstrap(args: argparse.Namespace) -> tuple[
    phase40.VerifiedTrustRoot, phase40.VerifiedInputClosure, dict[str, Any]
]:
    pins = _load_pins(args.pin_file)
    now = int(time.time()) if args.now is None else args.now
    verified_trust = phase40.verify_signed_trust_root(
        trust_root_path=args.trust_root,
        signature_path=args.trust_root_signature,
        owner_keyring_path=args.owner_keyring,
        build_node_keyring_path=args.build_node_keyring,
        expected_owner_primary_fingerprint=pins["owner_primary_fingerprint"],
        expected_owner_signing_fingerprint=pins["owner_signing_fingerprint"],
        expected_owner_keyring_sha256=pins["owner_keyring_sha256"],
        expected_build_node_primary_fingerprint=(
            pins["build_node_primary_fingerprint"]),
        expected_build_node_signing_fingerprint=(
            pins["build_node_signing_fingerprint"]),
        expected_build_node_keyring_sha256=(
            pins["build_node_keyring_sha256"]),
        now_unix=now,
        gpg_executable=args.gpg,
        gpgv_executable=args.gpgv,
    )
    if verified_trust.document["build_node"]["node_id"] != pins["build_node_id"]:
        raise phase40.PolicyError("Phase 40 trust root differs from pinned node ID")
    verified_input = phase40.verify_signed_input_closure(
        manifest_path=args.input_manifest,
        signature_path=args.input_signature,
        owner_keyring_path=args.owner_keyring,
        input_root=args.input_root,
        verified_trust_root=verified_trust,
        now_unix=now,
        gpgv_executable=args.gpgv,
    )
    return verified_trust, verified_input, pins


def _load_trust_state_file(path: Path) -> dict[str, Any]:
    """Load one descriptor-measured local trust state without path reopening."""
    _, payload = phase40.measure_file(
        path, maximum=phase40.MAX_TRUST_ROOT_BYTES,
        context="Phase 40 published trust state")
    return phase40.parse_trust_state(
        phase40._strict_json(payload, "Phase 40 published trust state"))  # noqa: SLF001


def _state_matches_verified_root(
    state: Mapping[str, Any], trust: phase40.VerifiedTrustRoot,
) -> bool:
    checked = phase40.parse_trust_state(state)
    return bool(
        checked["generation"] == trust.document["generation"]
        and checked["trust_root_digest"] == trust.trust_root_digest
        and checked["trust_root_verification_digest"] == trust.verification_digest
        and checked["owner_primary_fingerprint"]
            == trust.owner_identity.primary_fingerprint
        and checked["owner_job_signer_fingerprint"]
            == trust.owner_identity.signing_fingerprint
        and checked["owner_keyring_sha256"] == trust.owner_identity.keyring.sha256
        and checked["build_node_primary_fingerprint"]
            == trust.build_node_identity.primary_fingerprint
        and checked["build_node_result_signer_fingerprint"]
            == trust.build_node_identity.signing_fingerprint
        and checked["build_node_keyring_sha256"]
            == trust.build_node_identity.keyring.sha256
        and checked["build_node_id"] == trust.document["build_node"]["node_id"]
        and checked["fixture_mode"] == trust.fixture_mode
        and checked["owner_trust_authenticated"]
            == bool(trust.owner_authenticated and not trust.fixture_mode)
    )


def _derive_or_load_trust_state(
    *, trust: phase40.VerifiedTrustRoot, state_path: Path | None,
) -> tuple[dict[str, Any], bool]:
    """Return the current or next state and whether it must be published."""
    if state_path is None:
        return phase40.create_trust_state(verified_trust_root=trust), False
    destination = state_path.absolute()
    if destination.exists() or destination.is_symlink():
        current = _load_trust_state_file(destination)
        if current["trust_root_digest"] == trust.trust_root_digest:
            if not _state_matches_verified_root(current, trust):
                raise phase40.PolicyError(
                    "Phase 40 published trust state differs from verified trust root")
            return current, False
        return (
            phase40.create_trust_state(
                verified_trust_root=trust, previous_state=current),
            True,
        )
    return phase40.create_trust_state(verified_trust_root=trust), True


def _require_published_trust_state(
    path: Path, trust: phase40.VerifiedTrustRoot,
) -> dict[str, Any]:
    state = _load_trust_state_file(path.absolute())
    if not _state_matches_verified_root(state, trust):
        raise phase40.PolicyError(
            "Phase 40 published trust state does not bind the admitted trust root")
    return state


def _common_bootstrap_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--pin-file", type=Path,
        default=Path(phase40.NODE_PIN_FILE))
    parser.add_argument(
        "--trust-root", type=Path,
        default=Path(phase40.NODE_INPUT_ROOT) / "trust-root.json")
    parser.add_argument(
        "--trust-root-signature", type=Path,
        default=Path(phase40.NODE_INPUT_ROOT) / "trust-root.json.sig")
    parser.add_argument(
        "--owner-keyring", type=Path,
        default=Path(phase40.NODE_INPUT_ROOT) / "owner-job-keyring.gpg")
    parser.add_argument(
        "--build-node-keyring", type=Path,
        default=Path(phase40.NODE_INPUT_ROOT) / "build-node-result-keyring.gpg")
    parser.add_argument(
        "--input-manifest", type=Path,
        default=Path(phase40.NODE_INPUT_ROOT) / "input-closure.json")
    parser.add_argument(
        "--input-signature", type=Path,
        default=Path(phase40.NODE_INPUT_ROOT) / "input-closure.json.sig")
    parser.add_argument(
        "--input-root", type=Path,
        default=Path(phase40.NODE_INPUT_ROOT) / "artifacts")
    parser.add_argument("--now", type=int)
    parser.add_argument("--gpg", type=Path, default=Path("/usr/bin/gpg"))
    parser.add_argument("--gpgv", type=Path, default=Path("/usr/bin/gpgv"))


def command_contract(args: argparse.Namespace) -> dict[str, Any]:
    if args.kind == "owner":
        return phase40.phase40_contract()
    if args.kind == "gate1":
        return gate1.gate1_contract()
    return {
        "format": "securityops-phase40-contract-closure/1",
        "owner_trust": phase40.phase40_contract(),
        "gate1": gate1.gate1_contract(),
        "production_gates_approved": 0,
        "production_dispatch_allowed": False,
        "iso_release_allowed": False,
    }


def command_selftest(_args: argparse.Namespace) -> dict[str, Any]:
    return {
        "format": "securityops-phase40-bootstrap-selftest/1",
        "owner_trust": phase40.phase40_selftest(),
        "gate1": gate1.gate1_selftest(),
        "production_gates_approved": 0,
        "production_dispatch_allowed": False,
        "iso_release_allowed": False,
    }


def command_observe(_args: argparse.Namespace) -> dict[str, Any]:
    return {
        "format": "securityops-phase40-local-observation/1",
        "owner_trust": phase40.phase40_environment_observation(),
        "gate1": gate1.blocked_gate1_observation(),
        "production_gates_approved": 0,
        "production_dispatch_allowed": False,
        "iso_release_allowed": False,
        "iso_bytes_present": False,
        "release_decision": "NOT RELEASE READY — BLOCKERS LISTED",
    }


def command_generate_kit(args: argparse.Namespace) -> dict[str, Any]:
    return phase40.generate_bootstrap_kit(args.destination)


def command_inspect_keyring(args: argparse.Namespace) -> dict[str, Any]:
    identity = phase40.inspect_verification_keyring(
        args.keyring,
        expected_primary_fingerprint=args.primary_fingerprint,
        expected_signing_fingerprint=args.signing_fingerprint,
        valid_through_unix=args.valid_through,
        gpg_executable=args.gpg,
        fixture_mode=args.fixture,
    )
    return {
        "format": "securityops-phase40-keyring-inspection/1",
        "identity": identity.to_dict(),
        "fixture_mode": args.fixture,
        "production_gate_approved": False,
        "production_dispatch_allowed": False,
        "iso_release_allowed": False,
    }


def command_verify_bootstrap(args: argparse.Namespace) -> dict[str, Any]:
    trust, inputs, _ = _verify_bootstrap(args)
    state, needs_publication = _derive_or_load_trust_state(
        trust=trust, state_path=args.state_output)
    if args.state_output is not None and needs_publication:
        phase40.publish_trust_state(args.state_output, state)
    return {
        "format": "securityops-phase40-bootstrap-verification/1",
        "trust_root": trust.to_dict(),
        "trust_state": state,
        "input_closure": inputs.to_dict(),
        "ready_for_gate1_job": bool(
            trust.owner_authenticated and inputs.ready_for_gate1_job),
        "production_gate_approved": False,
        "production_dispatch_allowed": False,
        "iso_release_allowed": False,
    }


def command_create_gate1_job(args: argparse.Namespace) -> dict[str, Any]:
    trust, inputs, pins = _verify_bootstrap(args)
    state = _require_published_trust_state(args.trust_state, trust)
    if args.build_node_id != pins["build_node_id"]:
        raise phase40.PolicyError("Phase 40 requested node differs from local pin policy")
    request = phase40.create_gate1_signing_request(
        trust_root=trust,
        trust_state=state,
        input_closure=inputs,
        job_id=args.job_id,
        created_unix=args.created_unix,
        expires_unix=args.expires_unix,
        challenge_nonce=args.challenge_nonce,
        build_node_id=args.build_node_id,
        bootstrap_executable=args.bootstrap_executable,
        trust_state_path=os.fspath(args.trust_state.absolute()),
        guix_executable=args.guix,
        guile_executable=args.guile,
        guild_executable=args.guild,
        python_executable=args.python,
    )
    root = args.output_directory.absolute()
    if root.exists() or root.is_symlink():
        raise phase40.PolicyError("Phase 40 job output directory already exists")
    root.mkdir(parents=True, mode=0o700)
    root.chmod(0o700)
    _write_json(root / "gate1-signing-request.json", request, mode=0o400)
    _write_json(root / "job.json", request["job"], mode=0o400)
    return {
        "format": "securityops-phase40-gate1-job-publication/1",
        "request_digest": request["request_digest"],
        "job_digest": request["job"]["job_digest"],
        "output_directory": os.fspath(root),
        "owner_signature_present": False,
        "build_node_result_signature_present": False,
        "production_gate_approved": False,
        "production_dispatch_allowed": False,
        "iso_release_allowed": False,
    }


def command_verify_node_input(args: argparse.Namespace) -> dict[str, Any]:
    trust, inputs, pins = _verify_bootstrap(args)
    state = _require_published_trust_state(args.trust_state, trust)
    job_document = _load_json(
        args.job, maximum=phase39.MAX_JOB_BYTES,
        context="Phase 40 owner-signed Gate 1 job")
    job = phase39.parse_gate_job(job_document, now_unix=args.now)
    if (
        job.gate_name != gate1.FIRST_GATE
        or job.owner_fingerprint != trust.owner_identity.signing_fingerprint
        or job.result_fingerprint != trust.build_node_identity.signing_fingerprint
        or job.document["build_node_id"] != pins["build_node_id"]
    ):
        raise phase40.PolicyError("Phase 40 Gate 1 job differs from admitted trust")
    if args.expected_trust_state_digest != state["state_digest"]:
        raise phase40.PolicyError("Phase 40 expected trust-state digest differs")
    if args.expected_trust_root_digest != trust.trust_root_digest:
        raise phase40.PolicyError("Phase 40 expected trust-root digest differs")
    if (args.expected_trust_root_verification_digest
            != trust.verification_digest):
        raise phase40.PolicyError(
            "Phase 40 expected trust-root verification digest differs")
    if args.expected_input_closure_digest != inputs.input_closure_digest:
        raise phase40.PolicyError("Phase 40 expected input-closure digest differs")
    if (args.expected_input_closure_verification_digest
            != inputs.verification_digest):
        raise phase40.PolicyError(
            "Phase 40 expected input-closure verification digest differs")
    evidence = gate1.create_owner_input_evidence(
        trust_root_digest=trust.trust_root_digest,
        input_closure_digest=inputs.input_closure_digest,
        input_verification_digest=inputs.verification_digest,
        artifact_set_digest=hashlib.sha256(
            b"SECURITYOPS-PHASE40-ARTIFACT-SET-V1\x00"
            + phase40.canonical_json_bytes(
                [item.to_dict() for item in inputs.artifacts])
        ).hexdigest(),
        artifact_count=len(inputs.artifacts),
        exact_rust_archive_bound=inputs.exact_rust_archive_bound,
        publisher_admission_receipts_verified=(
            inputs.publisher_admission_receipts_verified),
        owner_inventory_authenticated=inputs.owner_inventory_authenticated,
        job_digest=job.job_digest,
        challenge_nonce=job.document["challenge_nonce"],
        fixture_mode=bool(trust.fixture_mode or inputs.fixture_mode or job.fixture_mode),
    )
    _write_json(args.output, evidence)
    return evidence


def command_attest_guix_qt(args: argparse.Namespace) -> dict[str, Any]:
    value = phase40.attest_guix_qt_environment(
        guix_executable=args.guix,
        guile_executable=args.guile,
        guild_executable=args.guild,
        python_executable=args.python,
    )
    _write_json(args.output, value)
    return value


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)

    item = commands.add_parser("contract")
    item.add_argument("--kind", choices=("owner", "gate1", "all"), default="all")
    item.set_defaults(handler=command_contract)

    item = commands.add_parser("selftest")
    item.set_defaults(handler=command_selftest)

    item = commands.add_parser("observe")
    item.set_defaults(handler=command_observe)

    item = commands.add_parser("blocked")
    item.set_defaults(
        handler=lambda _args: phase40.phase40_environment_observation())

    item = commands.add_parser("schemas")
    item.set_defaults(handler=lambda _args: {
        "format": "securityops-phase40-schema-closure/1",
        "trust_root": phase40.trust_root_schema(),
        "trust_state": phase40.trust_state_schema(),
        "input_closure": phase40.input_closure_schema(),
        "production_gates_approved": 0,
        "production_dispatch_allowed": False,
        "iso_release_allowed": False,
    })

    item = commands.add_parser("gate1-contract")
    item.set_defaults(handler=lambda _args: gate1.gate1_contract())

    item = commands.add_parser("gate1-blocked")
    item.set_defaults(handler=lambda _args: gate1.blocked_gate1_observation())

    item = commands.add_parser("generate-kit")
    item.add_argument("destination", type=Path)
    item.set_defaults(handler=command_generate_kit)

    item = commands.add_parser("inspect-keyring")
    item.add_argument("--keyring", type=Path, required=True)
    item.add_argument("--primary-fingerprint", required=True)
    item.add_argument("--signing-fingerprint", required=True)
    item.add_argument("--valid-through", type=int, required=True)
    item.add_argument("--gpg", type=Path, default=Path("/usr/bin/gpg"))
    item.add_argument("--fixture", action="store_true")
    item.set_defaults(handler=command_inspect_keyring)

    item = commands.add_parser("verify-bootstrap")
    _common_bootstrap_arguments(item)
    item.add_argument("--state-output", type=Path)
    item.set_defaults(handler=command_verify_bootstrap)

    item = commands.add_parser("create-gate1-job")
    _common_bootstrap_arguments(item)
    item.add_argument("--trust-state", type=Path, required=True)
    item.add_argument("--job-id", type=int, required=True)
    item.add_argument("--created-unix", type=int, required=True)
    item.add_argument("--expires-unix", type=int, required=True)
    item.add_argument("--challenge-nonce", required=True)
    item.add_argument("--build-node-id", required=True)
    item.add_argument("--bootstrap-executable", required=True)
    item.add_argument("--guix", required=True)
    item.add_argument("--guile", required=True)
    item.add_argument("--guild", required=True)
    item.add_argument("--python", required=True)
    item.add_argument("--output-directory", type=Path, required=True)
    item.set_defaults(handler=command_create_gate1_job)

    item = commands.add_parser("verify-node-input")
    _common_bootstrap_arguments(item)
    item.add_argument("--trust-state", type=Path, required=True)
    item.add_argument("--job", type=Path, default=Path(phase40.NODE_INPUT_ROOT) / "job.json")
    item.add_argument("--expected-trust-state-digest", required=True)
    item.add_argument("--expected-trust-root-digest", required=True)
    item.add_argument("--expected-trust-root-verification-digest", required=True)
    item.add_argument("--expected-input-closure-digest", required=True)
    item.add_argument("--expected-input-closure-verification-digest", required=True)
    item.add_argument("--output", type=Path, required=True)
    item.set_defaults(handler=command_verify_node_input)

    item = commands.add_parser("attest-guix-qt")
    item.add_argument("--guix", required=True)
    item.add_argument("--guile", required=True)
    item.add_argument("--guild", required=True)
    item.add_argument("--python", required=True)
    item.add_argument("--output", type=Path, required=True)
    item.set_defaults(handler=command_attest_guix_qt)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        value = args.handler(args)
    except (phase40.PolicyError, OSError, ValueError) as exc:
        print(f"securityops-phase40-bootstrap: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
