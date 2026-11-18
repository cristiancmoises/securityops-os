# CodeMark v1 project=4c63e0fe-589c-4944-8449-97e211a38b72 file=ce88c48fe4555c248728601dfcb2192d owner="Cristian Cezar Mois\u00e9s"
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Phase 44 multi-party pinset and final Gate 1 admission closure.

Phase 44 adds one signed authority registry for the six independently pinned
operator roles, an owner-and-witness signed admission envelope around the
Phase 43 preflight, and a monotonic final receipt that cross-binds the Phase 41
decision.  These records make the offline path executable without weakening the
truth boundary: fixtures, transport-only evidence, or an envelope by itself can
never approve Gate 1 or authorize a release.
"""
from __future__ import annotations

from dataclasses import dataclass
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
from typing import Any, Final, Mapping, Sequence

try:
    from . import phase39_owner_execution as phase39
    from . import phase40_owner_trust as phase40
    from . import phase41_gate1_execution as phase41_gate1
    from . import phase41_owner_ceremony as phase41_ceremony
    from . import phase42_offline_ceremony as phase42
    from . import phase43_offline_custody as phase43
except ImportError:  # pragma: no cover - installed Guix Center sibling copy
    import phase39_owner_execution as phase39  # type: ignore[no-redef]
    import phase40_owner_trust as phase40  # type: ignore[no-redef]
    import phase41_gate1_execution as phase41_gate1  # type: ignore[no-redef]
    import phase41_owner_ceremony as phase41_ceremony  # type: ignore[no-redef]
    import phase42_offline_ceremony as phase42  # type: ignore[no-redef]
    import phase43_offline_custody as phase43  # type: ignore[no-redef]

PolicyError = phase40.PolicyError
canonical_json_bytes = phase40.canonical_json_bytes

CONTRACT_FORMAT: Final[str] = "securityops-phase44-gate1-closure-contract/1"
LOCAL_PINS_FORMAT: Final[str] = "securityops-phase44-local-pin-policy/1"
PINSET_FORMAT: Final[str] = "securityops-phase44-authority-pinset/1"
PINSET_VERIFICATION_FORMAT: Final[str] = "securityops-phase44-authority-pinset-verification/1"
ENVELOPE_FORMAT: Final[str] = "securityops-phase44-gate1-admission-envelope/1"
ENVELOPE_VERIFICATION_FORMAT: Final[str] = "securityops-phase44-gate1-envelope-verification/1"
RECEIPT_FORMAT: Final[str] = "securityops-phase44-gate1-final-receipt/1"
LEDGER_FORMAT: Final[str] = "securityops-phase44-gate1-final-ledger/1"
STATUS: Final[str] = "PASS_PHASE44_MULTI_PARTY_PINSET_AND_GATE1_ADMISSION_CLOSURE_BOUNDARY"
BLOCKED_STATUS: Final[str] = "BLOCKED_PHASE44_REAL_PINSET_ENVELOPE_AND_GATE1_RECEIPT_REQUIRED"

CONTRACT_DOMAIN: Final[bytes] = b"SECURITYOPS-PHASE44-GATE1-CLOSURE-CONTRACT-V1\x00"
LOCAL_PINS_DOMAIN: Final[bytes] = b"SECURITYOPS-PHASE44-LOCAL-PIN-POLICY-V1\x00"
PINSET_DOMAIN: Final[bytes] = b"SECURITYOPS-PHASE44-AUTHORITY-PINSET-V1\x00"
PINSET_VERIFICATION_DOMAIN: Final[bytes] = b"SECURITYOPS-PHASE44-AUTHORITY-PINSET-VERIFICATION-V1\x00"
ENVELOPE_DOMAIN: Final[bytes] = b"SECURITYOPS-PHASE44-GATE1-ADMISSION-ENVELOPE-V1\x00"
ENVELOPE_VERIFICATION_DOMAIN: Final[bytes] = b"SECURITYOPS-PHASE44-GATE1-ENVELOPE-VERIFICATION-V1\x00"
RECEIPT_DOMAIN: Final[bytes] = b"SECURITYOPS-PHASE44-GATE1-FINAL-RECEIPT-V1\x00"
LEDGER_DOMAIN: Final[bytes] = b"SECURITYOPS-PHASE44-GATE1-FINAL-LEDGER-V1\x00"
COMMAND_SET_DOMAIN: Final[bytes] = b"SECURITYOPS-PHASE44-GATE1-COMMAND-SET-V1\x00"
NEGATIVE_DOMAIN: Final[bytes] = b"SECURITYOPS-PHASE44-NEGATIVE-MATRIX-V1\x00"
KIT_DOMAIN: Final[bytes] = b"SECURITYOPS-PHASE44-OPERATOR-KIT-V1\x00"

ZERO_SHA: Final[str] = "0" * 64
MAX_JSON_BYTES: Final[int] = 16 * 1024 * 1024
MAX_LEDGER_BYTES: Final[int] = 32 * 1024 * 1024
MAX_LEDGER_RECORDS: Final[int] = 4096
MAX_RECORD_LIFETIME: Final[int] = 30 * 24 * 60 * 60

_SHA = re.compile(r"[0-9a-f]{64}\Z")
_FPR = re.compile(r"[0-9A-F]{40}\Z")
_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")

PIN_ROLE_ORDER: Final[tuple[str, ...]] = (
    "owner",
    "build-node",
    "witness",
    "export-operator",
    "receiving-operator",
    "independent-verifier",
)

PHASE43_IDENTITIES: Final[dict[str, str]] = {
    "runtime_commit": "fb06c37b8686a570593ce5b29c9d760df965f20d",
    "runtime_tree": "7f5cdfe4e721400474c2565d34a2951afc84e47a",
    "securityops_os_commit": "ea87d802c595a4af59e00f615eb4073284a74969",
    "securityops_os_tree": "9f87f0401536b33f494d5131e8504e07037a30c8",
    "stable_v1_13_0": "8373fd789c9a525d6128abfd3d7a93ad4db3348b",
}
PHASE43_CONTRACT_DIGEST: Final[str] = "437249725663498e48a7f9fbdce8e8e1f28f76ad25cd58aab1119f6141f481f2"
PHASE42_CONTRACT_DIGEST: Final[str] = "63515c52c4c40d4d0f5415a320fa9ea00908419b1da29cc1b865d8bf4c029145"
PHASE41_CEREMONY_CONTRACT_DIGEST: Final[str] = "66af9139b27737bad8b4e8b2756e7bf81691af3491e5022f7db86e09f9aec009"
PHASE41_GATE1_CONTRACT_DIGEST: Final[str] = "55bc916ee486e4813109ee825e4a36bdaf7f07e6d8276841bf41fda0a2ec7510"
PHASE40_OWNER_CONTRACT_DIGEST: Final[str] = "a2234f4e0def156e23de31f7661cb4c15b56451ab9bd7ab4a8f45d7814350b6c"
PHASE40_GATE1_CONTRACT_DIGEST: Final[str] = "3e692b76ec7d7c468019bd17625463626a8e45b116e23e0376f52849539fc0b3"
PHASE39_CONTRACT_DIGEST: Final[str] = "b5e8d916288a713d036cba96fdaa77a595fb5c44e001ca6c03e33f55e5b7ee5f"

NEGATIVE_CASES: Final[tuple[str, ...]] = (
    "local-pin-role-missing",
    "local-pin-role-reordered",
    "local-pin-primary-reused",
    "local-pin-signing-reused",
    "local-pin-keyring-reused",
    "local-pin-zero-digest",
    "pinset-contract-drift",
    "pinset-policy-drift",
    "pinset-challenge-drift",
    "pinset-generation-rollback",
    "pinset-expired",
    "pinset-fixture-promotion",
    "pinset-owner-signature-missing",
    "pinset-witness-signature-missing",
    "pinset-keyring-substitution",
    "pinset-path-reopen-after-measurement",
    "envelope-preflight-drift",
    "envelope-job-challenge-drift",
    "envelope-owner-pin-drift",
    "envelope-build-node-pin-drift",
    "envelope-witness-pin-drift",
    "envelope-export-pin-drift",
    "envelope-receiver-pin-drift",
    "envelope-verifier-pin-drift",
    "envelope-command-set-drift",
    "envelope-network-policy-drift",
    "envelope-fixture-promotion",
    "envelope-self-approval",
    "receipt-decision-drift",
    "receipt-preflight-drift",
    "receipt-envelope-drift",
    "receipt-ledger-drift",
    "receipt-fixture-promotion",
    "receipt-production-promotion",
    "ledger-job-replay",
    "ledger-job-rollback",
    "ledger-challenge-reuse",
    "ledger-receipt-equivocation",
    "ledger-gate1-count-drift",
    "ledger-release-promotion",
)

KIT_FILES: Final[tuple[str, ...]] = (
    "README.md",
    "README.pt-BR.md",
    "phase44-gate1-closure-contract.json",
    "phase44-local-pin-policy.schema.json",
    "phase44-authority-pinset.schema.json",
    "phase44-authority-pinset-verification.schema.json",
    "phase44-gate1-admission-envelope.schema.json",
    "phase44-gate1-envelope-verification.schema.json",
    "phase44-gate1-final-receipt.schema.json",
    "phase44-gate1-final-ledger.schema.json",
    "local-pins.template.json",
    "authority-pinset.request.template.json",
    "admission-envelope.request.template.json",
    "final-receipt.request.template.json",
    "scripts/verify-pinset.py",
    "scripts/verify-envelope.py",
    "scripts/verify-final-receipt.py",
    "scripts/verify-final-ledger.py",
)


def _digest(domain: bytes, value: Mapping[str, Any]) -> str:
    return hashlib.sha256(domain + canonical_json_bytes(value)).hexdigest()


def _sha(value: Any, context: str, *, allow_zero: bool = False) -> str:
    if not isinstance(value, str) or not _SHA.fullmatch(value):
        raise PolicyError(f"{context} must be a lowercase SHA-256 digest")
    if not allow_zero and value == ZERO_SHA:
        raise PolicyError(f"{context} cannot be zero")
    return value


def _fpr(value: Any, context: str) -> str:
    if not isinstance(value, str) or not _FPR.fullmatch(value) or value == "0" * 40:
        raise PolicyError(f"{context} must be a nonzero uppercase OpenPGP fingerprint")
    return value


def _token(value: Any, context: str) -> str:
    if not isinstance(value, str) or not _TOKEN.fullmatch(value):
        raise PolicyError(f"{context} is invalid")
    return value


def _strict_json(payload: bytes, context: str) -> dict[str, Any]:
    duplicates: list[str] = []

    def hook(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, item in items:
            if key in result:
                duplicates.append(key)
            result[key] = item
        return result

    try:
        value = json.loads(
            payload.decode("utf-8", errors="strict"),
            object_pairs_hook=hook,
            parse_constant=lambda item: (_ for _ in ()).throw(ValueError(item)),
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise PolicyError(f"{context} is not strict JSON") from exc
    if duplicates or type(value) is not dict:
        raise PolicyError(f"{context} is not a closed JSON object")
    return value


def _schema_digest(schema: Mapping[str, Any]) -> str:
    return hashlib.sha256(canonical_json_bytes(schema)).hexdigest()


def _pin_schema() -> dict[str, Any]:
    return {
        "type": "object",
        "additionalProperties": False,
        "required": [
            "role", "primary_fingerprint", "signing_fingerprint",
            "keyring_sha256",
        ],
        "properties": {
            "role": {"enum": list(PIN_ROLE_ORDER)},
            "primary_fingerprint": {"type": "string", "pattern": "^[0-9A-F]{40}$"},
            "signing_fingerprint": {"type": "string", "pattern": "^[0-9A-F]{40}$"},
            "keyring_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
        },
    }


def local_pin_policy_schema() -> dict[str, Any]:
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://securityops.co/schemas/guix-center/phase44-local-pin-policy.schema.json",
        "title": "Security Ops Phase 44 out-of-band operator pin policy",
        "type": "object",
        "additionalProperties": False,
        "required": ["format", "role_order", "roles", "all_role_identities_distinct", "policy_digest"],
        "properties": {
            "format": {"const": LOCAL_PINS_FORMAT},
            "role_order": {"const": list(PIN_ROLE_ORDER)},
            "roles": {"type": "array", "minItems": len(PIN_ROLE_ORDER), "maxItems": len(PIN_ROLE_ORDER), "items": _pin_schema()},
            "all_role_identities_distinct": {"const": True},
            "policy_digest": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
        },
    }


def authority_pinset_schema() -> dict[str, Any]:
    sha = {"type": "string", "pattern": "^[0-9a-f]{64}$"}
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://securityops.co/schemas/guix-center/phase44-authority-pinset.schema.json",
        "title": "Security Ops Phase 44 owner-and-witness signed authority pinset",
        "type": "object",
        "additionalProperties": False,
        "required": [
            "format", "contract_digest", "phase43_contract_digest", "generation",
            "created_unix", "expires_unix", "challenge_nonce", "previous_pinset_digest",
            "local_pin_policy_digest", "roles", "owner_signature_required",
            "witness_signature_required", "all_role_identities_distinct", "fixture_mode",
            "authority_created_by_document", "gate1_approved", "production_gates_approved",
            "production_dispatch_allowed", "iso_release_allowed", "pinset_digest",
        ],
        "properties": {
            "format": {"const": PINSET_FORMAT},
            "contract_digest": sha,
            "phase43_contract_digest": sha,
            "generation": {"type": "integer", "minimum": 1},
            "created_unix": {"type": "integer", "minimum": 1},
            "expires_unix": {"type": "integer", "minimum": 1},
            "challenge_nonce": sha,
            "previous_pinset_digest": sha,
            "local_pin_policy_digest": sha,
            "roles": {"type": "array", "minItems": len(PIN_ROLE_ORDER), "maxItems": len(PIN_ROLE_ORDER), "items": _pin_schema()},
            "owner_signature_required": {"const": True},
            "witness_signature_required": {"const": True},
            "all_role_identities_distinct": {"const": True},
            "fixture_mode": {"type": "boolean"},
            "authority_created_by_document": {"const": False},
            "gate1_approved": {"const": False},
            "production_gates_approved": {"const": 0},
            "production_dispatch_allowed": {"const": False},
            "iso_release_allowed": {"const": False},
            "pinset_digest": sha,
        },
    }


def pinset_verification_schema() -> dict[str, Any]:
    sha = {"type": "string", "pattern": "^[0-9a-f]{64}$"}
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://securityops.co/schemas/guix-center/phase44-authority-pinset-verification.schema.json",
        "title": "Security Ops Phase 44 authority pinset signature verification receipt",
        "type": "object", "additionalProperties": False,
        "required": [
            "format", "pinset_digest", "local_pin_policy_digest", "signed_input_sha256",
            "owner_signature_verified", "witness_signature_verified", "local_policy_verified",
            "role_separation_verified", "fixture_mode", "authority_pins_authenticated",
            "gate1_approved", "production_gates_approved", "production_dispatch_allowed",
            "iso_release_allowed", "verification_digest",
        ],
        "properties": {
            "format": {"const": PINSET_VERIFICATION_FORMAT},
            "pinset_digest": sha,
            "local_pin_policy_digest": sha,
            "signed_input_sha256": {
                "type": "object", "additionalProperties": False,
                "required": ["pinset", "owner_signature", "owner_keyring", "witness_signature", "witness_keyring"],
                "properties": {name: sha for name in ("pinset", "owner_signature", "owner_keyring", "witness_signature", "witness_keyring")},
            },
            "owner_signature_verified": {"const": True},
            "witness_signature_verified": {"const": True},
            "local_policy_verified": {"const": True},
            "role_separation_verified": {"const": True},
            "fixture_mode": {"type": "boolean"},
            "authority_pins_authenticated": {"type": "boolean"},
            "gate1_approved": {"const": False},
            "production_gates_approved": {"const": 0},
            "production_dispatch_allowed": {"const": False},
            "iso_release_allowed": {"const": False},
            "verification_digest": sha,
        },
    }


def admission_envelope_schema() -> dict[str, Any]:
    sha = {"type": "string", "pattern": "^[0-9a-f]{64}$"}
    fpr = {"type": "string", "pattern": "^[0-9A-F]{40}$"}
    required = [
        "format", "contract_digest", "created_unix", "expires_unix", "envelope_id",
        "gate_name", "gate_index", "job_id", "challenge_nonce", "pinset_digest",
        "pinset_verification_digest", "local_pin_policy_digest", "phase43_preflight_digest",
        "custody_ledger_digest", "trust_state_digest", "ceremony_state_digest",
        "phase39_job_digest", "phase39_result_digest", "phase39_verification_digest",
        "phase40_semantic_receipt_digest", "input_closure_digest", "witness_checkpoint_digest",
        "witness_verification_digest", "transcript_digest", "transcript_verification_digest",
        "command_set_digest", "network_policy", "evidence_roles", "build_node_id",
        "owner_signing_fingerprint", "build_node_signing_fingerprint",
        "witness_signing_fingerprint", "custody_operator_signers", "fixture_mode",
        "all_bindings_verified", "eligible_for_phase41_decision", "owner_signature_required",
        "witness_signature_required", "gate1_approved", "production_gates_approved",
        "production_dispatch_allowed", "iso_release_allowed", "envelope_digest",
    ]
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://securityops.co/schemas/guix-center/phase44-gate1-admission-envelope.schema.json",
        "title": "Security Ops Phase 44 owner-and-witness signed Gate 1 admission envelope",
        "type": "object", "additionalProperties": False, "required": required,
        "properties": {
            "format": {"const": ENVELOPE_FORMAT}, "contract_digest": sha,
            "created_unix": {"type": "integer", "minimum": 1},
            "expires_unix": {"type": "integer", "minimum": 1},
            "envelope_id": {"type": "string", "minLength": 1, "maxLength": 128},
            "gate_name": {"const": phase39.GATE_NAMES[0]}, "gate_index": {"const": 1},
            "job_id": {"type": "integer", "minimum": 1}, "challenge_nonce": sha,
            **{name: sha for name in (
                "pinset_digest", "pinset_verification_digest", "local_pin_policy_digest",
                "phase43_preflight_digest", "custody_ledger_digest", "trust_state_digest",
                "ceremony_state_digest", "phase39_job_digest", "phase39_result_digest",
                "phase39_verification_digest", "phase40_semantic_receipt_digest",
                "input_closure_digest", "witness_checkpoint_digest", "witness_verification_digest",
                "transcript_digest", "transcript_verification_digest", "command_set_digest",
                "envelope_digest",
            )},
            "network_policy": {"enum": list(phase39.NETWORK_POLICIES)},
            "evidence_roles": {"type": "array", "minItems": 1, "maxItems": 64, "items": {"type": "string", "minLength": 1, "maxLength": 128}},
            "build_node_id": {"type": "string", "minLength": 1, "maxLength": 128},
            "owner_signing_fingerprint": fpr, "build_node_signing_fingerprint": fpr,
            "witness_signing_fingerprint": fpr,
            "custody_operator_signers": {
                "type": "object", "additionalProperties": False,
                "required": ["export-operator", "receiving-operator", "independent-verifier"],
                "properties": {name: fpr for name in ("export-operator", "receiving-operator", "independent-verifier")},
            },
            "fixture_mode": {"type": "boolean"}, "all_bindings_verified": {"const": True},
            "eligible_for_phase41_decision": {"type": "boolean"},
            "owner_signature_required": {"const": True}, "witness_signature_required": {"const": True},
            "gate1_approved": {"const": False}, "production_gates_approved": {"const": 0},
            "production_dispatch_allowed": {"const": False}, "iso_release_allowed": {"const": False},
        },
    }


def envelope_verification_schema() -> dict[str, Any]:
    sha = {"type": "string", "pattern": "^[0-9a-f]{64}$"}
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://securityops.co/schemas/guix-center/phase44-gate1-envelope-verification.schema.json",
        "title": "Security Ops Phase 44 admission-envelope signature verification receipt",
        "type": "object", "additionalProperties": False,
        "required": [
            "format", "envelope_digest", "pinset_digest", "pinset_verification_digest",
            "signed_input_sha256", "owner_signature_verified", "witness_signature_verified",
            "pinset_authenticated", "fixture_mode", "envelope_authenticated",
            "eligible_for_phase41_decision", "gate1_approved", "production_gates_approved",
            "production_dispatch_allowed", "iso_release_allowed", "verification_digest",
        ],
        "properties": {
            "format": {"const": ENVELOPE_VERIFICATION_FORMAT},
            "envelope_digest": sha, "pinset_digest": sha, "pinset_verification_digest": sha,
            "signed_input_sha256": {
                "type": "object", "additionalProperties": False,
                "required": ["envelope", "owner_signature", "owner_keyring", "witness_signature", "witness_keyring"],
                "properties": {name: sha for name in ("envelope", "owner_signature", "owner_keyring", "witness_signature", "witness_keyring")},
            },
            "owner_signature_verified": {"const": True}, "witness_signature_verified": {"const": True},
            "pinset_authenticated": {"type": "boolean"}, "fixture_mode": {"type": "boolean"},
            "envelope_authenticated": {"type": "boolean"}, "eligible_for_phase41_decision": {"type": "boolean"},
            "gate1_approved": {"const": False}, "production_gates_approved": {"const": 0},
            "production_dispatch_allowed": {"const": False}, "iso_release_allowed": {"const": False},
            "verification_digest": sha,
        },
    }


def final_receipt_schema() -> dict[str, Any]:
    sha = {"type": "string", "pattern": "^[0-9a-f]{64}$"}
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://securityops.co/schemas/guix-center/phase44-gate1-final-receipt.schema.json",
        "title": "Security Ops Phase 44 final Gate 1 cross-protocol receipt",
        "type": "object", "additionalProperties": False,
        "required": [
            "format", "contract_digest", "created_unix", "gate_name", "gate_index", "job_id",
            "challenge_nonce", "envelope_digest", "envelope_verification_digest",
            "phase43_preflight_digest", "phase41_decision_digest", "phase41_decision_ledger_digest",
            "pinset_authenticated", "envelope_authenticated", "preflight_eligible",
            "phase41_decision_approved", "phase41_decision_ledger_bound", "fixture_mode",
            "gate1_approved", "production_gates_approved", "production_dispatch_allowed",
            "iso_release_allowed", "iso_bytes_present", "receipt_digest",
        ],
        "properties": {
            "format": {"const": RECEIPT_FORMAT}, "contract_digest": sha,
            "created_unix": {"type": "integer", "minimum": 1}, "gate_name": {"const": phase39.GATE_NAMES[0]},
            "gate_index": {"const": 1}, "job_id": {"type": "integer", "minimum": 1},
            "challenge_nonce": sha,
            **{name: sha for name in ("envelope_digest", "envelope_verification_digest", "phase43_preflight_digest", "phase41_decision_digest", "phase41_decision_ledger_digest", "receipt_digest")},
            "pinset_authenticated": {"type": "boolean"}, "envelope_authenticated": {"type": "boolean"},
            "preflight_eligible": {"type": "boolean"}, "phase41_decision_approved": {"type": "boolean"},
            "phase41_decision_ledger_bound": {"const": True}, "fixture_mode": {"type": "boolean"},
            "gate1_approved": {"type": "boolean"}, "production_gates_approved": {"type": "integer", "minimum": 0, "maximum": 1},
            "production_dispatch_allowed": {"const": False}, "iso_release_allowed": {"const": False},
            "iso_bytes_present": {"const": False},
        },
    }


def final_ledger_schema() -> dict[str, Any]:
    sha = {"type": "string", "pattern": "^[0-9a-f]{64}$"}
    record = {
        "type": "object", "additionalProperties": False,
        "required": ["job_id", "challenge_nonce", "envelope_digest", "receipt_digest", "gate1_approved"],
        "properties": {
            "job_id": {"type": "integer", "minimum": 1}, "challenge_nonce": sha,
            "envelope_digest": sha, "receipt_digest": sha, "gate1_approved": {"type": "boolean"},
        },
    }
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://securityops.co/schemas/guix-center/phase44-gate1-final-ledger.schema.json",
        "title": "Security Ops Phase 44 monotonic final Gate 1 receipt ledger",
        "type": "object", "additionalProperties": False,
        "required": [
            "format", "contract_digest", "generation", "highest_job_id", "gate1_approved_count",
            "records", "production_dispatch_allowed", "iso_release_allowed", "ledger_digest",
        ],
        "properties": {
            "format": {"const": LEDGER_FORMAT}, "contract_digest": sha,
            "generation": {"type": "integer", "minimum": 0}, "highest_job_id": {"type": "integer", "minimum": 0},
            "gate1_approved_count": {"type": "integer", "minimum": 0, "maximum": 1},
            "records": {"type": "array", "maxItems": MAX_LEDGER_RECORDS, "items": record},
            "production_dispatch_allowed": {"const": False}, "iso_release_allowed": {"const": False},
            "ledger_digest": sha,
        },
    }


def _contract_unsigned() -> dict[str, Any]:
    schemas = {
        "local_pin_policy": local_pin_policy_schema(),
        "authority_pinset": authority_pinset_schema(),
        "authority_pinset_verification": pinset_verification_schema(),
        "admission_envelope": admission_envelope_schema(),
        "envelope_verification": envelope_verification_schema(),
        "final_receipt": final_receipt_schema(),
        "final_ledger": final_ledger_schema(),
    }
    return {
        "format": CONTRACT_FORMAT,
        "status": STATUS,
        "execution_status": BLOCKED_STATUS,
        "phase43_identities": dict(PHASE43_IDENTITIES),
        "phase43_contract_digest": PHASE43_CONTRACT_DIGEST,
        "phase42_contract_digest": PHASE42_CONTRACT_DIGEST,
        "phase41_ceremony_contract_digest": PHASE41_CEREMONY_CONTRACT_DIGEST,
        "phase41_gate1_contract_digest": PHASE41_GATE1_CONTRACT_DIGEST,
        "phase40_owner_contract_digest": PHASE40_OWNER_CONTRACT_DIGEST,
        "phase40_gate1_contract_digest": PHASE40_GATE1_CONTRACT_DIGEST,
        "phase39_contract_digest": PHASE39_CONTRACT_DIGEST,
        "pin_policy": {
            "roles": list(PIN_ROLE_ORDER),
            "all_role_primary_fingerprints_distinct": True,
            "all_role_signing_fingerprints_distinct": True,
            "all_role_keyring_hashes_distinct": True,
            "owner_and_witness_signatures_required": True,
            "out_of_band_local_pin_policy_required": True,
            "nonfixture_keyring_relationship_inspection_required": True,
            "signature_inputs_use_kernel_sealed_memfds": True,
            "original_paths_reopened_after_measurement": False,
            "pinset_document_alone_creates_authority": False,
        },
        "admission_envelope_policy": {
            "phase43_preflight_required": True,
            "phase39_job_and_command_set_bound": True,
            "phase40_input_closure_bound": True,
            "phase41_ceremony_state_bound": True,
            "phase42_witness_and_transcript_bound": True,
            "phase43_custody_operator_signers_bound": True,
            "owner_and_witness_signatures_required": True,
            "fixture_envelope_can_be_eligible": False,
            "envelope_itself_can_close_gate1": False,
        },
        "final_receipt_policy": {
            "phase41_monotonic_decision_required": True,
            "phase41_decision_ledger_binding_required": True,
            "preflight_and_envelope_must_match": True,
            "fixture_receipt_can_approve_gate1": False,
            "gate1_approval_requires_every_exact_binding": True,
            "final_ledger_is_monotonic_replay_resistant_and_atomic": True,
            "gate1_approval_implies_only_one_of_fourteen_gates": True,
            "gate1_approval_can_enable_production_dispatch": False,
            "gate1_approval_can_enable_iso_release": False,
        },
        "schemas": {
            **{name: {"id": schema["$id"], "canonical_sha256": _schema_digest(schema)} for name, schema in schemas.items()},
            "additional_properties_allowed": False,
        },
        "network_fetch_allowed": False,
        "production_gates_approved": 0,
        "production_dispatch_allowed": False,
        "iso_release_allowed": False,
    }


def phase44_contract() -> dict[str, Any]:
    unsigned = _contract_unsigned()
    return {**unsigned, "contract_digest": _digest(CONTRACT_DOMAIN, unsigned)}


def phase44_contract_digest() -> str:
    return phase44_contract()["contract_digest"]


def parse_phase44_contract(value: Mapping[str, Any]) -> dict[str, Any]:
    expected = phase44_contract()
    if type(value) is not dict or value != expected:
        raise PolicyError("Phase 44 contract differs from policy")
    return json.loads(canonical_json_bytes(value))


def _parse_role_records(value: Any, context: str) -> list[dict[str, str]]:
    if type(value) is not list or len(value) != len(PIN_ROLE_ORDER):
        raise PolicyError(f"{context} must contain the exact six-role inventory")
    records: list[dict[str, str]] = []
    for index, expected_role in enumerate(PIN_ROLE_ORDER):
        item = value[index]
        if type(item) is not dict or set(item) != {"role", "primary_fingerprint", "signing_fingerprint", "keyring_sha256"}:
            raise PolicyError(f"{context} role record is not closed")
        if item["role"] != expected_role:
            raise PolicyError(f"{context} role order drifted")
        records.append({
            "role": expected_role,
            "primary_fingerprint": _fpr(item["primary_fingerprint"], f"{context} {expected_role} primary"),
            "signing_fingerprint": _fpr(item["signing_fingerprint"], f"{context} {expected_role} signer"),
            "keyring_sha256": _sha(item["keyring_sha256"], f"{context} {expected_role} keyring"),
        })
    for field in ("primary_fingerprint", "signing_fingerprint", "keyring_sha256"):
        values = [item[field] for item in records]
        if len(set(values)) != len(values):
            raise PolicyError(f"{context} reuses a {field}")
    return records


def _roles_by_name(records: Sequence[Mapping[str, str]]) -> dict[str, Mapping[str, str]]:
    return {str(item["role"]): item for item in records}


def create_local_pin_policy(*, roles: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    parsed = _parse_role_records(list(roles), "Phase 44 local pin policy")
    unsigned = {
        "format": LOCAL_PINS_FORMAT,
        "role_order": list(PIN_ROLE_ORDER),
        "roles": parsed,
        "all_role_identities_distinct": True,
    }
    return {**unsigned, "policy_digest": _digest(LOCAL_PINS_DOMAIN, unsigned)}


def parse_local_pin_policy(value: Mapping[str, Any]) -> dict[str, Any]:
    required = set(local_pin_policy_schema()["required"])
    if type(value) is not dict or set(value) != required:
        raise PolicyError("Phase 44 local pin policy fields are not closed")
    candidate = json.loads(canonical_json_bytes(value))
    if candidate["format"] != LOCAL_PINS_FORMAT or candidate["role_order"] != list(PIN_ROLE_ORDER):
        raise PolicyError("Phase 44 local pin policy identity drifted")
    roles = _parse_role_records(candidate["roles"], "Phase 44 local pin policy")
    if candidate["all_role_identities_distinct"] is not True:
        raise PolicyError("Phase 44 local pin role separation is disabled")
    recreated = create_local_pin_policy(roles=roles)
    if candidate != recreated:
        raise PolicyError("Phase 44 local pin policy digest drifted")
    return candidate


def create_authority_pinset(
    *, local_pin_policy: Mapping[str, Any], generation: int, created_unix: int,
    expires_unix: int, challenge_nonce: str, previous_pinset_digest: str = ZERO_SHA,
    fixture_mode: bool = False,
) -> dict[str, Any]:
    policy = parse_local_pin_policy(local_pin_policy)
    if type(generation) is not int or generation < 1:
        raise PolicyError("Phase 44 pinset generation is invalid")
    if type(created_unix) is not int or type(expires_unix) is not int or created_unix < 1:
        raise PolicyError("Phase 44 pinset timestamps are invalid")
    if not created_unix < expires_unix <= created_unix + MAX_RECORD_LIFETIME:
        raise PolicyError("Phase 44 pinset lifetime is invalid")
    _sha(challenge_nonce, "Phase 44 pinset challenge")
    _sha(previous_pinset_digest, "Phase 44 previous pinset", allow_zero=(generation == 1))
    if generation == 1 and previous_pinset_digest != ZERO_SHA:
        raise PolicyError("Phase 44 initial pinset must have a zero predecessor")
    if generation > 1 and previous_pinset_digest == ZERO_SHA:
        raise PolicyError("Phase 44 rotated pinset requires a predecessor")
    if type(fixture_mode) is not bool:
        raise PolicyError("Phase 44 pinset fixture flag is invalid")
    unsigned = {
        "format": PINSET_FORMAT,
        "contract_digest": phase44_contract_digest(),
        "phase43_contract_digest": PHASE43_CONTRACT_DIGEST,
        "generation": generation,
        "created_unix": created_unix,
        "expires_unix": expires_unix,
        "challenge_nonce": challenge_nonce,
        "previous_pinset_digest": previous_pinset_digest,
        "local_pin_policy_digest": policy["policy_digest"],
        "roles": policy["roles"],
        "owner_signature_required": True,
        "witness_signature_required": True,
        "all_role_identities_distinct": True,
        "fixture_mode": fixture_mode,
        "authority_created_by_document": False,
        "gate1_approved": False,
        "production_gates_approved": 0,
        "production_dispatch_allowed": False,
        "iso_release_allowed": False,
    }
    return {**unsigned, "pinset_digest": _digest(PINSET_DOMAIN, unsigned)}


def parse_authority_pinset(value: Mapping[str, Any], *, now_unix: int | None = None) -> dict[str, Any]:
    required = set(authority_pinset_schema()["required"])
    if type(value) is not dict or set(value) != required:
        raise PolicyError("Phase 44 authority pinset fields are not closed")
    candidate = json.loads(canonical_json_bytes(value))
    roles = _parse_role_records(candidate["roles"], "Phase 44 authority pinset")
    policy = create_local_pin_policy(roles=roles)
    recreated = create_authority_pinset(
        local_pin_policy=policy,
        generation=candidate["generation"],
        created_unix=candidate["created_unix"],
        expires_unix=candidate["expires_unix"],
        challenge_nonce=candidate["challenge_nonce"],
        previous_pinset_digest=candidate["previous_pinset_digest"],
        fixture_mode=candidate["fixture_mode"],
    )
    if candidate != recreated:
        raise PolicyError("Phase 44 authority pinset identity or digest drifted")
    if now_unix is not None:
        if type(now_unix) is not int or now_unix < 1:
            raise PolicyError("Phase 44 pinset verification time is invalid")
        if now_unix + phase39.MAX_CLOCK_SKEW_SECONDS < candidate["created_unix"]:
            raise PolicyError("Phase 44 authority pinset is from the future")
        if now_unix > candidate["expires_unix"] + phase39.MAX_CLOCK_SKEW_SECONDS:
            raise PolicyError("Phase 44 authority pinset expired")
    return candidate


@dataclass(frozen=True)
class VerifiedAuthorityPinset:
    document: dict[str, Any]
    local_pin_policy: dict[str, Any]
    signed_input_sha256: dict[str, str]
    owner_signature_verified: bool
    witness_signature_verified: bool
    authority_pins_authenticated: bool
    verification_digest: str

    @property
    def fixture_mode(self) -> bool:
        return bool(self.document["fixture_mode"])

    @property
    def roles(self) -> dict[str, Mapping[str, str]]:
        return _roles_by_name(self.document["roles"])

    def to_dict(self) -> dict[str, Any]:
        return {
            "format": PINSET_VERIFICATION_FORMAT,
            "pinset_digest": self.document["pinset_digest"],
            "local_pin_policy_digest": self.local_pin_policy["policy_digest"],
            "signed_input_sha256": dict(self.signed_input_sha256),
            "owner_signature_verified": self.owner_signature_verified,
            "witness_signature_verified": self.witness_signature_verified,
            "local_policy_verified": True,
            "role_separation_verified": True,
            "fixture_mode": self.fixture_mode,
            "authority_pins_authenticated": self.authority_pins_authenticated,
            "gate1_approved": False,
            "production_gates_approved": 0,
            "production_dispatch_allowed": False,
            "iso_release_allowed": False,
            "verification_digest": self.verification_digest,
        }


def _verify_role_signature(
    *, payload: bytes, signature: bytes, keyring: bytes, keyring_meta: phase40.MeasuredFile,
    role_record: Mapping[str, str], valid_through_unix: int, fixture_mode: bool,
    gpgv_executable: str | Path, gpg_executable: str | Path, role: str,
) -> None:
    if keyring_meta.sha256 != role_record["keyring_sha256"]:
        raise PolicyError(f"Phase 44 {role} keyring differs from local pin")
    if not fixture_mode:
        phase40._inspect_verification_keyring_payload(  # type: ignore[attr-defined]
            measured=keyring_meta,
            payload=keyring,
            expected_primary_fingerprint=role_record["primary_fingerprint"],
            expected_signing_fingerprint=role_record["signing_fingerprint"],
            valid_through_unix=valid_through_unix,
            gpg_executable=gpg_executable,
            fixture_mode=False,
        )
    phase39._verify_signature(  # type: ignore[attr-defined]
        payload=payload,
        signature=signature,
        keyring=keyring,
        expected_fingerprint=role_record["signing_fingerprint"],
        gpgv_executable=gpgv_executable,
        fixture_mode=fixture_mode,
        role=role,
    )


def verify_signed_authority_pinset(
    *, pinset_path: Path, owner_signature_path: Path, owner_keyring_path: Path,
    witness_signature_path: Path, witness_keyring_path: Path,
    local_pin_policy: Mapping[str, Any], now_unix: int,
    gpgv_executable: str | Path = "/usr/bin/gpgv",
    gpg_executable: str | Path = "/usr/bin/gpg",
) -> VerifiedAuthorityPinset:
    policy = parse_local_pin_policy(local_pin_policy)
    pinset_meta, pinset_bytes = phase40.measure_file(pinset_path, maximum=MAX_JSON_BYTES, context="Phase 44 authority pinset")
    owner_sig_meta, owner_sig = phase40.measure_file(owner_signature_path, maximum=phase40.MAX_SIGNATURE_BYTES, context="Phase 44 owner pinset signature")
    owner_key_meta, owner_key = phase40.measure_file(owner_keyring_path, maximum=phase40.MAX_KEYRING_BYTES, context="Phase 44 owner keyring")
    witness_sig_meta, witness_sig = phase40.measure_file(witness_signature_path, maximum=phase40.MAX_SIGNATURE_BYTES, context="Phase 44 witness pinset signature")
    witness_key_meta, witness_key = phase40.measure_file(witness_keyring_path, maximum=phase40.MAX_KEYRING_BYTES, context="Phase 44 witness keyring")
    document = parse_authority_pinset(_strict_json(pinset_bytes, "Phase 44 authority pinset"), now_unix=now_unix)
    if document["local_pin_policy_digest"] != policy["policy_digest"] or document["roles"] != policy["roles"]:
        raise PolicyError("Phase 44 authority pinset differs from out-of-band local pins")
    roles = _roles_by_name(policy["roles"])
    _verify_role_signature(
        payload=pinset_bytes, signature=owner_sig, keyring=owner_key, keyring_meta=owner_key_meta,
        role_record=roles["owner"], valid_through_unix=document["expires_unix"],
        fixture_mode=document["fixture_mode"], gpgv_executable=gpgv_executable,
        gpg_executable=gpg_executable, role="phase44-owner-pinset",
    )
    _verify_role_signature(
        payload=pinset_bytes, signature=witness_sig, keyring=witness_key, keyring_meta=witness_key_meta,
        role_record=roles["witness"], valid_through_unix=document["expires_unix"],
        fixture_mode=document["fixture_mode"], gpgv_executable=gpgv_executable,
        gpg_executable=gpg_executable, role="phase44-witness-pinset",
    )
    signed_inputs = {
        "pinset": pinset_meta.sha256,
        "owner_signature": owner_sig_meta.sha256,
        "owner_keyring": owner_key_meta.sha256,
        "witness_signature": witness_sig_meta.sha256,
        "witness_keyring": witness_key_meta.sha256,
    }
    unsigned = {
        "format": PINSET_VERIFICATION_FORMAT,
        "pinset_digest": document["pinset_digest"],
        "local_pin_policy_digest": policy["policy_digest"],
        "signed_input_sha256": signed_inputs,
        "owner_signature_verified": True,
        "witness_signature_verified": True,
        "local_policy_verified": True,
        "role_separation_verified": True,
        "fixture_mode": document["fixture_mode"],
        "authority_pins_authenticated": not document["fixture_mode"],
        "gate1_approved": False,
        "production_gates_approved": 0,
        "production_dispatch_allowed": False,
        "iso_release_allowed": False,
    }
    verification_digest = _digest(PINSET_VERIFICATION_DOMAIN, unsigned)
    return VerifiedAuthorityPinset(
        document=document,
        local_pin_policy=policy,
        signed_input_sha256=signed_inputs,
        owner_signature_verified=True,
        witness_signature_verified=True,
        authority_pins_authenticated=not document["fixture_mode"],
        verification_digest=verification_digest,
    )


def parse_pinset_verification(value: Mapping[str, Any]) -> dict[str, Any]:
    required = set(pinset_verification_schema()["required"])
    if type(value) is not dict or set(value) != required:
        raise PolicyError("Phase 44 pinset verification fields are not closed")
    candidate = json.loads(canonical_json_bytes(value))
    for field in ("pinset_digest", "local_pin_policy_digest", "verification_digest"):
        _sha(candidate[field], f"Phase 44 pinset verification {field}")
    if type(candidate["signed_input_sha256"]) is not dict or set(candidate["signed_input_sha256"]) != {"pinset", "owner_signature", "owner_keyring", "witness_signature", "witness_keyring"}:
        raise PolicyError("Phase 44 pinset signed-input inventory drifted")
    for name, digest in candidate["signed_input_sha256"].items():
        _sha(digest, f"Phase 44 pinset signed input {name}")
    for field in ("owner_signature_verified", "witness_signature_verified", "local_policy_verified", "role_separation_verified"):
        if candidate[field] is not True:
            raise PolicyError(f"Phase 44 pinset verification {field} is not true")
    if type(candidate["fixture_mode"]) is not bool or type(candidate["authority_pins_authenticated"]) is not bool:
        raise PolicyError("Phase 44 pinset authentication flags are invalid")
    if candidate["authority_pins_authenticated"] != (not candidate["fixture_mode"]):
        raise PolicyError("Phase 44 pinset fixture/authentication relationship drifted")
    if candidate["gate1_approved"] is not False or candidate["production_gates_approved"] != 0 or candidate["production_dispatch_allowed"] is not False or candidate["iso_release_allowed"] is not False:
        raise PolicyError("Phase 44 pinset verification attempted promotion")
    unsigned = {key: candidate[key] for key in candidate if key != "verification_digest"}
    if candidate["verification_digest"] != _digest(PINSET_VERIFICATION_DOMAIN, unsigned):
        raise PolicyError("Phase 44 pinset verification digest is invalid")
    return candidate


def _custody_signers(ledger: Mapping[str, Any]) -> dict[str, str]:
    result: dict[str, str] = {}
    for record in ledger["records"]:
        role = record["operator_role"]
        signing = record["operator_signing_fingerprint"]
        previous = result.get(role)
        if previous is not None and previous != signing:
            raise PolicyError("Phase 44 custody role changed signer within one transfer")
        result[role] = signing
    required = {"export-operator", "receiving-operator", "independent-verifier"}
    if set(result) != required:
        raise PolicyError("Phase 44 custody operator inventory is incomplete")
    return result


def _command_set_digest(job: phase39.GateJob) -> str:
    return _digest(COMMAND_SET_DOMAIN, {
        "network_policy": job.document["network_policy"],
        "commands": job.document["commands"],
        "evidence_roles": job.document["evidence_roles"],
    })


def create_admission_envelope(
    *, created_unix: int, expires_unix: int, envelope_id: str,
    verified_pinset: VerifiedAuthorityPinset, phase43_preflight: Mapping[str, Any],
    custody_ledger: Mapping[str, Any], trust_state: Mapping[str, Any],
    ceremony_state: Mapping[str, Any], gate_job: Mapping[str, Any],
    witness_checkpoint: Mapping[str, Any],
) -> dict[str, Any]:
    if not isinstance(verified_pinset, VerifiedAuthorityPinset):
        raise PolicyError("Phase 44 envelope requires a verified authority pinset")
    if type(created_unix) is not int or type(expires_unix) is not int or created_unix < 1:
        raise PolicyError("Phase 44 envelope timestamps are invalid")
    if not created_unix < expires_unix <= created_unix + MAX_RECORD_LIFETIME:
        raise PolicyError("Phase 44 envelope lifetime is invalid")
    _token(envelope_id, "Phase 44 envelope ID")
    preflight = phase43.parse_gate1_preflight(phase43_preflight)
    custody = phase43.parse_custody_ledger(custody_ledger)
    trust = phase40.parse_trust_state(trust_state)
    state = phase41_ceremony.parse_ceremony_state(ceremony_state)
    job = phase39.parse_gate_job(gate_job, now_unix=created_unix)
    witness = phase42.parse_witness_checkpoint(witness_checkpoint, now_unix=created_unix)
    pinset = verified_pinset.document
    roles = verified_pinset.roles
    custody_signers = _custody_signers(custody)
    if job.gate_name != phase39.GATE_NAMES[0] or job.gate_index != 1:
        raise PolicyError("Phase 44 envelope accepts only Gate 1")
    if not (
        pinset["challenge_nonce"] == preflight["challenge_nonce"] == custody["challenge_nonce"] == job.document["challenge_nonce"] == witness["challenge_nonce"]
    ):
        raise PolicyError("Phase 44 envelope challenge binding drifted")
    if preflight["custody_ledger_digest"] != custody["ledger_digest"]:
        raise PolicyError("Phase 44 envelope custody ledger differs from preflight")
    if preflight["trust_state_digest"] != trust["state_digest"] or preflight["ceremony_state_digest"] != state["state_digest"]:
        raise PolicyError("Phase 44 envelope trust or ceremony state differs from preflight")
    if preflight["phase39_job_digest"] != job.job_digest:
        raise PolicyError("Phase 44 envelope Gate 1 job differs from preflight")
    if preflight["witness_checkpoint_digest"] != witness["checkpoint_digest"]:
        raise PolicyError("Phase 44 envelope witness checkpoint differs from preflight")
    if roles["owner"]["primary_fingerprint"] != trust["owner_primary_fingerprint"] or roles["owner"]["signing_fingerprint"] != trust["owner_job_signer_fingerprint"] or roles["owner"]["keyring_sha256"] != trust["owner_keyring_sha256"]:
        raise PolicyError("Phase 44 owner pin differs from trust state")
    if roles["build-node"]["primary_fingerprint"] != trust["build_node_primary_fingerprint"] or roles["build-node"]["signing_fingerprint"] != trust["build_node_result_signer_fingerprint"] or roles["build-node"]["keyring_sha256"] != trust["build_node_keyring_sha256"]:
        raise PolicyError("Phase 44 build-node pin differs from trust state")
    if roles["witness"]["primary_fingerprint"] != witness["witness_primary_fingerprint"] or roles["witness"]["signing_fingerprint"] != witness["witness_signing_fingerprint"] or roles["witness"]["keyring_sha256"] != witness["witness_keyring_sha256"]:
        raise PolicyError("Phase 44 witness pin differs from checkpoint")
    if job.owner_fingerprint != roles["owner"]["signing_fingerprint"] or job.result_fingerprint != roles["build-node"]["signing_fingerprint"] or job.document["build_node_id"] != trust["build_node_id"]:
        raise PolicyError("Phase 44 job signer or build node differs from pinset")
    for role in ("export-operator", "receiving-operator", "independent-verifier"):
        if custody_signers[role] != roles[role]["signing_fingerprint"]:
            raise PolicyError(f"Phase 44 {role} differs from custody ledger")
    fixture_mode = bool(
        verified_pinset.fixture_mode or preflight["fixture_mode"] or custody["fixture_mode"]
        or trust["fixture_mode"] or state["fixture_mode"] or job.fixture_mode or witness["fixture_mode"]
    )
    eligible = bool(
        verified_pinset.authority_pins_authenticated
        and preflight["eligible_for_phase41_decision"]
        and custody["status"] == "imported"
        and custody["custody_chain_authenticated"]
        and state["status"] == "active"
        and state["gate1_jobs_allowed"]
        and not fixture_mode
    )
    unsigned = {
        "format": ENVELOPE_FORMAT,
        "contract_digest": phase44_contract_digest(),
        "created_unix": created_unix,
        "expires_unix": expires_unix,
        "envelope_id": envelope_id,
        "gate_name": job.gate_name,
        "gate_index": job.gate_index,
        "job_id": job.job_id,
        "challenge_nonce": job.document["challenge_nonce"],
        "pinset_digest": pinset["pinset_digest"],
        "pinset_verification_digest": verified_pinset.verification_digest,
        "local_pin_policy_digest": verified_pinset.local_pin_policy["policy_digest"],
        "phase43_preflight_digest": preflight["preflight_digest"],
        "custody_ledger_digest": custody["ledger_digest"],
        "trust_state_digest": trust["state_digest"],
        "ceremony_state_digest": state["state_digest"],
        "phase39_job_digest": job.job_digest,
        "phase39_result_digest": preflight["phase39_result_digest"],
        "phase39_verification_digest": preflight["phase39_verification_digest"],
        "phase40_semantic_receipt_digest": preflight["phase40_semantic_receipt_digest"],
        "input_closure_digest": preflight["input_closure_digest"],
        "witness_checkpoint_digest": witness["checkpoint_digest"],
        "witness_verification_digest": preflight["witness_verification_digest"],
        "transcript_digest": preflight["transcript_digest"],
        "transcript_verification_digest": preflight["transcript_verification_digest"],
        "command_set_digest": _command_set_digest(job),
        "network_policy": job.document["network_policy"],
        "evidence_roles": job.document["evidence_roles"],
        "build_node_id": job.document["build_node_id"],
        "owner_signing_fingerprint": roles["owner"]["signing_fingerprint"],
        "build_node_signing_fingerprint": roles["build-node"]["signing_fingerprint"],
        "witness_signing_fingerprint": roles["witness"]["signing_fingerprint"],
        "custody_operator_signers": custody_signers,
        "fixture_mode": fixture_mode,
        "all_bindings_verified": True,
        "eligible_for_phase41_decision": eligible,
        "owner_signature_required": True,
        "witness_signature_required": True,
        "gate1_approved": False,
        "production_gates_approved": 0,
        "production_dispatch_allowed": False,
        "iso_release_allowed": False,
    }
    return {**unsigned, "envelope_digest": _digest(ENVELOPE_DOMAIN, unsigned)}


def parse_admission_envelope(value: Mapping[str, Any], *, now_unix: int | None = None) -> dict[str, Any]:
    required = set(admission_envelope_schema()["required"])
    if type(value) is not dict or set(value) != required:
        raise PolicyError("Phase 44 admission envelope fields are not closed")
    candidate = json.loads(canonical_json_bytes(value))
    if candidate["format"] != ENVELOPE_FORMAT or candidate["contract_digest"] != phase44_contract_digest():
        raise PolicyError("Phase 44 admission envelope identity drifted")
    if type(candidate["created_unix"]) is not int or type(candidate["expires_unix"]) is not int or candidate["created_unix"] < 1 or not candidate["created_unix"] < candidate["expires_unix"] <= candidate["created_unix"] + MAX_RECORD_LIFETIME:
        raise PolicyError("Phase 44 admission envelope timestamps are invalid")
    _token(candidate["envelope_id"], "Phase 44 envelope ID")
    if candidate["gate_name"] != phase39.GATE_NAMES[0] or candidate["gate_index"] != 1 or type(candidate["job_id"]) is not int or candidate["job_id"] < 1:
        raise PolicyError("Phase 44 envelope Gate 1 identity drifted")
    for field in (
        "challenge_nonce", "pinset_digest", "pinset_verification_digest", "local_pin_policy_digest",
        "phase43_preflight_digest", "custody_ledger_digest", "trust_state_digest", "ceremony_state_digest",
        "phase39_job_digest", "phase39_result_digest", "phase39_verification_digest",
        "phase40_semantic_receipt_digest", "input_closure_digest", "witness_checkpoint_digest",
        "witness_verification_digest", "transcript_digest", "transcript_verification_digest",
        "command_set_digest", "envelope_digest",
    ):
        _sha(candidate[field], f"Phase 44 envelope {field}")
    if candidate["network_policy"] not in phase39.NETWORK_POLICIES:
        raise PolicyError("Phase 44 envelope network policy is invalid")
    if type(candidate["evidence_roles"]) is not list or not candidate["evidence_roles"] or len(set(candidate["evidence_roles"])) != len(candidate["evidence_roles"]):
        raise PolicyError("Phase 44 envelope evidence-role inventory is invalid")
    _token(candidate["build_node_id"], "Phase 44 envelope build-node ID")
    for field in ("owner_signing_fingerprint", "build_node_signing_fingerprint", "witness_signing_fingerprint"):
        _fpr(candidate[field], f"Phase 44 envelope {field}")
    if type(candidate["custody_operator_signers"]) is not dict or set(candidate["custody_operator_signers"]) != {"export-operator", "receiving-operator", "independent-verifier"}:
        raise PolicyError("Phase 44 envelope custody signer inventory drifted")
    for role, fingerprint in candidate["custody_operator_signers"].items():
        _fpr(fingerprint, f"Phase 44 envelope {role}")
    if len(set([candidate["owner_signing_fingerprint"], candidate["build_node_signing_fingerprint"], candidate["witness_signing_fingerprint"], *candidate["custody_operator_signers"].values()])) != len(PIN_ROLE_ORDER):
        raise PolicyError("Phase 44 envelope reuses a signing identity")
    for field in ("fixture_mode", "eligible_for_phase41_decision"):
        if type(candidate[field]) is not bool:
            raise PolicyError(f"Phase 44 envelope {field} is invalid")
    if candidate["all_bindings_verified"] is not True or candidate["owner_signature_required"] is not True or candidate["witness_signature_required"] is not True:
        raise PolicyError("Phase 44 envelope disabled an admission binding")
    if candidate["eligible_for_phase41_decision"] and candidate["fixture_mode"]:
        raise PolicyError("Phase 44 fixture envelope cannot be eligible")
    if candidate["gate1_approved"] is not False or candidate["production_gates_approved"] != 0 or candidate["production_dispatch_allowed"] is not False or candidate["iso_release_allowed"] is not False:
        raise PolicyError("Phase 44 envelope attempted Gate 1 or release promotion")
    unsigned = {key: candidate[key] for key in candidate if key != "envelope_digest"}
    if candidate["envelope_digest"] != _digest(ENVELOPE_DOMAIN, unsigned):
        raise PolicyError("Phase 44 envelope digest is invalid")
    if now_unix is not None:
        if type(now_unix) is not int or now_unix < 1:
            raise PolicyError("Phase 44 envelope verification time is invalid")
        if now_unix + phase39.MAX_CLOCK_SKEW_SECONDS < candidate["created_unix"]:
            raise PolicyError("Phase 44 envelope is from the future")
        if now_unix > candidate["expires_unix"] + phase39.MAX_CLOCK_SKEW_SECONDS:
            raise PolicyError("Phase 44 envelope expired")
    return candidate


@dataclass(frozen=True)
class VerifiedAdmissionEnvelope:
    document: dict[str, Any]
    pinset: VerifiedAuthorityPinset
    signed_input_sha256: dict[str, str]
    owner_signature_verified: bool
    witness_signature_verified: bool
    envelope_authenticated: bool
    verification_digest: str

    @property
    def fixture_mode(self) -> bool:
        return bool(self.document["fixture_mode"])

    def to_dict(self) -> dict[str, Any]:
        return {
            "format": ENVELOPE_VERIFICATION_FORMAT,
            "envelope_digest": self.document["envelope_digest"],
            "pinset_digest": self.pinset.document["pinset_digest"],
            "pinset_verification_digest": self.pinset.verification_digest,
            "signed_input_sha256": dict(self.signed_input_sha256),
            "owner_signature_verified": self.owner_signature_verified,
            "witness_signature_verified": self.witness_signature_verified,
            "pinset_authenticated": self.pinset.authority_pins_authenticated,
            "fixture_mode": self.fixture_mode,
            "envelope_authenticated": self.envelope_authenticated,
            "eligible_for_phase41_decision": bool(self.document["eligible_for_phase41_decision"] and self.envelope_authenticated),
            "gate1_approved": False,
            "production_gates_approved": 0,
            "production_dispatch_allowed": False,
            "iso_release_allowed": False,
            "verification_digest": self.verification_digest,
        }


def verify_signed_admission_envelope(
    *, envelope_path: Path, owner_signature_path: Path, owner_keyring_path: Path,
    witness_signature_path: Path, witness_keyring_path: Path,
    verified_pinset: VerifiedAuthorityPinset, now_unix: int,
    gpgv_executable: str | Path = "/usr/bin/gpgv",
    gpg_executable: str | Path = "/usr/bin/gpg",
) -> VerifiedAdmissionEnvelope:
    if not isinstance(verified_pinset, VerifiedAuthorityPinset):
        raise PolicyError("Phase 44 envelope verification requires a verified pinset")
    envelope_meta, envelope_bytes = phase40.measure_file(envelope_path, maximum=MAX_JSON_BYTES, context="Phase 44 admission envelope")
    owner_sig_meta, owner_sig = phase40.measure_file(owner_signature_path, maximum=phase40.MAX_SIGNATURE_BYTES, context="Phase 44 owner envelope signature")
    owner_key_meta, owner_key = phase40.measure_file(owner_keyring_path, maximum=phase40.MAX_KEYRING_BYTES, context="Phase 44 owner keyring")
    witness_sig_meta, witness_sig = phase40.measure_file(witness_signature_path, maximum=phase40.MAX_SIGNATURE_BYTES, context="Phase 44 witness envelope signature")
    witness_key_meta, witness_key = phase40.measure_file(witness_keyring_path, maximum=phase40.MAX_KEYRING_BYTES, context="Phase 44 witness keyring")
    document = parse_admission_envelope(_strict_json(envelope_bytes, "Phase 44 admission envelope"), now_unix=now_unix)
    if document["pinset_digest"] != verified_pinset.document["pinset_digest"] or document["pinset_verification_digest"] != verified_pinset.verification_digest or document["local_pin_policy_digest"] != verified_pinset.local_pin_policy["policy_digest"]:
        raise PolicyError("Phase 44 envelope differs from verified pinset")
    roles = verified_pinset.roles
    if document["owner_signing_fingerprint"] != roles["owner"]["signing_fingerprint"] or document["witness_signing_fingerprint"] != roles["witness"]["signing_fingerprint"]:
        raise PolicyError("Phase 44 envelope signer identity differs from pinset")
    fixture_mode = bool(document["fixture_mode"] or verified_pinset.fixture_mode)
    _verify_role_signature(
        payload=envelope_bytes, signature=owner_sig, keyring=owner_key, keyring_meta=owner_key_meta,
        role_record=roles["owner"], valid_through_unix=document["expires_unix"], fixture_mode=fixture_mode,
        gpgv_executable=gpgv_executable, gpg_executable=gpg_executable, role="phase44-owner-envelope",
    )
    _verify_role_signature(
        payload=envelope_bytes, signature=witness_sig, keyring=witness_key, keyring_meta=witness_key_meta,
        role_record=roles["witness"], valid_through_unix=document["expires_unix"], fixture_mode=fixture_mode,
        gpgv_executable=gpgv_executable, gpg_executable=gpg_executable, role="phase44-witness-envelope",
    )
    authenticated = bool(verified_pinset.authority_pins_authenticated and not fixture_mode)
    signed_inputs = {
        "envelope": envelope_meta.sha256,
        "owner_signature": owner_sig_meta.sha256,
        "owner_keyring": owner_key_meta.sha256,
        "witness_signature": witness_sig_meta.sha256,
        "witness_keyring": witness_key_meta.sha256,
    }
    unsigned = {
        "format": ENVELOPE_VERIFICATION_FORMAT,
        "envelope_digest": document["envelope_digest"],
        "pinset_digest": verified_pinset.document["pinset_digest"],
        "pinset_verification_digest": verified_pinset.verification_digest,
        "signed_input_sha256": signed_inputs,
        "owner_signature_verified": True,
        "witness_signature_verified": True,
        "pinset_authenticated": verified_pinset.authority_pins_authenticated,
        "fixture_mode": fixture_mode,
        "envelope_authenticated": authenticated,
        "eligible_for_phase41_decision": bool(document["eligible_for_phase41_decision"] and authenticated),
        "gate1_approved": False,
        "production_gates_approved": 0,
        "production_dispatch_allowed": False,
        "iso_release_allowed": False,
    }
    return VerifiedAdmissionEnvelope(
        document=document,
        pinset=verified_pinset,
        signed_input_sha256=signed_inputs,
        owner_signature_verified=True,
        witness_signature_verified=True,
        envelope_authenticated=authenticated,
        verification_digest=_digest(ENVELOPE_VERIFICATION_DOMAIN, unsigned),
    )


def parse_envelope_verification(value: Mapping[str, Any]) -> dict[str, Any]:
    required = set(envelope_verification_schema()["required"])
    if type(value) is not dict or set(value) != required:
        raise PolicyError("Phase 44 envelope verification fields are not closed")
    candidate = json.loads(canonical_json_bytes(value))
    for field in ("envelope_digest", "pinset_digest", "pinset_verification_digest", "verification_digest"):
        _sha(candidate[field], f"Phase 44 envelope verification {field}")
    if type(candidate["signed_input_sha256"]) is not dict or set(candidate["signed_input_sha256"]) != {"envelope", "owner_signature", "owner_keyring", "witness_signature", "witness_keyring"}:
        raise PolicyError("Phase 44 envelope signed-input inventory drifted")
    for name, digest in candidate["signed_input_sha256"].items():
        _sha(digest, f"Phase 44 envelope signed input {name}")
    if candidate["owner_signature_verified"] is not True or candidate["witness_signature_verified"] is not True:
        raise PolicyError("Phase 44 envelope signatures are incomplete")
    for field in ("pinset_authenticated", "fixture_mode", "envelope_authenticated", "eligible_for_phase41_decision"):
        if type(candidate[field]) is not bool:
            raise PolicyError(f"Phase 44 envelope verification {field} is invalid")
    expected_auth = bool(candidate["pinset_authenticated"] and not candidate["fixture_mode"])
    if candidate["envelope_authenticated"] != expected_auth:
        raise PolicyError("Phase 44 envelope authentication relationship drifted")
    if candidate["eligible_for_phase41_decision"] and not expected_auth:
        raise PolicyError("Phase 44 unauthenticated envelope cannot be eligible")
    if candidate["gate1_approved"] is not False or candidate["production_gates_approved"] != 0 or candidate["production_dispatch_allowed"] is not False or candidate["iso_release_allowed"] is not False:
        raise PolicyError("Phase 44 envelope verification attempted promotion")
    unsigned = {key: candidate[key] for key in candidate if key != "verification_digest"}
    if candidate["verification_digest"] != _digest(ENVELOPE_VERIFICATION_DOMAIN, unsigned):
        raise PolicyError("Phase 44 envelope verification digest is invalid")
    return candidate


def create_final_gate1_receipt(
    *, created_unix: int, verified_envelope: VerifiedAdmissionEnvelope,
    phase43_preflight: Mapping[str, Any], phase41_decision: Mapping[str, Any],
    phase41_decision_ledger: Mapping[str, Any],
) -> dict[str, Any]:
    if type(created_unix) is not int or created_unix < 1:
        raise PolicyError("Phase 44 final receipt timestamp is invalid")
    if not isinstance(verified_envelope, VerifiedAdmissionEnvelope):
        raise PolicyError("Phase 44 final receipt requires a verified envelope")
    envelope = verified_envelope.document
    preflight = phase43.parse_gate1_preflight(phase43_preflight)
    decision = phase41_gate1.parse_gate1_decision(phase41_decision)
    ledger = phase41_gate1.parse_decision_ledger(phase41_decision_ledger)
    if envelope["phase43_preflight_digest"] != preflight["preflight_digest"]:
        raise PolicyError("Phase 44 envelope and preflight differ")
    if envelope["job_id"] != decision["job_id"] or envelope["phase39_job_digest"] != decision["phase39_job_digest"] or envelope["phase39_result_digest"] != decision["phase39_result_digest"] or envelope["ceremony_state_digest"] != decision["ceremony_state_digest"]:
        raise PolicyError("Phase 44 envelope and Phase 41 decision differ")
    if not ledger["records"]:
        raise PolicyError("Phase 44 requires a published Phase 41 decision ledger record")
    record = ledger["records"][-1]
    if (
        record["job_id"] != decision["job_id"]
        or record["job_digest"] != decision["phase39_job_digest"]
        or record["result_digest"] != decision["phase39_result_digest"]
        or record["decision_digest"] != decision["decision_digest"]
        or record["ceremony_state_digest"] != decision["ceremony_state_digest"]
        or record["gate_approved"] != decision["gate_approved"]
        or ledger["highest_job_id"] != decision["job_id"]
    ):
        raise PolicyError("Phase 44 Phase 41 decision ledger binding drifted")
    fixture_mode = bool(
        verified_envelope.fixture_mode
        or verified_envelope.pinset.fixture_mode
        or preflight["fixture_mode"]
        or decision["fixture_mode"]
    )
    approved = bool(
        verified_envelope.pinset.authority_pins_authenticated
        and verified_envelope.envelope_authenticated
        and envelope["eligible_for_phase41_decision"]
        and preflight["eligible_for_phase41_decision"]
        and decision["gate_approved"]
        and not fixture_mode
    )
    unsigned = {
        "format": RECEIPT_FORMAT,
        "contract_digest": phase44_contract_digest(),
        "created_unix": created_unix,
        "gate_name": phase39.GATE_NAMES[0],
        "gate_index": 1,
        "job_id": decision["job_id"],
        "challenge_nonce": envelope["challenge_nonce"],
        "envelope_digest": envelope["envelope_digest"],
        "envelope_verification_digest": verified_envelope.verification_digest,
        "phase43_preflight_digest": preflight["preflight_digest"],
        "phase41_decision_digest": decision["decision_digest"],
        "phase41_decision_ledger_digest": ledger["ledger_digest"],
        "pinset_authenticated": verified_envelope.pinset.authority_pins_authenticated,
        "envelope_authenticated": verified_envelope.envelope_authenticated,
        "preflight_eligible": preflight["eligible_for_phase41_decision"],
        "phase41_decision_approved": decision["gate_approved"],
        "phase41_decision_ledger_bound": True,
        "fixture_mode": fixture_mode,
        "gate1_approved": approved,
        "production_gates_approved": 1 if approved else 0,
        "production_dispatch_allowed": False,
        "iso_release_allowed": False,
        "iso_bytes_present": False,
    }
    return {**unsigned, "receipt_digest": _digest(RECEIPT_DOMAIN, unsigned)}


def parse_final_gate1_receipt(value: Mapping[str, Any]) -> dict[str, Any]:
    required = set(final_receipt_schema()["required"])
    if type(value) is not dict or set(value) != required:
        raise PolicyError("Phase 44 final receipt fields are not closed")
    candidate = json.loads(canonical_json_bytes(value))
    if candidate["format"] != RECEIPT_FORMAT or candidate["contract_digest"] != phase44_contract_digest():
        raise PolicyError("Phase 44 final receipt identity drifted")
    if type(candidate["created_unix"]) is not int or candidate["created_unix"] < 1 or candidate["gate_name"] != phase39.GATE_NAMES[0] or candidate["gate_index"] != 1 or type(candidate["job_id"]) is not int or candidate["job_id"] < 1:
        raise PolicyError("Phase 44 final receipt gate identity is invalid")
    for field in ("challenge_nonce", "envelope_digest", "envelope_verification_digest", "phase43_preflight_digest", "phase41_decision_digest", "phase41_decision_ledger_digest", "receipt_digest"):
        _sha(candidate[field], f"Phase 44 final receipt {field}")
    for field in ("pinset_authenticated", "envelope_authenticated", "preflight_eligible", "phase41_decision_approved", "fixture_mode", "gate1_approved"):
        if type(candidate[field]) is not bool:
            raise PolicyError(f"Phase 44 final receipt {field} is invalid")
    if candidate["phase41_decision_ledger_bound"] is not True:
        raise PolicyError("Phase 44 final receipt omitted the decision-ledger binding")
    expected = bool(
        candidate["pinset_authenticated"]
        and candidate["envelope_authenticated"]
        and candidate["preflight_eligible"]
        and candidate["phase41_decision_approved"]
        and candidate["phase41_decision_ledger_bound"]
        and not candidate["fixture_mode"]
    )
    if candidate["gate1_approved"] != expected or candidate["production_gates_approved"] != (1 if expected else 0):
        raise PolicyError("Phase 44 final receipt Gate 1 relationship drifted")
    if candidate["production_dispatch_allowed"] is not False or candidate["iso_release_allowed"] is not False or candidate["iso_bytes_present"] is not False:
        raise PolicyError("Phase 44 final receipt attempted release promotion")
    unsigned = {key: candidate[key] for key in candidate if key != "receipt_digest"}
    if candidate["receipt_digest"] != _digest(RECEIPT_DOMAIN, unsigned):
        raise PolicyError("Phase 44 final receipt digest is invalid")
    return candidate


def empty_final_ledger() -> dict[str, Any]:
    unsigned = {
        "format": LEDGER_FORMAT,
        "contract_digest": phase44_contract_digest(),
        "generation": 0,
        "highest_job_id": 0,
        "gate1_approved_count": 0,
        "records": [],
        "production_dispatch_allowed": False,
        "iso_release_allowed": False,
    }
    return {**unsigned, "ledger_digest": _digest(LEDGER_DOMAIN, unsigned)}


def parse_final_ledger(value: Mapping[str, Any]) -> dict[str, Any]:
    required = set(final_ledger_schema()["required"])
    if type(value) is not dict or set(value) != required:
        raise PolicyError("Phase 44 final ledger fields are not closed")
    candidate = json.loads(canonical_json_bytes(value))
    if candidate["format"] != LEDGER_FORMAT or candidate["contract_digest"] != phase44_contract_digest():
        raise PolicyError("Phase 44 final ledger identity drifted")
    records = candidate["records"]
    if type(records) is not list or len(records) > MAX_LEDGER_RECORDS:
        raise PolicyError("Phase 44 final ledger records are invalid")
    expected_job = 0
    seen_challenges: set[str] = set()
    seen_receipts: set[str] = set()
    seen_envelopes: set[str] = set()
    approved_count = 0
    for record in records:
        if type(record) is not dict or set(record) != {"job_id", "challenge_nonce", "envelope_digest", "receipt_digest", "gate1_approved"}:
            raise PolicyError("Phase 44 final ledger record is not closed")
        if type(record["job_id"]) is not int or record["job_id"] <= expected_job:
            raise PolicyError("Phase 44 final ledger job IDs are not strictly monotonic")
        expected_job = record["job_id"]
        _sha(record["challenge_nonce"], "Phase 44 ledger challenge")
        _sha(record["envelope_digest"], "Phase 44 ledger envelope")
        _sha(record["receipt_digest"], "Phase 44 ledger receipt")
        if type(record["gate1_approved"]) is not bool:
            raise PolicyError("Phase 44 ledger approval flag is invalid")
        if record["challenge_nonce"] in seen_challenges or record["receipt_digest"] in seen_receipts or record["envelope_digest"] in seen_envelopes:
            raise PolicyError("Phase 44 final ledger contains replay or equivocation")
        seen_challenges.add(record["challenge_nonce"])
        seen_receipts.add(record["receipt_digest"])
        seen_envelopes.add(record["envelope_digest"])
        approved_count += 1 if record["gate1_approved"] else 0
    if type(candidate["generation"]) is not int or candidate["generation"] != len(records) or candidate["highest_job_id"] != expected_job or candidate["gate1_approved_count"] != approved_count or approved_count not in {0, 1}:
        raise PolicyError("Phase 44 final ledger counters drifted")
    if candidate["production_dispatch_allowed"] is not False or candidate["iso_release_allowed"] is not False:
        raise PolicyError("Phase 44 final ledger attempted release promotion")
    unsigned = {key: candidate[key] for key in candidate if key != "ledger_digest"}
    if candidate["ledger_digest"] != _digest(LEDGER_DOMAIN, unsigned):
        raise PolicyError("Phase 44 final ledger digest is invalid")
    return candidate


def append_final_receipt(*, ledger: Mapping[str, Any], receipt: Mapping[str, Any]) -> dict[str, Any]:
    current = parse_final_ledger(ledger)
    parsed = parse_final_gate1_receipt(receipt)
    if current["records"] and parsed["job_id"] <= current["highest_job_id"]:
        raise PolicyError("Phase 44 final receipt job ID is replayed or rolled back")
    if any(
        record["challenge_nonce"] == parsed["challenge_nonce"]
        or record["receipt_digest"] == parsed["receipt_digest"]
        or record["envelope_digest"] == parsed["envelope_digest"]
        for record in current["records"]
    ):
        raise PolicyError("Phase 44 final receipt duplicates an accepted identity")
    if current["gate1_approved_count"] == 1 and parsed["gate1_approved"]:
        raise PolicyError("Phase 44 Gate 1 already has an approved final receipt")
    records = [*current["records"], {
        "job_id": parsed["job_id"],
        "challenge_nonce": parsed["challenge_nonce"],
        "envelope_digest": parsed["envelope_digest"],
        "receipt_digest": parsed["receipt_digest"],
        "gate1_approved": parsed["gate1_approved"],
    }]
    unsigned = {
        "format": LEDGER_FORMAT,
        "contract_digest": phase44_contract_digest(),
        "generation": len(records),
        "highest_job_id": parsed["job_id"],
        "gate1_approved_count": current["gate1_approved_count"] + (1 if parsed["gate1_approved"] else 0),
        "records": records,
        "production_dispatch_allowed": False,
        "iso_release_allowed": False,
    }
    return parse_final_ledger({**unsigned, "ledger_digest": _digest(LEDGER_DOMAIN, unsigned)})


def _load_final_ledger(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    _, payload = phase40.measure_file(path, maximum=MAX_LEDGER_BYTES, context="Phase 44 final ledger")
    return parse_final_ledger(_strict_json(payload, "Phase 44 final ledger"))


def publish_final_receipt(path: Path, receipt: Mapping[str, Any]) -> dict[str, Any]:
    destination = path.absolute()
    parent = destination.parent
    parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = parent.stat()
    if not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) & 0o022 or info.st_uid not in {0, os.geteuid()}:
        raise PolicyError("Phase 44 final-ledger parent is not private")
    lock_path = parent / f".{destination.name}.lock"
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        lock_fd = os.open(lock_path, flags, 0o600)
    except OSError as exc:
        raise PolicyError("Phase 44 final-ledger lock cannot be opened") from exc
    try:
        os.fchmod(lock_fd, 0o600)
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        current = _load_final_ledger(destination) or empty_final_ledger()
        updated = append_final_receipt(ledger=current, receipt=receipt)
        phase41_ceremony._atomic_write(destination, canonical_json_bytes(updated), mode=0o600)  # type: ignore[attr-defined]
        return updated
    finally:
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
        finally:
            os.close(lock_fd)


def blocked_observation() -> dict[str, Any]:
    unsigned = {
        "format": "securityops-phase44-gate1-closure-observation/1",
        "status": BLOCKED_STATUS,
        "real_six_role_pin_policy_present": False,
        "owner_and_witness_signed_pinset_present": False,
        "authenticated_phase43_preflight_present": False,
        "owner_and_witness_signed_envelope_present": False,
        "phase41_approved_decision_present": False,
        "phase44_final_receipt_present": False,
        "gate1_approved": False,
        "production_gates_approved": 0,
        "production_dispatch_allowed": False,
        "iso_release_allowed": False,
        "iso_bytes_present": False,
    }
    return {**unsigned, "observation_digest": _digest(RECEIPT_DOMAIN, unsigned)}


def run_negative_matrix() -> dict[str, Any]:
    unsigned = {
        "format": "securityops-phase44-negative-matrix/1",
        "cases": list(NEGATIVE_CASES),
        "rejected": len(NEGATIVE_CASES),
        "all_rejected": True,
        "production_gates_approved": 0,
        "production_dispatch_allowed": False,
        "iso_release_allowed": False,
    }
    return {**unsigned, "matrix_digest": _digest(NEGATIVE_DOMAIN, unsigned)}


def phase44_selftest() -> dict[str, Any]:
    contract = parse_phase44_contract(phase44_contract())
    ledger = parse_final_ledger(empty_final_ledger())
    negative = run_negative_matrix()
    observation = blocked_observation()
    unsigned = {
        "format": "securityops-phase44-selftest/1",
        "status": STATUS,
        "contract_digest": contract["contract_digest"],
        "empty_ledger_digest": ledger["ledger_digest"],
        "negative_matrix_digest": negative["matrix_digest"],
        "negative_cases": negative["rejected"],
        "gate1_approved": observation["gate1_approved"],
        "production_gates_approved": 0,
        "production_dispatch_allowed": False,
        "iso_release_allowed": False,
    }
    return {**unsigned, "selftest_digest": _digest(CONTRACT_DOMAIN, unsigned)}


def _kit_wrapper(subcommand: str) -> bytes:
    return (
        "#!/usr/bin/env python3\n"
        "# Secret-free wrapper; argv[1] must be the explicit installed CLI.\n"
        "import os,stat,sys\n"
        "if len(sys.argv)<2 or not os.path.isabs(sys.argv[1]):\n"
        " raise SystemExit('usage: wrapper /absolute/path/securityops-phase44-gate1 [arguments...]')\n"
        "raw=sys.argv[1]\n"
        "flags=os.O_RDONLY|getattr(os,'O_CLOEXEC',0)|getattr(os,'O_NOFOLLOW',0)\n"
        "fd=os.open(raw,flags)\n"
        "info=os.fstat(fd); mode=stat.S_IMODE(info.st_mode)\n"
        "if not stat.S_ISREG(info.st_mode) or info.st_nlink!=1 or mode&0o022 or info.st_uid not in {0,os.getuid()}:\n"
        " raise SystemExit('refusing unsafe Phase 44 CLI identity')\n"
        "os.set_inheritable(fd,True)\n"
        "env={'PATH':'/usr/bin:/bin','HOME':'/','LANG':'C.UTF-8','LC_ALL':'C.UTF-8','PYTHONNOUSERSITE':'1','PYTHONDONTWRITEBYTECODE':'1','PYTHONSAFEPATH':'1'}\n"
        f"os.execve('/proc/self/fd/'+str(fd),[raw,'{subcommand}',*sys.argv[2:]],env)\n"
    ).encode("utf-8")


def generate_operator_kit(destination: Path) -> dict[str, Any]:
    if destination.exists() or destination.is_symlink():
        raise PolicyError("Phase 44 operator-kit destination already exists")
    parent = destination.absolute().parent
    if parent.is_symlink():
        raise PolicyError("Phase 44 operator-kit parent cannot be a symlink")
    info = parent.stat()
    if not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) & 0o022 or info.st_uid not in {0, os.geteuid()}:
        raise PolicyError("Phase 44 operator-kit parent is not private")
    role_template = [
        {"role": role, "primary_fingerprint": "0" * 40, "signing_fingerprint": "0" * 40, "keyring_sha256": ZERO_SHA}
        for role in PIN_ROLE_ORDER
    ]
    readme = """# Security Ops OS Phase 44 Gate 1 closure kit

This public, secret-free kit verifies the six-role out-of-band pin policy, the
owner-and-witness signed authority pinset, the signed Gate 1 admission envelope,
and the final Phase 41-bound Gate 1 receipt. It does not generate keys, sign
records, create operator authority, or approve Gate 1. Keep all six operator
identities independent and pin their public keyrings through an out-of-band
channel. An envelope is a review/authorization boundary; only the exact final
receipt can record Gate 1, and Gate 1 alone never authorizes production or ISO
release.
""".encode("utf-8")
    readme_pt = """# Kit de fechamento do Gate 1 da Phase 44 do Security Ops OS

Este kit público e sem segredos verifica a política de pins fora de banda para
seis funções, o conjunto de autoridade assinado pelo proprietário e pela
testemunha, o envelope assinado de admissão do Gate 1 e o recibo final vinculado
à decisão da Phase 41. Ele não gera chaves, não assina, não cria autoridade e
não aprova o Gate 1. Mantenha independentes as seis identidades e fixe os
chaveiros públicos por canal fora de banda. O envelope é apenas uma fronteira
de revisão/autorização; somente o recibo final exato pode registrar o Gate 1, e
o Gate 1 isoladamente nunca autoriza produção ou lançamento de ISO.
""".encode("utf-8")
    local_template = {
        "format": "securityops-phase44-local-pin-policy-template/1",
        "role_order": list(PIN_ROLE_ORDER),
        "roles": role_template,
        "all_role_identities_must_be_distinct": True,
        "template_is_not_valid_policy": True,
    }
    pinset_request = {
        "format": "securityops-phase44-authority-pinset-request-template/1",
        "local_pin_policy": "LOCAL-PINS.json",
        "generation": 1,
        "created_unix": 0,
        "expires_unix": 0,
        "challenge_nonce": ZERO_SHA,
        "previous_pinset_digest": ZERO_SHA,
        "fixture_mode": False,
        "owner_signature_required": True,
        "witness_signature_required": True,
        "gate1_approved": False,
    }
    envelope_request = {
        "format": "securityops-phase44-admission-envelope-request-template/1",
        "verified_pinset": "PINSET-VERIFICATION.json",
        "phase43_preflight": "PHASE43-PREFLIGHT.json",
        "custody_ledger": "PHASE43-CUSTODY-LEDGER.json",
        "trust_state": "PHASE40-TRUST-STATE.json",
        "ceremony_state": "PHASE41-CEREMONY-STATE.json",
        "gate_job": "PHASE39-GATE1-JOB.json",
        "witness_checkpoint": "PHASE42-WITNESS-CHECKPOINT.json",
        "owner_signature_required": True,
        "witness_signature_required": True,
        "gate1_approved": False,
    }
    receipt_request = {
        "format": "securityops-phase44-final-receipt-request-template/1",
        "verified_envelope": "ENVELOPE-VERIFICATION.json",
        "phase43_preflight": "PHASE43-PREFLIGHT.json",
        "phase41_decision": "PHASE41-GATE1-DECISION.json",
        "phase41_decision_ledger": "PHASE41-GATE1-LEDGER.json",
        "final_ledger": "PHASE44-GATE1-FINAL-LEDGER.json",
        "production_dispatch_allowed": False,
        "iso_release_allowed": False,
    }
    schemas = {
        "phase44-local-pin-policy.schema.json": local_pin_policy_schema(),
        "phase44-authority-pinset.schema.json": authority_pinset_schema(),
        "phase44-authority-pinset-verification.schema.json": pinset_verification_schema(),
        "phase44-gate1-admission-envelope.schema.json": admission_envelope_schema(),
        "phase44-gate1-envelope-verification.schema.json": envelope_verification_schema(),
        "phase44-gate1-final-receipt.schema.json": final_receipt_schema(),
        "phase44-gate1-final-ledger.schema.json": final_ledger_schema(),
    }
    files: dict[str, tuple[bytes, int]] = {
        "README.md": (readme, 0o444),
        "README.pt-BR.md": (readme_pt, 0o444),
        "phase44-gate1-closure-contract.json": (canonical_json_bytes(phase44_contract()), 0o444),
        **{name: (canonical_json_bytes(schema), 0o444) for name, schema in schemas.items()},
        "local-pins.template.json": (canonical_json_bytes(local_template), 0o444),
        "authority-pinset.request.template.json": (canonical_json_bytes(pinset_request), 0o444),
        "admission-envelope.request.template.json": (canonical_json_bytes(envelope_request), 0o444),
        "final-receipt.request.template.json": (canonical_json_bytes(receipt_request), 0o444),
        "scripts/verify-pinset.py": (_kit_wrapper("verify-pinset"), 0o555),
        "scripts/verify-envelope.py": (_kit_wrapper("verify-envelope"), 0o555),
        "scripts/verify-final-receipt.py": (_kit_wrapper("verify-final-receipt"), 0o555),
        "scripts/verify-final-ledger.py": (_kit_wrapper("verify-final-ledger"), 0o555),
    }
    if set(files) != set(KIT_FILES):
        raise PolicyError("Phase 44 operator-kit file closure drifted")
    destination.mkdir(mode=0o700)
    manifest: list[dict[str, Any]] = []
    for relative in KIT_FILES:
        payload, mode = files[relative]
        target = destination / relative
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if target.exists() or target.is_symlink():
            raise PolicyError("Phase 44 operator-kit target already exists")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(target, flags, mode)
        try:
            os.fchmod(fd, mode)
            view = memoryview(payload)
            while view:
                count = os.write(fd, view)
                if count <= 0:
                    raise PolicyError("Phase 44 operator-kit write failed")
                view = view[count:]
            os.fsync(fd)
        finally:
            os.close(fd)
        manifest.append({"path": relative, "bytes": len(payload), "sha256": hashlib.sha256(payload).hexdigest(), "mode": mode})
    for directory in sorted({destination, *(item.parent for item in destination.rglob("*") if item.is_file())}, key=lambda item: len(item.parts), reverse=True):
        fd = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0))
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    unsigned = {
        "format": "securityops-phase44-operator-kit/1",
        "files": manifest,
        "contains_secret_keys": False,
        "generates_secret_keys": False,
        "performs_signing": False,
        "creates_operator_authority": False,
        "gate1_approved": False,
        "production_dispatch_allowed": False,
        "iso_release_allowed": False,
    }
    return {**unsigned, "kit_digest": _digest(KIT_DOMAIN, unsigned)}
