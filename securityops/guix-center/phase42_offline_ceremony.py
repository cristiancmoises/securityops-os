# CodeMark v1 project=4c63e0fe-589c-4944-8449-97e211a38b72 file=6a7c0759ece35194aa59bb93275d6dae owner="Cristian Cezar Mois\u00e9s"
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Phase 42 witnessed offline ceremony, checkpoint, and transcript boundary.

Phase 42 turns the Phase 41 owner lifecycle into an operator-safe offline
workflow.  It adds deterministic media packages, an independently signed
witness checkpoint chain, externally anchored recovery, and a dual-signed
ceremony transcript.  None of these transport or transcript artifacts can
close Gate 1 without the complete inherited non-fixture Phase 39-41 chain.
"""
from __future__ import annotations

from dataclasses import dataclass
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import tempfile
from typing import Any, Final, Mapping, Sequence

try:
    from . import phase39_owner_execution as phase39
    from . import phase40_owner_trust as phase40
    from . import phase41_owner_ceremony as phase41
    from . import phase41_gate1_execution as phase41_gate1
    from . import phase42_media as media
except ImportError:  # pragma: no cover - installed Guix Center copy
    import phase39_owner_execution as phase39  # type: ignore[no-redef]
    import phase40_owner_trust as phase40  # type: ignore[no-redef]
    import phase41_owner_ceremony as phase41  # type: ignore[no-redef]
    import phase41_gate1_execution as phase41_gate1  # type: ignore[no-redef]
    import phase42_media as media  # type: ignore[no-redef]

PolicyError = phase40.PolicyError
canonical_json_bytes = phase40.canonical_json_bytes

CONTRACT_FORMAT: Final[str] = "securityops-phase42-offline-ceremony-contract/1"
CHECKPOINT_FORMAT: Final[str] = "securityops-phase42-witness-checkpoint/1"
CHECKPOINT_VERIFICATION_FORMAT: Final[str] = "securityops-phase42-witness-checkpoint-verification/1"
LEDGER_FORMAT: Final[str] = "securityops-phase42-witness-ledger/1"
RECOVERY_FORMAT: Final[str] = "securityops-phase42-witnessed-recovery/1"
TRANSCRIPT_FORMAT: Final[str] = "securityops-phase42-ceremony-transcript/1"
TRANSCRIPT_VERIFICATION_FORMAT: Final[str] = "securityops-phase42-ceremony-transcript-verification/1"
KIT_FORMAT: Final[str] = "securityops-phase42-offline-operator-kit/1"
STATUS: Final[str] = "PASS_PHASE42_OFFLINE_MEDIA_WITNESS_TRANSCRIPT_BOUNDARY"
BLOCKED_STATUS: Final[str] = "BLOCKED_PHASE42_REAL_OWNER_INPUTS_AND_GATE1_EXCHANGE_REQUIRED"

CONTRACT_DOMAIN: Final[bytes] = b"SECURITYOPS-PHASE42-OFFLINE-CEREMONY-CONTRACT-V1\x00"
CHECKPOINT_DOMAIN: Final[bytes] = b"SECURITYOPS-PHASE42-WITNESS-CHECKPOINT-V1\x00"
CHECKPOINT_VERIFICATION_DOMAIN: Final[bytes] = b"SECURITYOPS-PHASE42-WITNESS-VERIFICATION-V1\x00"
LEDGER_DOMAIN: Final[bytes] = b"SECURITYOPS-PHASE42-WITNESS-LEDGER-V1\x00"
RECOVERY_DOMAIN: Final[bytes] = b"SECURITYOPS-PHASE42-WITNESSED-RECOVERY-V1\x00"
TRANSCRIPT_DOMAIN: Final[bytes] = b"SECURITYOPS-PHASE42-CEREMONY-TRANSCRIPT-V1\x00"
TRANSCRIPT_VERIFICATION_DOMAIN: Final[bytes] = b"SECURITYOPS-PHASE42-TRANSCRIPT-VERIFICATION-V1\x00"
KIT_DOMAIN: Final[bytes] = b"SECURITYOPS-PHASE42-OFFLINE-KIT-V1\x00"
OBSERVATION_DOMAIN: Final[bytes] = b"SECURITYOPS-PHASE42-OBSERVATION-V1\x00"

PHASE41_IDENTITIES: Final[dict[str, str]] = dict(media.PHASE41_IDENTITIES)
PHASE41_CEREMONY_CONTRACT_DIGEST: Final[str] = media.PHASE41_CEREMONY_CONTRACT_DIGEST
PHASE41_GATE1_CONTRACT_DIGEST: Final[str] = media.PHASE41_GATE1_CONTRACT_DIGEST
PHASE40_OWNER_CONTRACT_DIGEST: Final[str] = phase41.PHASE40_OWNER_CONTRACT_DIGEST
PHASE40_GATE1_CONTRACT_DIGEST: Final[str] = phase41.PHASE40_GATE1_CONTRACT_DIGEST
PHASE39_CONTRACT_DIGEST: Final[str] = phase41.PHASE39_CONTRACT_DIGEST

ZERO_SHA: Final[str] = "0" * 64
ZERO_FINGERPRINT: Final[str] = "0" * 40
MAX_CHECKPOINT_BYTES: Final[int] = 4 * 1024 * 1024
MAX_TRANSCRIPT_BYTES: Final[int] = 16 * 1024 * 1024
MAX_LEDGER_BYTES: Final[int] = 32 * 1024 * 1024
MAX_LEDGER_RECORDS: Final[int] = 4096
MAX_TRANSCRIPT_RECORDS: Final[int] = 4096
MAX_TRANSCRIPT_MEDIA: Final[int] = 4096
MAX_LIFETIME: Final[int] = 30 * 24 * 60 * 60

_SHA = re.compile(r"[0-9a-f]{64}\Z")
_FPR = re.compile(r"[0-9A-F]{40}\Z")
_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")

NEGATIVE_CASES: Final[tuple[str, ...]] = (
    "extra-contract-field",
    "phase41-runtime-identity-drift",
    "phase41-os-identity-drift",
    "phase41-ceremony-contract-drift",
    "phase41-gate1-contract-drift",
    "media-profile-removed",
    "media-ready-marker-disabled",
    "media-rename-noreplace-disabled",
    "media-overwrite-enabled",
    "media-deterministic-chunking-disabled",
    "media-deterministic-placement-disabled",
    "media-stable-filename-disabled",
    "media-descriptor-relative-open-disabled",
    "media-hardlinks-enabled",
    "witness-may-equal-owner",
    "witness-may-equal-build-node",
    "witness-keyring-may-alias-owner",
    "witness-original-path-reopened",
    "witness-checkpoint-not-monotonic",
    "witness-checkpoint-not-challenge-bound",
    "witness-checkpoint-not-store-bound",
    "witness-ledger-replay-enabled",
    "witness-ledger-equivocation-enabled",
    "recovery-without-external-witness",
    "fixture-witness-can-authorize-recovery",
    "quarantine-cleared-by-recovery",
    "transcript-without-transition-signatures",
    "transcript-without-owner-signature",
    "transcript-without-witness-signature",
    "transcript-alone-closes-gate1",
    "transcript-fixture-promotes-owner",
    "gate1-without-phase39-exchange",
    "gate1-without-phase40-semantic-receipt",
    "gate1-without-phase41-decision",
    "transport-is-publisher-admission",
    "capability-discovery-is-execution",
    "production-promotion",
    "iso-promotion",
)

KIT_FILES: Final[tuple[str, ...]] = (
    "README.md",
    "README.pt-BR.md",
    "phase42-offline-ceremony-contract.json",
    "phase42-offline-media-manifest.schema.json",
    "phase42-offline-media-ready.schema.json",
    "phase42-offline-media-review.schema.json",
    "phase42-witness-checkpoint.schema.json",
    "phase42-witness-ledger.schema.json",
    "phase42-ceremony-transcript.schema.json",
    "initialize-media.request.template.json",
    "rotation-media.request.template.json",
    "checkpoint-media.request.template.json",
    "gate1-media.request.template.json",
    "transcript-media.request.template.json",
    "witness-checkpoint.request.template.json",
    "transcript.request.template.json",
    "scripts/export-media.py",
    "scripts/import-media.py",
    "scripts/verify-witness.py",
    "scripts/verify-transcript.py",
)


def _digest(domain: bytes, value: Mapping[str, Any]) -> str:
    return hashlib.sha256(domain + canonical_json_bytes(value)).hexdigest()


def _sha(value: Any, context: str, *, allow_zero: bool = False) -> str:
    if not isinstance(value, str) or not _SHA.fullmatch(value):
        raise PolicyError(f"{context} must be a lowercase SHA-256 digest")
    if not allow_zero and value == ZERO_SHA:
        raise PolicyError(f"{context} cannot be the zero digest")
    return value


def _fpr(value: Any, context: str, *, allow_zero: bool = False) -> str:
    if not isinstance(value, str) or not _FPR.fullmatch(value):
        raise PolicyError(f"{context} must be an uppercase OpenPGP fingerprint")
    if not allow_zero and value == ZERO_FINGERPRINT:
        raise PolicyError(f"{context} cannot be the zero fingerprint")
    return value


def _token(value: Any, context: str) -> str:
    if not isinstance(value, str) or not _TOKEN.fullmatch(value):
        raise PolicyError(f"{context} is invalid")
    return value


def _strict_json(payload: bytes, context: str) -> dict[str, Any]:
    duplicates: list[str] = []

    def hook(items: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in items:
            if key in value:
                duplicates.append(key)
            value[key] = item
        return value

    def constant(value: str) -> None:
        raise PolicyError(f"{context} contains non-finite value {value}")

    try:
        value = json.loads(
            payload.decode("utf-8", errors="strict"),
            object_pairs_hook=hook,
            parse_constant=constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PolicyError(f"{context} is not strict UTF-8 JSON") from exc
    if duplicates or type(value) is not dict:
        raise PolicyError(f"{context} has duplicate fields or is not an object")
    return value


def checkpoint_schema() -> dict[str, Any]:
    sha = {"type": "string", "pattern": "^[0-9a-f]{64}$"}
    fpr = {"type": "string", "pattern": "^[0-9A-F]{40}$"}
    required = [
        "format", "contract_digest", "phase41_ceremony_contract_digest",
        "phase41_gate1_contract_digest", "sequence", "created_unix",
        "expires_unix", "challenge_nonce", "witness_id",
        "witness_primary_fingerprint", "witness_signing_fingerprint",
        "witness_keyring_sha256", "owner_signing_fingerprint",
        "owner_keyring_sha256", "build_node_signing_fingerprint",
        "build_node_keyring_sha256", "ceremony_state_digest",
        "ceremony_store_digest", "trust_state_digest", "trust_generation",
        "previous_checkpoint_digest", "media_package_digest", "fixture_mode",
        "owner_state_authenticated", "checkpoint_signature_present",
        "witness_authenticated", "recovery_authorized", "gate1_approved",
        "production_gates_approved", "production_dispatch_allowed",
        "iso_release_allowed", "checkpoint_digest",
    ]
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://securityops.co/schemas/guix-center/phase42-witness-checkpoint.schema.json",
        "title": "Security Ops Phase 42 independent witness checkpoint",
        "type": "object", "additionalProperties": False,
        "required": required,
        "properties": {
            "format": {"const": CHECKPOINT_FORMAT},
            "contract_digest": sha,
            "phase41_ceremony_contract_digest": sha,
            "phase41_gate1_contract_digest": sha,
            "sequence": {"type": "integer", "minimum": 1},
            "created_unix": {"type": "integer", "minimum": 1},
            "expires_unix": {"type": "integer", "minimum": 1},
            "challenge_nonce": sha,
            "witness_id": {"type": "string", "minLength": 1, "maxLength": 128},
            "witness_primary_fingerprint": fpr,
            "witness_signing_fingerprint": fpr,
            "witness_keyring_sha256": sha,
            "owner_signing_fingerprint": fpr,
            "owner_keyring_sha256": sha,
            "build_node_signing_fingerprint": fpr,
            "build_node_keyring_sha256": sha,
            "ceremony_state_digest": sha,
            "ceremony_store_digest": sha,
            "trust_state_digest": sha,
            "trust_generation": {"type": "integer", "minimum": 1},
            "previous_checkpoint_digest": sha,
            "media_package_digest": sha,
            "fixture_mode": {"type": "boolean"},
            "owner_state_authenticated": {"type": "boolean"},
            "checkpoint_signature_present": {"const": False},
            "witness_authenticated": {"const": False},
            "recovery_authorized": {"const": False},
            "gate1_approved": {"const": False},
            "production_gates_approved": {"const": 0},
            "production_dispatch_allowed": {"const": False},
            "iso_release_allowed": {"const": False},
            "checkpoint_digest": sha,
        },
    }


def witness_ledger_schema() -> dict[str, Any]:
    sha = {"type": "string", "pattern": "^[0-9a-f]{64}$"}
    record = {
        "type": "object", "additionalProperties": False,
        "required": [
            "sequence", "checkpoint_digest", "verification_digest",
            "previous_checkpoint_digest", "ceremony_state_digest",
            "ceremony_store_digest", "trust_state_digest",
            "witness_signing_fingerprint", "witness_authenticated", "fixture_mode",
        ],
        "properties": {
            "sequence": {"type": "integer", "minimum": 1},
            "checkpoint_digest": sha,
            "verification_digest": sha,
            "previous_checkpoint_digest": sha,
            "ceremony_state_digest": sha,
            "ceremony_store_digest": sha,
            "trust_state_digest": sha,
            "witness_signing_fingerprint": {"type": "string", "pattern": "^[0-9A-F]{40}$"},
            "witness_authenticated": {"type": "boolean"},
            "fixture_mode": {"type": "boolean"},
        },
    }
    required = [
        "format", "contract_digest", "generation", "highest_sequence",
        "current_checkpoint_digest", "records", "fixture_mode",
        "witness_chain_authenticated", "recovery_authorized",
        "production_gates_approved", "production_dispatch_allowed",
        "iso_release_allowed", "ledger_digest",
    ]
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://securityops.co/schemas/guix-center/phase42-witness-ledger.schema.json",
        "title": "Security Ops Phase 42 monotonic witness ledger",
        "type": "object", "additionalProperties": False,
        "required": required,
        "properties": {
            "format": {"const": LEDGER_FORMAT},
            "contract_digest": sha,
            "generation": {"type": "integer", "minimum": 0},
            "highest_sequence": {"type": "integer", "minimum": 0},
            "current_checkpoint_digest": sha,
            "records": {"type": "array", "maxItems": MAX_LEDGER_RECORDS, "items": record},
            "fixture_mode": {"type": "boolean"},
            "witness_chain_authenticated": {"type": "boolean"},
            "recovery_authorized": {"type": "boolean"},
            "production_gates_approved": {"const": 0},
            "production_dispatch_allowed": {"const": False},
            "iso_release_allowed": {"const": False},
            "ledger_digest": sha,
        },
    }


def transcript_schema() -> dict[str, Any]:
    sha = {"type": "string", "pattern": "^[0-9a-f]{64}$"}
    fpr = {"type": "string", "pattern": "^[0-9A-F]{40}$"}
    transition = {
        "type": "object", "additionalProperties": False,
        "required": [
            "sequence", "transition_type", "transition_digest",
            "verification_digest", "previous_ceremony_state_digest",
            "ceremony_state_digest", "signatures_verified",
            "owner_authenticated", "fixture_mode",
        ],
        "properties": {
            "sequence": {"type": "integer", "minimum": 1},
            "transition_type": {"enum": list(phase41.TRANSITION_TYPES)},
            "transition_digest": sha,
            "verification_digest": sha,
            "previous_ceremony_state_digest": sha,
            "ceremony_state_digest": sha,
            "signatures_verified": {"const": True},
            "owner_authenticated": {"type": "boolean"},
            "fixture_mode": {"type": "boolean"},
        },
    }
    required = [
        "format", "contract_digest", "transcript_id", "created_unix",
        "challenge_nonce", "transition_count", "transitions",
        "initial_ceremony_state_digest", "final_ceremony_state_digest",
        "final_ceremony_store_digest", "final_trust_state_digest",
        "witness_checkpoint_digest", "witness_verification_digest",
        "media_package_digests", "owner_signing_fingerprint",
        "owner_keyring_sha256", "witness_signing_fingerprint",
        "witness_keyring_sha256", "all_transition_signatures_verified",
        "owner_authenticated", "witness_authenticated", "fixture_mode",
        "transcript_signature_present", "transcript_alone_can_close_gate1",
        "gate1_approved", "production_gates_approved",
        "production_dispatch_allowed", "iso_release_allowed", "transcript_digest",
    ]
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://securityops.co/schemas/guix-center/phase42-ceremony-transcript.schema.json",
        "title": "Security Ops Phase 42 witnessed ceremony transcript",
        "type": "object", "additionalProperties": False,
        "required": required,
        "properties": {
            "format": {"const": TRANSCRIPT_FORMAT},
            "contract_digest": sha,
            "transcript_id": {"type": "string", "minLength": 1, "maxLength": 128},
            "created_unix": {"type": "integer", "minimum": 1},
            "challenge_nonce": sha,
            "transition_count": {"type": "integer", "minimum": 1, "maximum": MAX_TRANSCRIPT_RECORDS},
            "transitions": {"type": "array", "minItems": 1, "maxItems": MAX_TRANSCRIPT_RECORDS, "items": transition},
            "initial_ceremony_state_digest": sha,
            "final_ceremony_state_digest": sha,
            "final_ceremony_store_digest": sha,
            "final_trust_state_digest": sha,
            "witness_checkpoint_digest": sha,
            "witness_verification_digest": sha,
            "media_package_digests": {"type": "array", "minItems": 1, "maxItems": MAX_TRANSCRIPT_MEDIA, "items": sha},
            "owner_signing_fingerprint": fpr,
            "owner_keyring_sha256": sha,
            "witness_signing_fingerprint": fpr,
            "witness_keyring_sha256": sha,
            "all_transition_signatures_verified": {"const": True},
            "owner_authenticated": {"type": "boolean"},
            "witness_authenticated": {"type": "boolean"},
            "fixture_mode": {"type": "boolean"},
            "transcript_signature_present": {"const": False},
            "transcript_alone_can_close_gate1": {"const": False},
            "gate1_approved": {"const": False},
            "production_gates_approved": {"const": 0},
            "production_dispatch_allowed": {"const": False},
            "iso_release_allowed": {"const": False},
            "transcript_digest": sha,
        },
    }


def _contract_unsigned() -> dict[str, Any]:
    schemas = {
        "media_manifest": media.manifest_schema(),
        "media_ready": media.ready_schema(),
        "media_review": media.review_schema(),
        "witness_checkpoint": checkpoint_schema(),
        "witness_ledger": witness_ledger_schema(),
        "ceremony_transcript": transcript_schema(),
    }
    return {
        "format": CONTRACT_FORMAT,
        "status": STATUS,
        "phase41_identities": dict(PHASE41_IDENTITIES),
        "phase41_ceremony_contract_digest": PHASE41_CEREMONY_CONTRACT_DIGEST,
        "phase41_gate1_contract_digest": PHASE41_GATE1_CONTRACT_DIGEST,
        "phase40_owner_contract_digest": PHASE40_OWNER_CONTRACT_DIGEST,
        "phase40_gate1_contract_digest": PHASE40_GATE1_CONTRACT_DIGEST,
        "phase39_contract_digest": PHASE39_CONTRACT_DIGEST,
        "schemas": {
            role: {
                "id": value["$id"],
                "canonical_sha256": hashlib.sha256(canonical_json_bytes(value)).hexdigest(),
            }
            for role, value in schemas.items()
        } | {"additional_properties_allowed": False},
        "media_policy": media.media_policy_fragment(),
        "witness_policy": {
            "independent_identity_required": True,
            "witness_must_differ_from_owner": True,
            "witness_must_differ_from_build_node": True,
            "witness_keyring_must_differ_from_owner_and_build_node": True,
            "locally_pinned_fingerprint_required": True,
            "locally_pinned_keyring_sha256_required": True,
            "verification_uses_kernel_sealed_memfd": True,
            "original_paths_reopened_after_measurement": False,
            "checkpoint_binds_challenge": True,
            "checkpoint_binds_ceremony_state": True,
            "checkpoint_binds_ceremony_store": True,
            "checkpoint_binds_trust_state": True,
            "checkpoint_binds_media_package": True,
            "checkpoint_chain_is_monotonic": True,
            "ledger_replay_rejected": True,
            "ledger_rollback_rejected": True,
            "ledger_equivocation_rejected": True,
            "fixture_witness_can_authorize_production_recovery": False,
            "recovery_requires_external_verified_checkpoint": True,
            "recovery_cannot_clear_quarantine": True,
        },
        "transcript_policy": {
            "all_transition_signatures_required": True,
            "owner_signature_required": True,
            "independent_witness_signature_required": True,
            "exact_local_keyring_pins_required": True,
            "media_package_digest_inventory_required": True,
            "final_store_state_trust_and_witness_binding_required": True,
            "transcript_alone_can_close_gate1": False,
            "fixture_transcript_can_authenticate_owner": False,
            "signed_transcript_without_phase39_phase40_phase41_chain_can_close_gate1": False,
        },
        "gate1_truth_boundary": {
            "real_owner_pins_required": True,
            "authenticated_35_artifact_closure_required": True,
            "phase39_dual_signed_exchange_required": True,
            "phase40_semantic_admission_required": True,
            "phase41_monotonic_decision_required": True,
            "phase42_media_integrity_is_additional_transport_evidence_only": True,
            "phase42_witness_transcript_is_gate1_by_itself": False,
        },
        "network_fetch_allowed": False,
        "production_gates_approved": 0,
        "production_dispatch_allowed": False,
        "iso_release_allowed": False,
        "execution_status": BLOCKED_STATUS,
    }


def offline_ceremony_contract() -> dict[str, Any]:
    unsigned = _contract_unsigned()
    return {**unsigned, "contract_digest": _digest(CONTRACT_DOMAIN, unsigned)}


def offline_ceremony_contract_digest() -> str:
    return offline_ceremony_contract()["contract_digest"]


def parse_offline_ceremony_contract(value: Mapping[str, Any]) -> dict[str, Any]:
    if type(value) is not dict or value != offline_ceremony_contract():
        raise PolicyError("Phase 42 offline ceremony contract differs from policy")
    return json.loads(canonical_json_bytes(value))


def create_witness_checkpoint(
    *,
    witness_id: str,
    witness_primary_fingerprint: str,
    witness_signing_fingerprint: str,
    witness_keyring_sha256: str,
    sequence: int,
    created_unix: int,
    expires_unix: int,
    challenge_nonce: str,
    ceremony_state: Mapping[str, Any],
    ceremony_store: Mapping[str, Any],
    trust_state: Mapping[str, Any],
    previous_checkpoint_digest: str,
    media_package_digest: str,
    fixture_mode: bool,
) -> dict[str, Any]:
    state = phase41.parse_ceremony_state(ceremony_state)
    store = phase41.parse_ceremony_store(ceremony_store)
    trust = phase40.parse_trust_state(trust_state)
    witness_id = _token(witness_id, "Phase 42 witness ID")
    witness_primary = _fpr(witness_primary_fingerprint, "Phase 42 witness primary fingerprint")
    witness_signing = _fpr(witness_signing_fingerprint, "Phase 42 witness signing fingerprint")
    witness_keyring = _sha(witness_keyring_sha256, "Phase 42 witness keyring")
    challenge = _sha(challenge_nonce, "Phase 42 witness challenge")
    media_digest = _sha(media_package_digest, "Phase 42 media package")
    previous = _sha(
        previous_checkpoint_digest,
        "Phase 42 previous witness checkpoint",
        allow_zero=(sequence == 1),
    )
    if type(sequence) is not int or sequence < 1:
        raise PolicyError("Phase 42 witness sequence is invalid")
    if sequence == 1 and previous != ZERO_SHA:
        raise PolicyError("Phase 42 first witness checkpoint must use zero previous digest")
    if sequence > 1 and previous == ZERO_SHA:
        raise PolicyError("Phase 42 later witness checkpoint requires a previous digest")
    if (
        type(created_unix) is not int or type(expires_unix) is not int
        or created_unix < 1 or not created_unix < expires_unix
        or expires_unix > created_unix + MAX_LIFETIME
    ):
        raise PolicyError("Phase 42 witness checkpoint lifetime is invalid")
    if type(fixture_mode) is not bool:
        raise PolicyError("Phase 42 witness fixture state is invalid")
    if state["sequence"] != sequence or store["highest_sequence"] != sequence:
        raise PolicyError("Phase 42 witness sequence does not bind the ceremony store")
    if store["current_state"]["state_digest"] != state["state_digest"]:
        raise PolicyError("Phase 42 witness store does not contain the supplied ceremony state")
    if state["trust_state_digest"] != trust["state_digest"]:
        raise PolicyError("Phase 42 witness state does not bind the supplied trust state")
    if state["trust_generation"] != trust["generation"]:
        raise PolicyError("Phase 42 witness trust generation drifted")
    if fixture_mode != bool(state["fixture_mode"] or trust["fixture_mode"]):
        raise PolicyError("Phase 42 witness fixture state differs from owner state")
    if witness_primary in {
        state["owner_signing_fingerprint"], state["build_node_signing_fingerprint"]
    } or witness_signing in {
        state["owner_signing_fingerprint"], state["build_node_signing_fingerprint"]
    }:
        raise PolicyError("Phase 42 witness identity is not independent")
    if witness_keyring in {
        state["owner_keyring_sha256"], state["build_node_keyring_sha256"]
    }:
        raise PolicyError("Phase 42 witness keyring is not independent")
    owner_authenticated = bool(state["owner_trust_authenticated"] and not fixture_mode)
    unsigned: dict[str, Any] = {
        "format": CHECKPOINT_FORMAT,
        "contract_digest": offline_ceremony_contract_digest(),
        "phase41_ceremony_contract_digest": PHASE41_CEREMONY_CONTRACT_DIGEST,
        "phase41_gate1_contract_digest": PHASE41_GATE1_CONTRACT_DIGEST,
        "sequence": sequence,
        "created_unix": created_unix,
        "expires_unix": expires_unix,
        "challenge_nonce": challenge,
        "witness_id": witness_id,
        "witness_primary_fingerprint": witness_primary,
        "witness_signing_fingerprint": witness_signing,
        "witness_keyring_sha256": witness_keyring,
        "owner_signing_fingerprint": state["owner_signing_fingerprint"],
        "owner_keyring_sha256": state["owner_keyring_sha256"],
        "build_node_signing_fingerprint": state["build_node_signing_fingerprint"],
        "build_node_keyring_sha256": state["build_node_keyring_sha256"],
        "ceremony_state_digest": state["state_digest"],
        "ceremony_store_digest": store["store_digest"],
        "trust_state_digest": trust["state_digest"],
        "trust_generation": trust["generation"],
        "previous_checkpoint_digest": previous,
        "media_package_digest": media_digest,
        "fixture_mode": fixture_mode,
        "owner_state_authenticated": owner_authenticated,
        "checkpoint_signature_present": False,
        "witness_authenticated": False,
        "recovery_authorized": False,
        "gate1_approved": False,
        "production_gates_approved": 0,
        "production_dispatch_allowed": False,
        "iso_release_allowed": False,
    }
    return {**unsigned, "checkpoint_digest": _digest(CHECKPOINT_DOMAIN, unsigned)}


def parse_witness_checkpoint(value: Mapping[str, Any], *, now_unix: int | None = None) -> dict[str, Any]:
    required = set(checkpoint_schema()["required"])
    if type(value) is not dict or set(value) != required:
        raise PolicyError("Phase 42 witness checkpoint fields are not closed")
    candidate = json.loads(canonical_json_bytes(value))
    if candidate["format"] != CHECKPOINT_FORMAT:
        raise PolicyError("Phase 42 witness checkpoint format drifted")
    if candidate["contract_digest"] != offline_ceremony_contract_digest():
        raise PolicyError("Phase 42 witness checkpoint contract drifted")
    if (
        candidate["phase41_ceremony_contract_digest"] != PHASE41_CEREMONY_CONTRACT_DIGEST
        or candidate["phase41_gate1_contract_digest"] != PHASE41_GATE1_CONTRACT_DIGEST
    ):
        raise PolicyError("Phase 42 witness checkpoint Phase 41 binding drifted")
    for key in (
        "challenge_nonce", "witness_keyring_sha256", "owner_keyring_sha256",
        "build_node_keyring_sha256", "ceremony_state_digest",
        "ceremony_store_digest", "trust_state_digest", "media_package_digest",
    ):
        _sha(candidate[key], f"Phase 42 checkpoint {key}")
    _sha(
        candidate["previous_checkpoint_digest"],
        "Phase 42 checkpoint previous digest",
        allow_zero=(candidate["sequence"] == 1),
    )
    for key in (
        "witness_primary_fingerprint", "witness_signing_fingerprint",
        "owner_signing_fingerprint", "build_node_signing_fingerprint",
    ):
        _fpr(candidate[key], f"Phase 42 checkpoint {key}")
    _token(candidate["witness_id"], "Phase 42 checkpoint witness ID")
    if candidate["witness_signing_fingerprint"] in {
        candidate["owner_signing_fingerprint"], candidate["build_node_signing_fingerprint"]
    }:
        raise PolicyError("Phase 42 witness checkpoint identity is not independent")
    if candidate["witness_keyring_sha256"] in {
        candidate["owner_keyring_sha256"], candidate["build_node_keyring_sha256"]
    }:
        raise PolicyError("Phase 42 witness checkpoint keyring is not independent")
    if (
        type(candidate["sequence"]) is not int or candidate["sequence"] < 1
        or type(candidate["trust_generation"]) is not int or candidate["trust_generation"] < 1
        or type(candidate["created_unix"]) is not int
        or type(candidate["expires_unix"]) is not int
        or not candidate["created_unix"] < candidate["expires_unix"]
        or candidate["expires_unix"] > candidate["created_unix"] + MAX_LIFETIME
    ):
        raise PolicyError("Phase 42 witness checkpoint numeric policy drifted")
    if candidate["sequence"] == 1 and candidate["previous_checkpoint_digest"] != ZERO_SHA:
        raise PolicyError("Phase 42 first checkpoint previous digest drifted")
    if candidate["sequence"] > 1 and candidate["previous_checkpoint_digest"] == ZERO_SHA:
        raise PolicyError("Phase 42 later checkpoint has no predecessor")
    for key in ("fixture_mode", "owner_state_authenticated"):
        if type(candidate[key]) is not bool:
            raise PolicyError("Phase 42 witness checkpoint Boolean is invalid")
    for key in (
        "checkpoint_signature_present", "witness_authenticated", "recovery_authorized",
        "gate1_approved", "production_dispatch_allowed", "iso_release_allowed",
    ):
        if candidate[key] is not False:
            raise PolicyError("Phase 42 unsigned witness checkpoint attempted promotion")
    if candidate["production_gates_approved"] != 0:
        raise PolicyError("Phase 42 witness checkpoint attempted gate promotion")
    unsigned = {key: candidate[key] for key in candidate if key != "checkpoint_digest"}
    if candidate["checkpoint_digest"] != _digest(CHECKPOINT_DOMAIN, unsigned):
        raise PolicyError("Phase 42 witness checkpoint digest is invalid")
    if now_unix is not None and not candidate["created_unix"] <= now_unix <= candidate["expires_unix"]:
        raise PolicyError("Phase 42 witness checkpoint is not valid at the supplied time")
    return candidate


@dataclass(frozen=True)
class VerifiedWitnessCheckpoint:
    document: dict[str, Any]
    signed_input_sha256: dict[str, str]
    signature_verified: bool
    local_pin_verified: bool
    witness_authenticated: bool
    verification_digest: str

    @property
    def fixture_mode(self) -> bool:
        return bool(self.document["fixture_mode"])

    def to_dict(self) -> dict[str, Any]:
        return {
            "format": CHECKPOINT_VERIFICATION_FORMAT,
            "checkpoint_digest": self.document["checkpoint_digest"],
            "sequence": self.document["sequence"],
            "witness_signing_fingerprint": self.document["witness_signing_fingerprint"],
            "signed_input_sha256": dict(self.signed_input_sha256),
            "signature_verified": self.signature_verified,
            "local_pin_verified": self.local_pin_verified,
            "fixture_mode": self.fixture_mode,
            "owner_state_authenticated": self.document["owner_state_authenticated"],
            "witness_authenticated": self.witness_authenticated,
            "recovery_authorized": bool(
                self.witness_authenticated and self.document["owner_state_authenticated"]
            ),
            "gate1_approved": False,
            "production_gates_approved": 0,
            "production_dispatch_allowed": False,
            "iso_release_allowed": False,
            "verification_digest": self.verification_digest,
        }


def verify_signed_witness_checkpoint(
    *,
    checkpoint_path: Path,
    signature_path: Path,
    keyring_path: Path,
    expected_witness_primary_fingerprint: str,
    expected_witness_signing_fingerprint: str,
    expected_witness_keyring_sha256: str,
    ceremony_state: Mapping[str, Any],
    ceremony_store: Mapping[str, Any],
    trust_state: Mapping[str, Any],
    now_unix: int,
    gpgv_executable: str | Path = "/usr/bin/gpgv",
) -> VerifiedWitnessCheckpoint:
    checkpoint_meta, checkpoint_bytes = phase40.measure_file(
        checkpoint_path, maximum=MAX_CHECKPOINT_BYTES,
        context="Phase 42 witness checkpoint")
    signature_meta, signature = phase40.measure_file(
        signature_path, maximum=phase40.MAX_SIGNATURE_BYTES,
        context="Phase 42 witness checkpoint signature")
    keyring_meta, keyring = phase40.measure_file(
        keyring_path, maximum=phase40.MAX_KEYRING_BYTES,
        context="Phase 42 witness verification keyring")
    document = parse_witness_checkpoint(
        _strict_json(checkpoint_bytes, "Phase 42 witness checkpoint"), now_unix=now_unix)
    expected_primary = _fpr(
        expected_witness_primary_fingerprint, "Phase 42 locally pinned witness primary")
    expected_signing = _fpr(
        expected_witness_signing_fingerprint, "Phase 42 locally pinned witness signer")
    expected_keyring = _sha(
        expected_witness_keyring_sha256, "Phase 42 locally pinned witness keyring")
    if (
        document["witness_primary_fingerprint"] != expected_primary
        or document["witness_signing_fingerprint"] != expected_signing
        or document["witness_keyring_sha256"] != expected_keyring
        or keyring_meta.sha256 != expected_keyring
    ):
        raise PolicyError("Phase 42 witness checkpoint differs from local witness pins")
    state = phase41.parse_ceremony_state(ceremony_state)
    store = phase41.parse_ceremony_store(ceremony_store)
    trust = phase40.parse_trust_state(trust_state)
    recreated = create_witness_checkpoint(
        witness_id=document["witness_id"],
        witness_primary_fingerprint=document["witness_primary_fingerprint"],
        witness_signing_fingerprint=document["witness_signing_fingerprint"],
        witness_keyring_sha256=document["witness_keyring_sha256"],
        sequence=document["sequence"],
        created_unix=document["created_unix"],
        expires_unix=document["expires_unix"],
        challenge_nonce=document["challenge_nonce"],
        ceremony_state=state,
        ceremony_store=store,
        trust_state=trust,
        previous_checkpoint_digest=document["previous_checkpoint_digest"],
        media_package_digest=document["media_package_digest"],
        fixture_mode=document["fixture_mode"],
    )
    if recreated != document:
        raise PolicyError("Phase 42 witness checkpoint differs from supplied state")
    if keyring_meta.sha256 in {state["owner_keyring_sha256"], state["build_node_keyring_sha256"]}:
        raise PolicyError("Phase 42 witness keyring aliases an owner/build-node identity")
    phase39._verify_signature(  # type: ignore[attr-defined]
        payload=checkpoint_bytes,
        signature=signature,
        keyring=keyring,
        expected_fingerprint=expected_signing,
        gpgv_executable=gpgv_executable,
        fixture_mode=document["fixture_mode"],
        role="phase42-witness-checkpoint",
    )
    authenticated = bool(
        not document["fixture_mode"]
        and document["owner_state_authenticated"]
        and trust["owner_trust_authenticated"]
    )
    signed_inputs = {
        "checkpoint": checkpoint_meta.sha256,
        "signature": signature_meta.sha256,
        "keyring": keyring_meta.sha256,
    }
    unsigned = {
        "format": CHECKPOINT_VERIFICATION_FORMAT,
        "checkpoint_digest": document["checkpoint_digest"],
        "sequence": document["sequence"],
        "witness_signing_fingerprint": expected_signing,
        "signed_input_sha256": signed_inputs,
        "signature_verified": True,
        "local_pin_verified": True,
        "fixture_mode": document["fixture_mode"],
        "owner_state_authenticated": document["owner_state_authenticated"],
        "witness_authenticated": authenticated,
        "recovery_authorized": bool(authenticated and document["owner_state_authenticated"]),
        "gate1_approved": False,
        "production_gates_approved": 0,
        "production_dispatch_allowed": False,
        "iso_release_allowed": False,
    }
    return VerifiedWitnessCheckpoint(
        document=document,
        signed_input_sha256=signed_inputs,
        signature_verified=True,
        local_pin_verified=True,
        witness_authenticated=authenticated,
        verification_digest=_digest(CHECKPOINT_VERIFICATION_DOMAIN, unsigned),
    )


def empty_witness_ledger() -> dict[str, Any]:
    unsigned = {
        "format": LEDGER_FORMAT,
        "contract_digest": offline_ceremony_contract_digest(),
        "generation": 0,
        "highest_sequence": 0,
        "current_checkpoint_digest": ZERO_SHA,
        "records": [],
        "fixture_mode": False,
        "witness_chain_authenticated": False,
        "recovery_authorized": False,
        "production_gates_approved": 0,
        "production_dispatch_allowed": False,
        "iso_release_allowed": False,
    }
    return {**unsigned, "ledger_digest": _digest(LEDGER_DOMAIN, unsigned)}


def parse_witness_ledger(value: Mapping[str, Any]) -> dict[str, Any]:
    required = set(witness_ledger_schema()["required"])
    if type(value) is not dict or set(value) != required:
        raise PolicyError("Phase 42 witness ledger fields are not closed")
    candidate = json.loads(canonical_json_bytes(value))
    if candidate["format"] != LEDGER_FORMAT or candidate["contract_digest"] != offline_ceremony_contract_digest():
        raise PolicyError("Phase 42 witness ledger identity drifted")
    records = candidate["records"]
    if type(records) is not list or len(records) > MAX_LEDGER_RECORDS:
        raise PolicyError("Phase 42 witness ledger record count is invalid")
    previous = ZERO_SHA
    all_authenticated = bool(records)
    fixture = False
    for index, record in enumerate(records, 1):
        expected_fields = {
            "sequence", "checkpoint_digest", "verification_digest",
            "previous_checkpoint_digest", "ceremony_state_digest",
            "ceremony_store_digest", "trust_state_digest",
            "witness_signing_fingerprint", "witness_authenticated", "fixture_mode",
        }
        if type(record) is not dict or set(record) != expected_fields or record["sequence"] != index:
            raise PolicyError("Phase 42 witness ledger record is invalid")
        for key in (
            "checkpoint_digest", "verification_digest", "ceremony_state_digest",
            "ceremony_store_digest", "trust_state_digest",
        ):
            _sha(record[key], f"Phase 42 witness ledger {key}")
        _sha(record["previous_checkpoint_digest"], "Phase 42 ledger previous checkpoint", allow_zero=(index == 1))
        _fpr(record["witness_signing_fingerprint"], "Phase 42 ledger witness")
        if record["previous_checkpoint_digest"] != previous:
            raise PolicyError("Phase 42 witness ledger checkpoint chain drifted")
        previous = record["checkpoint_digest"]
        if type(record["witness_authenticated"]) is not bool or type(record["fixture_mode"]) is not bool:
            raise PolicyError("Phase 42 witness ledger Boolean is invalid")
        fixture = fixture or record["fixture_mode"]
        all_authenticated = all_authenticated and record["witness_authenticated"]
    if (
        candidate["generation"] != len(records)
        or candidate["highest_sequence"] != len(records)
        or candidate["current_checkpoint_digest"] != previous
        or candidate["fixture_mode"] is not fixture
        or candidate["witness_chain_authenticated"] is not bool(all_authenticated and not fixture)
        or candidate["recovery_authorized"] is not bool(all_authenticated and not fixture)
        or candidate["production_gates_approved"] != 0
        or candidate["production_dispatch_allowed"] is not False
        or candidate["iso_release_allowed"] is not False
    ):
        raise PolicyError("Phase 42 witness ledger summary drifted")
    unsigned = {key: candidate[key] for key in candidate if key != "ledger_digest"}
    if candidate["ledger_digest"] != _digest(LEDGER_DOMAIN, unsigned):
        raise PolicyError("Phase 42 witness ledger digest is invalid")
    return candidate


def append_witness_checkpoint(
    *, ledger: Mapping[str, Any], verified: VerifiedWitnessCheckpoint,
) -> dict[str, Any]:
    if not isinstance(verified, VerifiedWitnessCheckpoint):
        raise PolicyError("Phase 42 verified witness checkpoint is required")
    current = parse_witness_ledger(ledger)
    checkpoint = verified.document
    expected_sequence = current["highest_sequence"] + 1
    if checkpoint["sequence"] != expected_sequence:
        raise PolicyError("Phase 42 witness checkpoint sequence is stale or nonconsecutive")
    if checkpoint["previous_checkpoint_digest"] != current["current_checkpoint_digest"]:
        raise PolicyError("Phase 42 witness checkpoint predecessor drifted")
    if any(item["checkpoint_digest"] == checkpoint["checkpoint_digest"] for item in current["records"]):
        raise PolicyError("Phase 42 witness checkpoint replay was rejected")
    record = {
        "sequence": checkpoint["sequence"],
        "checkpoint_digest": checkpoint["checkpoint_digest"],
        "verification_digest": verified.verification_digest,
        "previous_checkpoint_digest": checkpoint["previous_checkpoint_digest"],
        "ceremony_state_digest": checkpoint["ceremony_state_digest"],
        "ceremony_store_digest": checkpoint["ceremony_store_digest"],
        "trust_state_digest": checkpoint["trust_state_digest"],
        "witness_signing_fingerprint": checkpoint["witness_signing_fingerprint"],
        "witness_authenticated": verified.witness_authenticated,
        "fixture_mode": checkpoint["fixture_mode"],
    }
    records = [*current["records"], record]
    fixture = any(item["fixture_mode"] for item in records)
    authenticated = bool(records and all(item["witness_authenticated"] for item in records) and not fixture)
    unsigned = {
        "format": LEDGER_FORMAT,
        "contract_digest": offline_ceremony_contract_digest(),
        "generation": len(records),
        "highest_sequence": checkpoint["sequence"],
        "current_checkpoint_digest": checkpoint["checkpoint_digest"],
        "records": records,
        "fixture_mode": fixture,
        "witness_chain_authenticated": authenticated,
        "recovery_authorized": authenticated,
        "production_gates_approved": 0,
        "production_dispatch_allowed": False,
        "iso_release_allowed": False,
    }
    return parse_witness_ledger({**unsigned, "ledger_digest": _digest(LEDGER_DOMAIN, unsigned)})


def _private_parent(path: Path, context: str) -> Path:
    parent = path.absolute().parent
    if parent.is_symlink():
        raise PolicyError(f"{context} parent cannot be a symbolic link")
    info = parent.stat()
    if (
        not stat.S_ISDIR(info.st_mode)
        or stat.S_IMODE(info.st_mode) & 0o022
        or info.st_uid not in {0, os.getuid()}
    ):
        raise PolicyError(f"{context} parent is not private")
    return parent


def _atomic_write(path: Path, payload: bytes, *, mode: int = 0o600) -> None:
    parent = _private_parent(path, "Phase 42 atomic publication")
    temporary = parent / f".{path.name}.tmp-{os.getpid()}-{hashlib.sha256(payload).hexdigest()[:12]}"
    if path.exists() or path.is_symlink() or temporary.exists() or temporary.is_symlink():
        raise PolicyError("Phase 42 atomic publication target already exists")
    fd = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0),
        mode,
    )
    published = False
    try:
        os.fchmod(fd, mode)
        view = memoryview(payload)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise PolicyError("Phase 42 atomic publication did not complete")
            view = view[written:]
        os.fsync(fd)
        os.close(fd)
        fd = -1
        media._rename_noreplace(temporary, path, context="Phase 42 atomic publication")
        published = True
        directory_fd = os.open(
            parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if fd >= 0:
            os.close(fd)
        if not published:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass


def publish_witness_ledger(path: Path, verified: VerifiedWitnessCheckpoint) -> dict[str, Any]:
    parent = _private_parent(path, "Phase 42 witness ledger")
    lock_path = parent / f".{path.name}.lock"
    lock_fd = os.open(
        lock_path,
        os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        os.fchmod(lock_fd, 0o600)
        lock_info = os.fstat(lock_fd)
        if (
            not stat.S_ISREG(lock_info.st_mode)
            or lock_info.st_nlink != 1
            or stat.S_IMODE(lock_info.st_mode) & 0o077
            or lock_info.st_uid not in {0, os.getuid()}
        ):
            raise PolicyError("Phase 42 witness-ledger lock is unsafe")
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        if path.exists():
            meta, payload = phase40.measure_file(
                path, maximum=MAX_LEDGER_BYTES, context="Phase 42 existing witness ledger")
            if meta.mode & 0o077:
                raise PolicyError("Phase 42 witness ledger is not private")
            current = parse_witness_ledger(_strict_json(payload, "Phase 42 witness ledger"))
        else:
            current = empty_witness_ledger()
        updated = append_witness_checkpoint(ledger=current, verified=verified)
        temporary = parent / f".{path.name}.next-{os.getpid()}"
        if temporary.exists() or temporary.is_symlink():
            raise PolicyError("Phase 42 witness ledger temporary path already exists")
        fd = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        published = False
        try:
            os.fchmod(fd, 0o600)
            data = canonical_json_bytes(updated)
            view = memoryview(data)
            while view:
                count = os.write(fd, view)
                if count <= 0:
                    raise PolicyError("Phase 42 witness ledger write did not complete")
                view = view[count:]
            os.fsync(fd)
            os.close(fd)
            fd = -1
            os.replace(temporary, path)
            published = True
            directory_fd = os.open(
                parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0))
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        finally:
            if fd >= 0:
                os.close(fd)
            if not published:
                try:
                    temporary.unlink()
                except FileNotFoundError:
                    pass
        return updated
    finally:
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
        finally:
            os.close(lock_fd)


def witnessed_recovery(
    *,
    destination: Path,
    checkpoint_store: Mapping[str, Any],
    trust_state: Mapping[str, Any],
    verified_witness: VerifiedWitnessCheckpoint,
    minimum_sequence: int,
    fixture_drill: bool = False,
) -> dict[str, Any]:
    if not isinstance(verified_witness, VerifiedWitnessCheckpoint):
        raise PolicyError("Phase 42 verified witness checkpoint is required")
    store = phase41.parse_ceremony_store(checkpoint_store)
    trust = phase40.parse_trust_state(trust_state)
    checkpoint = verified_witness.document
    if (
        store["store_digest"] != checkpoint["ceremony_store_digest"]
        or store["current_state"]["state_digest"] != checkpoint["ceremony_state_digest"]
        or trust["state_digest"] != checkpoint["trust_state_digest"]
        or store["highest_sequence"] != checkpoint["sequence"]
    ):
        raise PolicyError("Phase 42 recovery inputs differ from the witnessed checkpoint")
    if checkpoint["fixture_mode"]:
        if fixture_drill is not True:
            raise PolicyError("Phase 42 fixture witness cannot authorize recovery")
    elif not (
        verified_witness.witness_authenticated
        and checkpoint["owner_state_authenticated"]
        and trust["owner_trust_authenticated"]
    ):
        raise PolicyError("Phase 42 production recovery lacks owner/witness authentication")
    recovered = phase41.recover_ceremony_store(
        destination=destination,
        checkpoint=store,
        minimum_sequence=minimum_sequence,
        expected_state_digest=checkpoint["ceremony_state_digest"],
    )
    authorized = bool(
        not checkpoint["fixture_mode"]
        and verified_witness.witness_authenticated
        and checkpoint["owner_state_authenticated"]
        and trust["owner_trust_authenticated"]
    )
    unsigned = {
        "format": RECOVERY_FORMAT,
        "checkpoint_digest": checkpoint["checkpoint_digest"],
        "witness_verification_digest": verified_witness.verification_digest,
        "ceremony_store_digest": recovered["store_digest"],
        "ceremony_state_digest": recovered["current_state"]["state_digest"],
        "trust_state_digest": trust["state_digest"],
        "sequence": recovered["highest_sequence"],
        "fixture_drill": checkpoint["fixture_mode"],
        "recovery_executed": True,
        "recovery_authorized": authorized,
        "quarantine_cleared": False,
        "gate1_approved": False,
        "production_gates_approved": 0,
        "production_dispatch_allowed": False,
        "iso_release_allowed": False,
    }
    return {**unsigned, "recovery_digest": _digest(RECOVERY_DOMAIN, unsigned)}


def _parse_transition_verification(value: Mapping[str, Any]) -> dict[str, Any]:
    required = {
        "format", "transition_digest", "transition_type", "sequence",
        "signature_roles_verified", "signed_input_sha256", "fixture_mode",
        "signatures_verified", "owner_authenticated", "production_gate_approved",
        "production_dispatch_allowed", "iso_release_allowed", "verification_digest",
    }
    if type(value) is not dict or set(value) != required:
        raise PolicyError("Phase 42 transition verification fields are not closed")
    candidate = json.loads(canonical_json_bytes(value))
    if candidate["format"] != phase41.VERIFICATION_FORMAT:
        raise PolicyError("Phase 42 transition verification format drifted")
    _sha(candidate["transition_digest"], "Phase 42 transition digest")
    _sha(candidate["verification_digest"], "Phase 42 transition verification digest")
    if candidate["transition_type"] not in phase41.TRANSITION_TYPES:
        raise PolicyError("Phase 42 transcript transition type is invalid")
    if type(candidate["sequence"]) is not int or candidate["sequence"] < 1:
        raise PolicyError("Phase 42 transcript transition sequence is invalid")
    if type(candidate["signature_roles_verified"]) is not list or not candidate["signature_roles_verified"]:
        raise PolicyError("Phase 42 transcript transition roles are incomplete")
    if type(candidate["signed_input_sha256"]) is not dict or not candidate["signed_input_sha256"]:
        raise PolicyError("Phase 42 transcript transition signed inputs are incomplete")
    for digest in candidate["signed_input_sha256"].values():
        _sha(digest, "Phase 42 transition signed input")
    if candidate["signatures_verified"] is not True:
        raise PolicyError("Phase 42 transcript contains an unsigned transition")
    if type(candidate["fixture_mode"]) is not bool or type(candidate["owner_authenticated"]) is not bool:
        raise PolicyError("Phase 42 transcript transition Boolean is invalid")
    if (
        candidate["production_gate_approved"] is not False
        or candidate["production_dispatch_allowed"] is not False
        or candidate["iso_release_allowed"] is not False
    ):
        raise PolicyError("Phase 42 transition verification attempted promotion")
    unsigned = {key: candidate[key] for key in candidate if key != "verification_digest"}
    if candidate["verification_digest"] != phase41._digest(phase41.VERIFICATION_DOMAIN, unsigned):
        raise PolicyError("Phase 42 transition verification digest is invalid")
    return candidate


def create_ceremony_transcript(
    *,
    transcript_id: str,
    created_unix: int,
    challenge_nonce: str,
    transition_verifications: Sequence[Mapping[str, Any]],
    ceremony_states: Sequence[Mapping[str, Any]],
    final_ceremony_store: Mapping[str, Any],
    final_trust_state: Mapping[str, Any],
    verified_witness: VerifiedWitnessCheckpoint,
    media_package_digests: Sequence[str],
) -> dict[str, Any]:
    transcript_id = _token(transcript_id, "Phase 42 transcript ID")
    challenge = _sha(challenge_nonce, "Phase 42 transcript challenge")
    if type(created_unix) is not int or created_unix < 1:
        raise PolicyError("Phase 42 transcript time is invalid")
    if (
        type(transition_verifications) not in {list, tuple}
        or type(ceremony_states) not in {list, tuple}
        or not 1 <= len(transition_verifications) == len(ceremony_states) <= MAX_TRANSCRIPT_RECORDS
    ):
        raise PolicyError("Phase 42 transcript transition inventory is invalid")
    verifications = [_parse_transition_verification(item) for item in transition_verifications]
    states = [phase41.parse_ceremony_state(item) for item in ceremony_states]
    records: list[dict[str, Any]] = []
    previous_state = ZERO_SHA
    for index, (verification, state) in enumerate(zip(verifications, states, strict=True), 1):
        if verification["sequence"] != index or state["sequence"] != index:
            raise PolicyError("Phase 42 transcript sequence is not consecutive")
        if (
            verification["transition_digest"] != state["transition_digest"]
            or verification["transition_type"] != state["transition_type"]
            or state["previous_ceremony_state_digest"] != previous_state
        ):
            raise PolicyError("Phase 42 transcript transition/state binding drifted")
        previous_state = state["state_digest"]
        records.append({
            "sequence": index,
            "transition_type": state["transition_type"],
            "transition_digest": state["transition_digest"],
            "verification_digest": verification["verification_digest"],
            "previous_ceremony_state_digest": state["previous_ceremony_state_digest"],
            "ceremony_state_digest": state["state_digest"],
            "signatures_verified": True,
            "owner_authenticated": verification["owner_authenticated"],
            "fixture_mode": bool(verification["fixture_mode"] or state["fixture_mode"]),
        })
    store = phase41.parse_ceremony_store(final_ceremony_store)
    trust = phase40.parse_trust_state(final_trust_state)
    final_state = states[-1]
    checkpoint = verified_witness.document
    if (
        store["current_state"]["state_digest"] != final_state["state_digest"]
        or store["highest_sequence"] != final_state["sequence"]
        or final_state["trust_state_digest"] != trust["state_digest"]
        or checkpoint["ceremony_state_digest"] != final_state["state_digest"]
        or checkpoint["ceremony_store_digest"] != store["store_digest"]
        or checkpoint["trust_state_digest"] != trust["state_digest"]
    ):
        raise PolicyError("Phase 42 transcript final state/store/trust/witness binding drifted")
    if type(media_package_digests) not in {list, tuple} or not 1 <= len(media_package_digests) <= MAX_TRANSCRIPT_MEDIA:
        raise PolicyError("Phase 42 transcript media inventory is invalid")
    media_digests = [_sha(item, "Phase 42 transcript media package") for item in media_package_digests]
    if len(set(media_digests)) != len(media_digests):
        raise PolicyError("Phase 42 transcript media package digest is duplicated")
    fixture = bool(
        any(item["fixture_mode"] for item in records)
        or checkpoint["fixture_mode"] or trust["fixture_mode"]
    )
    owner_authenticated = bool(
        not fixture
        and all(item["owner_authenticated"] for item in records)
        and final_state["owner_trust_authenticated"]
        and trust["owner_trust_authenticated"]
    )
    witness_authenticated = bool(not fixture and verified_witness.witness_authenticated)
    unsigned: dict[str, Any] = {
        "format": TRANSCRIPT_FORMAT,
        "contract_digest": offline_ceremony_contract_digest(),
        "transcript_id": transcript_id,
        "created_unix": created_unix,
        "challenge_nonce": challenge,
        "transition_count": len(records),
        "transitions": records,
        "initial_ceremony_state_digest": states[0]["state_digest"],
        "final_ceremony_state_digest": final_state["state_digest"],
        "final_ceremony_store_digest": store["store_digest"],
        "final_trust_state_digest": trust["state_digest"],
        "witness_checkpoint_digest": checkpoint["checkpoint_digest"],
        "witness_verification_digest": verified_witness.verification_digest,
        "media_package_digests": media_digests,
        "owner_signing_fingerprint": final_state["owner_signing_fingerprint"],
        "owner_keyring_sha256": final_state["owner_keyring_sha256"],
        "witness_signing_fingerprint": checkpoint["witness_signing_fingerprint"],
        "witness_keyring_sha256": checkpoint["witness_keyring_sha256"],
        "all_transition_signatures_verified": True,
        "owner_authenticated": owner_authenticated,
        "witness_authenticated": witness_authenticated,
        "fixture_mode": fixture,
        "transcript_signature_present": False,
        "transcript_alone_can_close_gate1": False,
        "gate1_approved": False,
        "production_gates_approved": 0,
        "production_dispatch_allowed": False,
        "iso_release_allowed": False,
    }
    return {**unsigned, "transcript_digest": _digest(TRANSCRIPT_DOMAIN, unsigned)}


def parse_ceremony_transcript(value: Mapping[str, Any]) -> dict[str, Any]:
    required = set(transcript_schema()["required"])
    if type(value) is not dict or set(value) != required:
        raise PolicyError("Phase 42 ceremony transcript fields are not closed")
    candidate = json.loads(canonical_json_bytes(value))
    if candidate["format"] != TRANSCRIPT_FORMAT or candidate["contract_digest"] != offline_ceremony_contract_digest():
        raise PolicyError("Phase 42 ceremony transcript identity drifted")
    _token(candidate["transcript_id"], "Phase 42 transcript ID")
    _sha(candidate["challenge_nonce"], "Phase 42 transcript challenge")
    if type(candidate["created_unix"]) is not int or candidate["created_unix"] < 1:
        raise PolicyError("Phase 42 transcript time is invalid")
    records = candidate["transitions"]
    if type(records) is not list or candidate["transition_count"] != len(records) or not 1 <= len(records) <= MAX_TRANSCRIPT_RECORDS:
        raise PolicyError("Phase 42 transcript record count is invalid")
    previous_state = ZERO_SHA
    fixture = False
    all_owner = True
    for index, record in enumerate(records, 1):
        fields = {
            "sequence", "transition_type", "transition_digest", "verification_digest",
            "previous_ceremony_state_digest", "ceremony_state_digest",
            "signatures_verified", "owner_authenticated", "fixture_mode",
        }
        if type(record) is not dict or set(record) != fields or record["sequence"] != index:
            raise PolicyError("Phase 42 transcript record is invalid")
        if record["transition_type"] not in phase41.TRANSITION_TYPES or record["signatures_verified"] is not True:
            raise PolicyError("Phase 42 transcript record lacks an admitted signed transition")
        for key in (
            "transition_digest", "verification_digest",
            "previous_ceremony_state_digest", "ceremony_state_digest",
        ):
            _sha(
                record[key], f"Phase 42 transcript {key}",
                allow_zero=(key == "previous_ceremony_state_digest" and index == 1),
            )
        if record["previous_ceremony_state_digest"] != previous_state:
            raise PolicyError("Phase 42 transcript ceremony-state chain is not contiguous")
        if type(record["owner_authenticated"]) is not bool or type(record["fixture_mode"]) is not bool:
            raise PolicyError("Phase 42 transcript record Boolean is invalid")
        fixture = fixture or record["fixture_mode"]
        all_owner = all_owner and record["owner_authenticated"]
        if index == 1 and candidate["initial_ceremony_state_digest"] != record["ceremony_state_digest"]:
            raise PolicyError("Phase 42 transcript initial state drifted")
        previous_state = record["ceremony_state_digest"]
    if candidate["final_ceremony_state_digest"] != previous_state:
        raise PolicyError("Phase 42 transcript final state drifted")
    for key in (
        "initial_ceremony_state_digest", "final_ceremony_state_digest",
        "final_ceremony_store_digest", "final_trust_state_digest",
        "witness_checkpoint_digest", "witness_verification_digest",
        "owner_keyring_sha256", "witness_keyring_sha256",
    ):
        _sha(candidate[key], f"Phase 42 transcript {key}")
    packages = candidate["media_package_digests"]
    if type(packages) is not list or not 1 <= len(packages) <= MAX_TRANSCRIPT_MEDIA:
        raise PolicyError("Phase 42 transcript media package inventory is invalid")
    for item in packages:
        _sha(item, "Phase 42 transcript media package")
    if len(set(packages)) != len(packages):
        raise PolicyError("Phase 42 transcript media package digest is duplicated")
    owner_fpr = _fpr(candidate["owner_signing_fingerprint"], "Phase 42 transcript owner")
    witness_fpr = _fpr(candidate["witness_signing_fingerprint"], "Phase 42 transcript witness")
    if owner_fpr == witness_fpr or candidate["owner_keyring_sha256"] == candidate["witness_keyring_sha256"]:
        raise PolicyError("Phase 42 transcript owner/witness identities are not independent")
    for key in ("owner_authenticated", "witness_authenticated", "fixture_mode"):
        if type(candidate[key]) is not bool:
            raise PolicyError("Phase 42 transcript Boolean is invalid")
    if candidate["fixture_mode"] is not fixture:
        raise PolicyError("Phase 42 transcript fixture summary drifted")
    if candidate["owner_authenticated"] and (fixture or not all_owner):
        raise PolicyError("Phase 42 transcript owner authentication is inconsistent")
    if candidate["witness_authenticated"] and fixture:
        raise PolicyError("Phase 42 fixture transcript promoted witness authority")
    if candidate["all_transition_signatures_verified"] is not True:
        raise PolicyError("Phase 42 transcript signature summary drifted")
    for key in (
        "transcript_signature_present", "transcript_alone_can_close_gate1",
        "gate1_approved", "production_dispatch_allowed", "iso_release_allowed",
    ):
        if candidate[key] is not False:
            raise PolicyError("Phase 42 unsigned transcript attempted promotion")
    if candidate["production_gates_approved"] != 0:
        raise PolicyError("Phase 42 transcript attempted gate promotion")
    unsigned = {key: candidate[key] for key in candidate if key != "transcript_digest"}
    if candidate["transcript_digest"] != _digest(TRANSCRIPT_DOMAIN, unsigned):
        raise PolicyError("Phase 42 transcript digest is invalid")
    return candidate


@dataclass(frozen=True)
class VerifiedCeremonyTranscript:
    document: dict[str, Any]
    signed_input_sha256: dict[str, str]
    owner_signature_verified: bool
    witness_signature_verified: bool
    local_pins_verified: bool
    transcript_authenticated: bool
    verification_digest: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "format": TRANSCRIPT_VERIFICATION_FORMAT,
            "transcript_digest": self.document["transcript_digest"],
            "signed_input_sha256": dict(self.signed_input_sha256),
            "owner_signature_verified": self.owner_signature_verified,
            "witness_signature_verified": self.witness_signature_verified,
            "local_pins_verified": self.local_pins_verified,
            "fixture_mode": self.document["fixture_mode"],
            "transcript_authenticated": self.transcript_authenticated,
            "transcript_alone_can_close_gate1": False,
            "gate1_approved": False,
            "production_gates_approved": 0,
            "production_dispatch_allowed": False,
            "iso_release_allowed": False,
            "verification_digest": self.verification_digest,
        }


def verify_signed_ceremony_transcript(
    *,
    transcript_path: Path,
    owner_signature_path: Path,
    owner_keyring_path: Path,
    witness_signature_path: Path,
    witness_keyring_path: Path,
    expected_owner_signing_fingerprint: str,
    expected_owner_keyring_sha256: str,
    expected_witness_signing_fingerprint: str,
    expected_witness_keyring_sha256: str,
    gpgv_executable: str | Path = "/usr/bin/gpgv",
) -> VerifiedCeremonyTranscript:
    transcript_meta, transcript_bytes = phase40.measure_file(
        transcript_path, maximum=MAX_TRANSCRIPT_BYTES, context="Phase 42 ceremony transcript")
    owner_sig_meta, owner_sig = phase40.measure_file(
        owner_signature_path, maximum=phase40.MAX_SIGNATURE_BYTES,
        context="Phase 42 owner transcript signature")
    owner_key_meta, owner_key = phase40.measure_file(
        owner_keyring_path, maximum=phase40.MAX_KEYRING_BYTES,
        context="Phase 42 owner transcript keyring")
    witness_sig_meta, witness_sig = phase40.measure_file(
        witness_signature_path, maximum=phase40.MAX_SIGNATURE_BYTES,
        context="Phase 42 witness transcript signature")
    witness_key_meta, witness_key = phase40.measure_file(
        witness_keyring_path, maximum=phase40.MAX_KEYRING_BYTES,
        context="Phase 42 witness transcript keyring")
    document = parse_ceremony_transcript(
        _strict_json(transcript_bytes, "Phase 42 ceremony transcript"))
    owner_fpr = _fpr(expected_owner_signing_fingerprint, "Phase 42 local owner transcript pin")
    witness_fpr = _fpr(expected_witness_signing_fingerprint, "Phase 42 local witness transcript pin")
    owner_sha = _sha(expected_owner_keyring_sha256, "Phase 42 local owner keyring pin")
    witness_sha = _sha(expected_witness_keyring_sha256, "Phase 42 local witness keyring pin")
    if (
        document["owner_signing_fingerprint"] != owner_fpr
        or document["witness_signing_fingerprint"] != witness_fpr
        or document["owner_keyring_sha256"] != owner_sha
        or document["witness_keyring_sha256"] != witness_sha
        or owner_key_meta.sha256 != owner_sha
        or witness_key_meta.sha256 != witness_sha
    ):
        raise PolicyError("Phase 42 transcript differs from local owner/witness pins")
    if owner_fpr == witness_fpr or owner_sha == witness_sha:
        raise PolicyError("Phase 42 transcript signatures do not use independent identities")
    if (owner_key_meta.device, owner_key_meta.inode) == (witness_key_meta.device, witness_key_meta.inode):
        raise PolicyError("Phase 42 transcript keyrings alias a file identity")
    phase39._verify_signature(  # type: ignore[attr-defined]
        payload=transcript_bytes, signature=owner_sig, keyring=owner_key,
        expected_fingerprint=owner_fpr, gpgv_executable=gpgv_executable,
        fixture_mode=document["fixture_mode"], role="phase42-transcript-owner")
    phase39._verify_signature(  # type: ignore[attr-defined]
        payload=transcript_bytes, signature=witness_sig, keyring=witness_key,
        expected_fingerprint=witness_fpr, gpgv_executable=gpgv_executable,
        fixture_mode=document["fixture_mode"], role="phase42-transcript-witness")
    authenticated = bool(
        not document["fixture_mode"]
        and document["owner_authenticated"]
        and document["witness_authenticated"]
    )
    inputs = {
        "transcript": transcript_meta.sha256,
        "owner-signature": owner_sig_meta.sha256,
        "owner-keyring": owner_key_meta.sha256,
        "witness-signature": witness_sig_meta.sha256,
        "witness-keyring": witness_key_meta.sha256,
    }
    unsigned = {
        "format": TRANSCRIPT_VERIFICATION_FORMAT,
        "transcript_digest": document["transcript_digest"],
        "signed_input_sha256": inputs,
        "owner_signature_verified": True,
        "witness_signature_verified": True,
        "local_pins_verified": True,
        "fixture_mode": document["fixture_mode"],
        "transcript_authenticated": authenticated,
        "transcript_alone_can_close_gate1": False,
        "gate1_approved": False,
        "production_gates_approved": 0,
        "production_dispatch_allowed": False,
        "iso_release_allowed": False,
    }
    return VerifiedCeremonyTranscript(
        document=document,
        signed_input_sha256=inputs,
        owner_signature_verified=True,
        witness_signature_verified=True,
        local_pins_verified=True,
        transcript_authenticated=authenticated,
        verification_digest=_digest(TRANSCRIPT_VERIFICATION_DOMAIN, unsigned),
    )


def blocked_observation() -> dict[str, Any]:
    unsigned = {
        "format": "securityops-phase42-offline-ceremony-observation/1",
        "status": BLOCKED_STATUS,
        "contract_digest": offline_ceremony_contract_digest(),
        "real_owner_keys_supplied": False,
        "real_witness_key_supplied": False,
        "authenticated_35_artifact_closure_present": False,
        "nonfixture_phase39_gate1_exchange_present": False,
        "phase40_gate1_semantic_receipt_present": False,
        "phase41_gate1_decision_present": False,
        "gate1_approved": False,
        "production_gates_approved": 0,
        "production_dispatch_allowed": False,
        "iso_release_allowed": False,
        "iso_bytes_present": False,
    }
    return {**unsigned, "observation_digest": _digest(OBSERVATION_DOMAIN, unsigned)}


def run_negative_matrix() -> dict[str, Any]:
    contract = offline_ceremony_contract()
    rejected = 0
    for name in NEGATIVE_CASES:
        value = json.loads(canonical_json_bytes(contract))
        if name == "extra-contract-field":
            value["unexpected"] = True
        elif name == "phase41-runtime-identity-drift":
            value["phase41_identities"]["runtime_commit"] = "1" * 40
        elif name == "phase41-os-identity-drift":
            value["phase41_identities"]["securityops_os_commit"] = "2" * 40
        elif name == "phase41-ceremony-contract-drift":
            value["phase41_ceremony_contract_digest"] = "3" * 64
        elif name == "phase41-gate1-contract-drift":
            value["phase41_gate1_contract_digest"] = "4" * 64
        elif name == "media-profile-removed":
            value["media_policy"]["profiles"].pop(next(iter(value["media_policy"]["profiles"])))
        elif name == "media-ready-marker-disabled":
            value["media_policy"]["atomic_ready_marker_required"] = False
        elif name == "media-rename-noreplace-disabled":
            value["media_policy"]["atomic_publication_uses_rename_noreplace"] = False
        elif name == "media-overwrite-enabled":
            value["media_policy"]["publication_can_overwrite_existing_target"] = True
        elif name == "media-deterministic-chunking-disabled":
            value["media_policy"]["deterministic_chunk_boundaries_required"] = False
        elif name == "media-deterministic-placement-disabled":
            value["media_policy"]["deterministic_first_fit_media_placement_required"] = False
        elif name == "media-stable-filename-disabled":
            value["media_policy"]["stable_caller_independent_filenames"] = False
        elif name == "media-descriptor-relative-open-disabled":
            value["media_policy"]["descriptor_relative_opening_required"] = False
        elif name == "media-hardlinks-enabled":
            value["media_policy"]["hardlinks_allowed"] = True
        elif name == "witness-may-equal-owner":
            value["witness_policy"]["witness_must_differ_from_owner"] = False
        elif name == "witness-may-equal-build-node":
            value["witness_policy"]["witness_must_differ_from_build_node"] = False
        elif name == "witness-keyring-may-alias-owner":
            value["witness_policy"]["witness_keyring_must_differ_from_owner_and_build_node"] = False
        elif name == "witness-original-path-reopened":
            value["witness_policy"]["original_paths_reopened_after_measurement"] = True
        elif name == "witness-checkpoint-not-monotonic":
            value["witness_policy"]["checkpoint_chain_is_monotonic"] = False
        elif name == "witness-checkpoint-not-challenge-bound":
            value["witness_policy"]["checkpoint_binds_challenge"] = False
        elif name == "witness-checkpoint-not-store-bound":
            value["witness_policy"]["checkpoint_binds_ceremony_store"] = False
        elif name == "witness-ledger-replay-enabled":
            value["witness_policy"]["ledger_replay_rejected"] = False
        elif name == "witness-ledger-equivocation-enabled":
            value["witness_policy"]["ledger_equivocation_rejected"] = False
        elif name == "recovery-without-external-witness":
            value["witness_policy"]["recovery_requires_external_verified_checkpoint"] = False
        elif name == "fixture-witness-can-authorize-recovery":
            value["witness_policy"]["fixture_witness_can_authorize_production_recovery"] = True
        elif name == "quarantine-cleared-by-recovery":
            value["witness_policy"]["recovery_cannot_clear_quarantine"] = False
        elif name == "transcript-without-transition-signatures":
            value["transcript_policy"]["all_transition_signatures_required"] = False
        elif name == "transcript-without-owner-signature":
            value["transcript_policy"]["owner_signature_required"] = False
        elif name == "transcript-without-witness-signature":
            value["transcript_policy"]["independent_witness_signature_required"] = False
        elif name == "transcript-alone-closes-gate1":
            value["transcript_policy"]["transcript_alone_can_close_gate1"] = True
        elif name == "transcript-fixture-promotes-owner":
            value["transcript_policy"]["fixture_transcript_can_authenticate_owner"] = True
        elif name == "gate1-without-phase39-exchange":
            value["gate1_truth_boundary"]["phase39_dual_signed_exchange_required"] = False
        elif name == "gate1-without-phase40-semantic-receipt":
            value["gate1_truth_boundary"]["phase40_semantic_admission_required"] = False
        elif name == "gate1-without-phase41-decision":
            value["gate1_truth_boundary"]["phase41_monotonic_decision_required"] = False
        elif name == "transport-is-publisher-admission":
            value["media_policy"]["transport_integrity_is_owner_authority"] = True
        elif name == "capability-discovery-is-execution":
            value["gate1_truth_boundary"]["phase42_media_integrity_is_additional_transport_evidence_only"] = False
        elif name == "production-promotion":
            value["production_dispatch_allowed"] = True
        elif name == "iso-promotion":
            value["iso_release_allowed"] = True
        else:  # pragma: no cover
            raise AssertionError(name)
        unsigned = dict(value)
        unsigned.pop("contract_digest", None)
        value["contract_digest"] = _digest(CONTRACT_DOMAIN, unsigned)
        try:
            parse_offline_ceremony_contract(value)
        except PolicyError:
            rejected += 1
        else:  # pragma: no cover
            raise AssertionError(f"Phase 42 contract mutation accepted: {name}")
    return {
        "format": "securityops-phase42-offline-ceremony-negative-results/1",
        "cases": list(NEGATIVE_CASES),
        "rejected": rejected,
        "total": len(NEGATIVE_CASES),
        "all_rejected": rejected == len(NEGATIVE_CASES),
        "production_gates_approved": 0,
        "production_dispatch_allowed": False,
        "iso_release_allowed": False,
    }


def phase42_selftest() -> dict[str, Any]:
    contract = parse_offline_ceremony_contract(offline_ceremony_contract())
    negatives = run_negative_matrix()
    media_negatives = media.run_media_negative_matrix()
    observation = blocked_observation()
    unsigned = {
        "format": "securityops-phase42-offline-ceremony-selftest/1",
        "status": STATUS,
        "contract_digest": contract["contract_digest"],
        "schemas": {
            "manifest": hashlib.sha256(canonical_json_bytes(media.manifest_schema())).hexdigest(),
            "ready": hashlib.sha256(canonical_json_bytes(media.ready_schema())).hexdigest(),
            "review": hashlib.sha256(canonical_json_bytes(media.review_schema())).hexdigest(),
            "checkpoint": hashlib.sha256(canonical_json_bytes(checkpoint_schema())).hexdigest(),
            "ledger": hashlib.sha256(canonical_json_bytes(witness_ledger_schema())).hexdigest(),
            "transcript": hashlib.sha256(canonical_json_bytes(transcript_schema())).hexdigest(),
        },
        "contract_negative_cases_rejected": negatives["rejected"],
        "media_negative_case_names": media_negatives["total"],
        "blocked_observation_digest": observation["observation_digest"],
        "owner_authority_created": False,
        "gate1_approved": False,
        "production_gates_approved": 0,
        "production_dispatch_allowed": False,
        "iso_release_allowed": False,
    }
    return {
        **unsigned,
        "selftest_digest": hashlib.sha256(
            b"SECURITYOPS-PHASE42-SELFTEST-V1\x00" + canonical_json_bytes(unsigned)
        ).hexdigest(),
    }


def _kit_template(profile: str) -> dict[str, Any]:
    return {
        "format": "securityops-phase42-media-export-request-template/1",
        "profile": profile,
        "package_sequence": 1,
        "created_unix": 0,
        "expires_unix": 0,
        "challenge_nonce": ZERO_SHA,
        "previous_package_digest": ZERO_SHA,
        "roles": [
            {"role": role, "path": f"INPUTS/{filename}"}
            for role, filename in media.PACKAGE_PROFILES[profile]
        ],
        "fixture": False,
        "owner_authority_created": False,
        "production_dispatch_allowed": False,
        "iso_release_allowed": False,
    }


def generate_operator_kit(destination: Path) -> dict[str, Any]:
    if destination.exists() or destination.is_symlink():
        raise PolicyError("Phase 42 operator-kit destination already exists")
    parent = destination.absolute().parent
    if parent.is_symlink():
        raise PolicyError("Phase 42 operator-kit parent cannot be a symbolic link")
    info = parent.stat()
    if not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) & 0o022:
        raise PolicyError("Phase 42 operator-kit parent is not private")
    temporary: Path | None = Path(
        tempfile.mkdtemp(prefix=f".{destination.name}.tmp-", dir=parent))
    temporary.chmod(0o700)
    def command_stub(subcommand: str) -> bytes:
        return (
            "#!/usr/bin/env python3\n"
            "# Secret-free wrapper for the installed Phase 42 CLI.\n"
            "import os,sys\n"
            "os.execvp('securityops-phase42-ceremony',"
            f"['securityops-phase42-ceremony','{subcommand}',*sys.argv[1:]])\n"
        ).encode("utf-8")
    readme = """# Security Ops OS Phase 42 offline ceremony kit

This public kit contains contracts, schemas, request templates, and thin
wrappers only. It contains no secret key and creates no owner authority.
Generate and retain owner, build-node, and independent witness secret keys on
separate operator-controlled systems. Verify local public-keyring hashes and
fingerprints out of band before importing any signature.

A media package proves transport integrity only. A signed transcript proves
its admitted signatures and bindings only. Gate 1 still requires the complete
Phase 39 dual-signed exchange, Phase 40 authenticated 35-artifact closure and
semantic admission, and Phase 41 monotonic decision receipt.
""".encode()
    readme_pt = """# Kit de cerimônia offline da Phase 42 do Security Ops OS

Este kit público contém somente contratos, esquemas, modelos de solicitação e
wrappers mínimos. Ele não contém chave secreta e não cria autoridade do
proprietário. Gere e mantenha as chaves secretas do proprietário, do nó de
build e da testemunha independente em sistemas separados controlados pelo
operador. Confirme hashes e fingerprints das chaves públicas fora de banda.

Um pacote de mídia comprova apenas integridade de transporte. Um transcrito
assinado comprova somente as assinaturas e vínculos admitidos. O Gate 1 ainda
exige a troca com duas assinaturas da Phase 39, o fechamento autenticado dos 35
artefatos e a admissão semântica da Phase 40, além do recibo monotônico da
Phase 41.
""".encode()
    try:
        files: dict[str, tuple[bytes, int]] = {
            "README.md": (readme, 0o444),
            "README.pt-BR.md": (readme_pt, 0o444),
            "phase42-offline-ceremony-contract.json": (canonical_json_bytes(offline_ceremony_contract()), 0o444),
            "phase42-offline-media-manifest.schema.json": (canonical_json_bytes(media.manifest_schema()), 0o444),
            "phase42-offline-media-ready.schema.json": (canonical_json_bytes(media.ready_schema()), 0o444),
            "phase42-offline-media-review.schema.json": (canonical_json_bytes(media.review_schema()), 0o444),
            "phase42-witness-checkpoint.schema.json": (canonical_json_bytes(checkpoint_schema()), 0o444),
            "phase42-witness-ledger.schema.json": (canonical_json_bytes(witness_ledger_schema()), 0o444),
            "phase42-ceremony-transcript.schema.json": (canonical_json_bytes(transcript_schema()), 0o444),
            "initialize-media.request.template.json": (canonical_json_bytes(_kit_template("initialize-transition")), 0o444),
            "rotation-media.request.template.json": (canonical_json_bytes(_kit_template("rotate-both-transition")), 0o444),
            "checkpoint-media.request.template.json": (canonical_json_bytes(_kit_template("ceremony-checkpoint")), 0o444),
            "gate1-media.request.template.json": (canonical_json_bytes(_kit_template("gate1-import")), 0o444),
            "transcript-media.request.template.json": (canonical_json_bytes(_kit_template("signed-transcript")), 0o444),
            "witness-checkpoint.request.template.json": (canonical_json_bytes({
                "format": "securityops-phase42-witness-checkpoint-request-template/1",
                "witness_id": "OUT_OF_BAND_WITNESS_ID",
                "witness_primary_fingerprint": ZERO_FINGERPRINT,
                "witness_signing_fingerprint": ZERO_FINGERPRINT,
                "witness_keyring_sha256": ZERO_SHA,
                "challenge_nonce": ZERO_SHA,
                "ceremony_state": "CEREMONY_STATE.json",
                "ceremony_store": "CEREMONY_STORE.json",
                "trust_state": "TRUST_STATE.json",
                "media_package_digest": ZERO_SHA,
                "fixture": False,
                "production_dispatch_allowed": False,
                "iso_release_allowed": False,
            }), 0o444),
            "transcript.request.template.json": (canonical_json_bytes({
                "format": "securityops-phase42-transcript-request-template/1",
                "transcript_id": "OPERATOR_ASSIGNED_TRANSCRIPT_ID",
                "challenge_nonce": ZERO_SHA,
                "transition_verifications": [],
                "ceremony_states": [],
                "media_package_digests": [],
                "transcript_alone_can_close_gate1": False,
                "production_dispatch_allowed": False,
                "iso_release_allowed": False,
            }), 0o444),
            "scripts/export-media.py": (command_stub("export-media"), 0o555),
            "scripts/import-media.py": (command_stub("import-media"), 0o555),
            "scripts/verify-witness.py": (command_stub("verify-witness"), 0o555),
            "scripts/verify-transcript.py": (command_stub("verify-transcript"), 0o555),
        }
        if tuple(sorted(files)) != tuple(sorted(KIT_FILES)):
            raise PolicyError("Phase 42 operator-kit inventory drifted")
        records = []
        for relative in KIT_FILES:
            payload, mode = files[relative]
            target = temporary / relative
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            fd = os.open(
                target,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
                mode,
            )
            try:
                os.fchmod(fd, mode)
                view = memoryview(payload)
                while view:
                    count = os.write(fd, view)
                    if count <= 0:
                        raise PolicyError("Phase 42 operator-kit write did not complete")
                    view = view[count:]
                os.fsync(fd)
            finally:
                os.close(fd)
            records.append({
                "path": relative, "sha256": hashlib.sha256(payload).hexdigest(),
                "bytes": len(payload), "mode": mode,
            })
        media._fsync_directory(temporary / "scripts")
        media._fsync_directory(temporary)
        media._rename_noreplace(
            temporary, destination, context="Phase 42 operator kit")
        temporary = None
        unsigned = {
            "format": KIT_FORMAT,
            "status": "PASS_PHASE42_DETERMINISTIC_SECRET_FREE_OFFLINE_OPERATOR_KIT",
            "contract_digest": offline_ceremony_contract_digest(),
            "files": records,
            "file_count": len(records),
            "contains_secret_keys": False,
            "generates_production_secret_keys": False,
            "performs_signing": False,
            "creates_owner_authority": False,
            "creates_witness_authority": False,
            "owner_authenticated": False,
            "witness_authenticated": False,
            "gate1_approved": False,
            "production_gates_approved": 0,
            "production_dispatch_allowed": False,
            "iso_release_allowed": False,
        }
        return {**unsigned, "kit_digest": _digest(KIT_DOMAIN, unsigned)}
    finally:
        if temporary is not None and temporary.exists():
            shutil.rmtree(temporary)
