# CodeMark v1 project=4c63e0fe-589c-4944-8449-97e211a38b72 file=49846c7fb88b59bcb5fe18d244b2335b owner="Cristian Cezar Mois\u00e9s"
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Phase 43 offline chain-of-custody and Gate 1 preflight boundary.

This module adds an independently signed transport-custody chain around the
Phase 42 deterministic media packages and a fail-closed preflight receipt for
Gate 1.  Custody proves who handled which measured package under locally pinned
verification identities.  It does *not* create owner, publisher, witness, or
build-node authority and it cannot approve Gate 1 by itself.
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
import shutil
import tempfile
from typing import Any, Final, Mapping, Sequence

try:
    from . import phase39_owner_execution as phase39
    from . import phase40_owner_trust as phase40
    from . import phase40_gate1_admission as phase40_gate1
    from . import phase41_owner_ceremony as phase41
    from . import phase42_media as phase42_media
    from . import phase42_offline_ceremony as phase42_ceremony
except ImportError:  # pragma: no cover - installed Guix Center sibling copy
    import phase39_owner_execution as phase39  # type: ignore[no-redef]
    import phase40_owner_trust as phase40  # type: ignore[no-redef]
    import phase40_gate1_admission as phase40_gate1  # type: ignore[no-redef]
    import phase41_owner_ceremony as phase41  # type: ignore[no-redef]
    import phase42_media as phase42_media  # type: ignore[no-redef]
    import phase42_offline_ceremony as phase42_ceremony  # type: ignore[no-redef]

PolicyError = phase40.PolicyError
canonical_json_bytes = phase40.canonical_json_bytes

CONTRACT_FORMAT: Final[str] = "securityops-phase43-offline-custody-contract/1"
EVENT_FORMAT: Final[str] = "securityops-phase43-custody-event/1"
EVENT_VERIFICATION_FORMAT: Final[str] = "securityops-phase43-custody-event-verification/1"
LEDGER_FORMAT: Final[str] = "securityops-phase43-custody-ledger/1"
PREFLIGHT_FORMAT: Final[str] = "securityops-phase43-gate1-preflight/1"
STATUS: Final[str] = "PASS_PHASE43_OFFLINE_CUSTODY_GATE1_PREFLIGHT_BOUNDARY"
BLOCKED_STATUS: Final[str] = "BLOCKED_PHASE43_REAL_CUSTODY_AND_GATE1_CHAIN_REQUIRED"

CONTRACT_DOMAIN: Final[bytes] = b"SECURITYOPS-PHASE43-OFFLINE-CUSTODY-CONTRACT-V1\x00"
EVENT_DOMAIN: Final[bytes] = b"SECURITYOPS-PHASE43-CUSTODY-EVENT-V1\x00"
EVENT_VERIFICATION_DOMAIN: Final[bytes] = b"SECURITYOPS-PHASE43-CUSTODY-EVENT-VERIFICATION-V1\x00"
LEDGER_DOMAIN: Final[bytes] = b"SECURITYOPS-PHASE43-CUSTODY-LEDGER-V1\x00"
PREFLIGHT_DOMAIN: Final[bytes] = b"SECURITYOPS-PHASE43-GATE1-PREFLIGHT-V1\x00"
MEDIA_INVENTORY_DOMAIN: Final[bytes] = b"SECURITYOPS-PHASE43-MEDIA-INVENTORY-V1\x00"
NEGATIVE_DOMAIN: Final[bytes] = b"SECURITYOPS-PHASE43-CUSTODY-NEGATIVE-V1\x00"
KIT_DOMAIN: Final[bytes] = b"SECURITYOPS-PHASE43-CUSTODY-KIT-V1\x00"
KIT_FORMAT: Final[str] = "securityops-phase43-offline-custody-kit/1"
KIT_FILES: Final[tuple[str, ...]] = (
    "README.md", "README.pt-BR.md",
    "phase43-offline-custody-contract.json",
    "phase43-custody-event.schema.json",
    "phase43-custody-ledger.schema.json",
    "phase43-gate1-preflight.schema.json",
    "custody-pins.template.json",
    "custody-event.request.template.json",
    "gate1-preflight.request.template.json",
    "scripts/create-event.py", "scripts/verify-event.py",
    "scripts/verify-ledger.py", "scripts/verify-preflight.py",
)

PHASE42_IDENTITIES: Final[dict[str, str]] = {
    "runtime_commit": "ec67d0d3cbffe8d1312bd5eec594010e70c67734",
    "runtime_tree": "e1408141711b1b273893fc8d1529c20f5b049cf8",
    "securityops_os_commit": "26a8630b243653fe4d038d60678df5bb66f31b31",
    "securityops_os_tree": "49ad43d5fa12fb68a340378309b19cba7c95f14c",
    "stable_v1_13_0": "8373fd789c9a525d6128abfd3d7a93ad4db3348b",
}
PHASE42_CONTRACT_DIGEST: Final[str] = (
    "63515c52c4c40d4d0f5415a320fa9ea00908419b1da29cc1b865d8bf4c029145"
)
ZERO_SHA: Final[str] = "0" * 64
MAX_EVENT_BYTES: Final[int] = 4 * 1024 * 1024
MAX_LEDGER_BYTES: Final[int] = 16 * 1024 * 1024
MAX_LEDGER_RECORDS: Final[int] = 4096
MAX_EVENT_LIFETIME: Final[int] = 30 * 24 * 60 * 60

_SHA = re.compile(r"[0-9a-f]{64}\Z")
_FPR = re.compile(r"[0-9A-F]{40}\Z")
_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")

EVENT_ROLE: Final[dict[str, str]] = {
    "exported": "export-operator",
    "received": "receiving-operator",
    "verified": "independent-verifier",
    "imported": "receiving-operator",
    "quarantined": "receiving-operator",
}
TERMINAL_EVENTS: Final[tuple[str, ...]] = ("imported", "quarantined")

NEGATIVE_CASES: Final[tuple[str, ...]] = (
    "event-extra-field", "event-contract-drift", "event-zero-challenge",
    "event-role-mismatch", "event-profile-unknown", "event-review-mismatch",
    "event-signature-optional", "event-keyring-pin-mismatch", "event-primary-signing-relationship-mismatch",
    "event-path-reopen-after-measurement", "event-fixture-promotion",
    "ledger-first-event-not-exported", "ledger-sequence-gap",
    "ledger-previous-digest-mismatch", "ledger-package-substitution",
    "ledger-challenge-substitution", "ledger-exporter-receiver-key-reuse",
    "ledger-receiver-verifier-key-reuse", "ledger-importer-differs-from-receiver",
    "ledger-event-after-terminal", "ledger-quarantine-promotes-transport",
    "preflight-profile-not-gate1", "preflight-job-challenge-mismatch",
    "preflight-phase39-phase40-mismatch", "preflight-witness-state-mismatch",
    "preflight-transcript-state-mismatch", "preflight-fixture-promotion",
    "preflight-custody-only-approval", "preflight-production-promotion",
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


def event_schema() -> dict[str, Any]:
    sha = {"type": "string", "pattern": "^[0-9a-f]{64}$"}
    fpr = {"type": "string", "pattern": "^[0-9A-F]{40}$"}
    required = [
        "format", "contract_digest", "phase42_contract_digest", "sequence",
        "created_unix", "expires_unix", "challenge_nonce", "transfer_id",
        "event_type", "operator_role", "station_id",
        "operator_primary_fingerprint", "operator_signing_fingerprint",
        "operator_keyring_sha256", "package_profile", "package_sequence",
        "package_manifest_digest", "media_verification_digest",
        "media_review_digest", "media_inventory_digest",
        "previous_event_digest", "fixture_mode", "transport_integrity_verified",
        "signature_present", "operator_authenticated", "owner_authority_created",
        "gate1_approved", "production_gates_approved",
        "production_dispatch_allowed", "iso_release_allowed", "event_digest",
    ]
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://securityops.co/schemas/guix-center/phase43-custody-event.schema.json",
        "title": "Security Ops Phase 43 signed offline-media custody event",
        "type": "object", "additionalProperties": False,
        "required": required,
        "properties": {
            "format": {"const": EVENT_FORMAT}, "contract_digest": sha,
            "phase42_contract_digest": sha,
            "sequence": {"type": "integer", "minimum": 1},
            "created_unix": {"type": "integer", "minimum": 1},
            "expires_unix": {"type": "integer", "minimum": 1},
            "challenge_nonce": sha,
            "transfer_id": {"type": "string", "minLength": 1, "maxLength": 128},
            "event_type": {"enum": list(EVENT_ROLE)},
            "operator_role": {"enum": sorted(set(EVENT_ROLE.values()))},
            "station_id": {"type": "string", "minLength": 1, "maxLength": 128},
            "operator_primary_fingerprint": fpr,
            "operator_signing_fingerprint": fpr,
            "operator_keyring_sha256": sha,
            "package_profile": {"enum": list(phase42_media.PACKAGE_PROFILES)},
            "package_sequence": {"type": "integer", "minimum": 1},
            "package_manifest_digest": sha,
            "media_verification_digest": sha,
            "media_review_digest": sha,
            "media_inventory_digest": sha,
            "previous_event_digest": sha,
            "fixture_mode": {"type": "boolean"},
            "transport_integrity_verified": {"const": True},
            "signature_present": {"const": False},
            "operator_authenticated": {"const": False},
            "owner_authority_created": {"const": False},
            "gate1_approved": {"const": False},
            "production_gates_approved": {"const": 0},
            "production_dispatch_allowed": {"const": False},
            "iso_release_allowed": {"const": False},
            "event_digest": sha,
        },
    }


def ledger_schema() -> dict[str, Any]:
    sha = {"type": "string", "pattern": "^[0-9a-f]{64}$"}
    fpr = {"type": "string", "pattern": "^[0-9A-F]{40}$"}
    record = {
        "type": "object", "additionalProperties": False,
        "required": [
            "sequence", "event_type", "event_digest", "verification_digest",
            "previous_event_digest", "operator_role", "station_id",
            "operator_signing_fingerprint", "signature_verified",
            "local_pin_verified", "operator_authenticated", "fixture_mode",
        ],
        "properties": {
            "sequence": {"type": "integer", "minimum": 1},
            "event_type": {"enum": list(EVENT_ROLE)},
            "event_digest": sha, "verification_digest": sha,
            "previous_event_digest": sha,
            "operator_role": {"enum": sorted(set(EVENT_ROLE.values()))},
            "station_id": {"type": "string", "minLength": 1, "maxLength": 128},
            "operator_signing_fingerprint": fpr,
            "signature_verified": {"const": True},
            "local_pin_verified": {"const": True},
            "operator_authenticated": {"type": "boolean"},
            "fixture_mode": {"type": "boolean"},
        },
    }
    required = [
        "format", "contract_digest", "generation", "transfer_id",
        "challenge_nonce", "package_profile", "package_sequence",
        "package_manifest_digest", "media_verification_digest",
        "media_review_digest", "media_inventory_digest", "status",
        "current_event_digest", "records", "fixture_mode",
        "all_signatures_verified", "dual_control_verified",
        "transport_integrity_verified", "custody_chain_authenticated",
        "transport_accepted", "package_quarantined", "owner_authority_created",
        "eligible_for_phase41_decision", "gate1_approved",
        "production_gates_approved", "production_dispatch_allowed",
        "iso_release_allowed", "ledger_digest",
    ]
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://securityops.co/schemas/guix-center/phase43-custody-ledger.schema.json",
        "title": "Security Ops Phase 43 signed media chain-of-custody ledger",
        "type": "object", "additionalProperties": False,
        "required": required,
        "properties": {
            "format": {"const": LEDGER_FORMAT}, "contract_digest": sha,
            "generation": {"type": "integer", "minimum": 0},
            "transfer_id": {"type": "string", "maxLength": 128},
            "challenge_nonce": sha,
            "package_profile": {"type": "string", "maxLength": 128},
            "package_sequence": {"type": "integer", "minimum": 0},
            "package_manifest_digest": sha,
            "media_verification_digest": sha,
            "media_review_digest": sha,
            "media_inventory_digest": sha,
            "status": {"enum": ["empty", *EVENT_ROLE]},
            "current_event_digest": sha,
            "records": {"type": "array", "maxItems": MAX_LEDGER_RECORDS, "items": record},
            "fixture_mode": {"type": "boolean"},
            "all_signatures_verified": {"type": "boolean"},
            "dual_control_verified": {"type": "boolean"},
            "transport_integrity_verified": {"type": "boolean"},
            "custody_chain_authenticated": {"type": "boolean"},
            "transport_accepted": {"type": "boolean"},
            "package_quarantined": {"type": "boolean"},
            "owner_authority_created": {"const": False},
            "eligible_for_phase41_decision": {"const": False},
            "gate1_approved": {"const": False},
            "production_gates_approved": {"const": 0},
            "production_dispatch_allowed": {"const": False},
            "iso_release_allowed": {"const": False},
            "ledger_digest": sha,
        },
    }


def preflight_schema() -> dict[str, Any]:
    sha = {"type": "string", "pattern": "^[0-9a-f]{64}$"}
    required = [
        "format", "contract_digest", "created_unix", "transfer_id",
        "challenge_nonce", "custody_ledger_digest", "custody_status",
        "custody_chain_authenticated", "package_profile",
        "package_manifest_digest", "ceremony_state_digest",
        "ceremony_store_digest", "trust_state_digest", "trust_root_digest",
        "input_closure_digest", "phase39_job_digest", "phase39_result_digest",
        "phase39_verification_digest", "phase39_exchange_verified",
        "phase40_semantic_receipt_digest", "phase40_semantics_verified",
        "witness_checkpoint_digest", "witness_verification_digest",
        "witness_authenticated", "transcript_digest",
        "transcript_verification_digest", "transcript_authenticated",
        "fixture_mode", "all_bindings_verified",
        "eligible_for_phase41_decision", "phase41_decision_required",
        "gate1_approved", "production_gates_approved",
        "production_dispatch_allowed", "iso_release_allowed",
        "iso_bytes_present", "preflight_digest",
    ]
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://securityops.co/schemas/guix-center/phase43-gate1-preflight.schema.json",
        "title": "Security Ops Phase 43 Gate 1 preflight receipt",
        "type": "object", "additionalProperties": False,
        "required": required,
        "properties": {
            "format": {"const": PREFLIGHT_FORMAT}, "contract_digest": sha,
            "created_unix": {"type": "integer", "minimum": 1},
            "transfer_id": {"type": "string", "minLength": 1, "maxLength": 128},
            "challenge_nonce": sha, "custody_ledger_digest": sha,
            "custody_status": {"enum": ["imported", "quarantined"]},
            "custody_chain_authenticated": {"type": "boolean"},
            "package_profile": {"const": "gate1-import"},
            "package_manifest_digest": sha,
            "ceremony_state_digest": sha, "ceremony_store_digest": sha,
            "trust_state_digest": sha, "trust_root_digest": sha,
            "input_closure_digest": sha, "phase39_job_digest": sha,
            "phase39_result_digest": sha, "phase39_verification_digest": sha,
            "phase39_exchange_verified": {"type": "boolean"},
            "phase40_semantic_receipt_digest": sha,
            "phase40_semantics_verified": {"type": "boolean"},
            "witness_checkpoint_digest": sha, "witness_verification_digest": sha,
            "witness_authenticated": {"type": "boolean"},
            "transcript_digest": sha, "transcript_verification_digest": sha,
            "transcript_authenticated": {"type": "boolean"},
            "fixture_mode": {"type": "boolean"},
            "all_bindings_verified": {"const": True},
            "eligible_for_phase41_decision": {"type": "boolean"},
            "phase41_decision_required": {"const": True},
            "gate1_approved": {"const": False},
            "production_gates_approved": {"const": 0},
            "production_dispatch_allowed": {"const": False},
            "iso_release_allowed": {"const": False},
            "iso_bytes_present": {"const": False},
            "preflight_digest": sha,
        },
    }


def _contract_unsigned() -> dict[str, Any]:
    schemas = {
        "custody_event": {
            "id": event_schema()["$id"],
            "canonical_sha256": _schema_digest(event_schema()),
        },
        "custody_ledger": {
            "id": ledger_schema()["$id"],
            "canonical_sha256": _schema_digest(ledger_schema()),
        },
        "gate1_preflight": {
            "id": preflight_schema()["$id"],
            "canonical_sha256": _schema_digest(preflight_schema()),
        },
    }
    return {
        "format": CONTRACT_FORMAT,
        "status": STATUS,
        "execution_status": BLOCKED_STATUS,
        "phase42_identities": dict(PHASE42_IDENTITIES),
        "phase42_contract_digest": PHASE42_CONTRACT_DIGEST,
        "phase39_contract_digest": phase39.phase39_contract_digest(),
        "phase40_owner_contract_digest": phase40.phase40_contract_digest(),
        "phase40_gate1_contract_digest": phase40_gate1.gate1_contract_digest(),
        "phase41_ceremony_contract_digest": phase41.ceremony_contract_digest(),
        "phase42_offline_ceremony_contract_digest": phase42_ceremony.offline_ceremony_contract_digest(),
        "schemas": {"additional_properties_allowed": False, **schemas},
        "custody_policy": {
            "event_order": ["exported", "received", "verified", "imported"],
            "quarantine_is_terminal": True,
            "all_events_require_detached_signature": True,
            "all_keyrings_require_local_sha256_pin": True,
            "nonfixture_keyring_primary_signing_relationship_required": True,
            "signature_inputs_use_kernel_sealed_memfds": True,
            "original_paths_reopened_after_measurement": False,
            "export_receiver_identity_reuse_allowed": False,
            "receiver_verifier_identity_reuse_allowed": False,
            "importer_must_match_receiver": True,
            "package_challenge_profile_sequence_and_digests_bound": True,
            "ledger_is_monotonic_and_replay_resistant": True,
            "ledger_publication_is_atomic_and_locked": True,
            "custody_proves_owner_authority": False,
            "custody_alone_can_close_gate1": False,
        },
        "gate1_preflight_policy": {
            "exact_gate1_import_profile_required": True,
            "authenticated_custody_chain_required": True,
            "active_phase41_ceremony_state_required": True,
            "phase39_dual_signed_exchange_required": True,
            "phase40_semantic_admission_required": True,
            "phase42_independent_witness_required": True,
            "phase42_owner_and_witness_transcript_required": True,
            "all_challenges_and_receipt_digests_cross_bound": True,
            "fixture_preflight_can_be_eligible": False,
            "preflight_itself_can_close_gate1": False,
            "phase41_monotonic_decision_required": True,
        },
        "network_fetch_allowed": False,
        "production_gates_approved": 0,
        "production_dispatch_allowed": False,
        "iso_release_allowed": False,
    }


def offline_custody_contract() -> dict[str, Any]:
    unsigned = _contract_unsigned()
    return {**unsigned, "contract_digest": _digest(CONTRACT_DOMAIN, unsigned)}


def offline_custody_contract_digest() -> str:
    return str(offline_custody_contract()["contract_digest"])


def parse_offline_custody_contract(value: Mapping[str, Any]) -> dict[str, Any]:
    expected = offline_custody_contract()
    if type(value) is not dict or value != expected:
        raise PolicyError("Phase 43 offline custody contract differs from policy")
    return json.loads(canonical_json_bytes(value))


def _inventory_digest(verified: phase42_media.VerifiedMediaPackage) -> str:
    media_records = verified.manifest["media_inventory"]
    return _digest(MEDIA_INVENTORY_DOMAIN, {"media": media_records})


def create_custody_event(
    *, verified_media: phase42_media.VerifiedMediaPackage,
    review: Mapping[str, Any], sequence: int, created_unix: int,
    expires_unix: int, challenge_nonce: str, transfer_id: str,
    event_type: str, station_id: str, operator_primary_fingerprint: str,
    operator_signing_fingerprint: str, operator_keyring_sha256: str,
    previous_event_digest: str = ZERO_SHA, fixture_mode: bool = False,
) -> dict[str, Any]:
    if not isinstance(verified_media, phase42_media.VerifiedMediaPackage):
        raise PolicyError("Phase 43 requires a verified Phase 42 media package")
    parsed_review = phase42_media.parse_review_report(review)
    if (
        parsed_review["manifest_digest"] != verified_media.manifest_digest
        or parsed_review["review_digest"] == ZERO_SHA
        or parsed_review["challenge_nonce"] != verified_media.manifest["challenge_nonce"]
        or parsed_review["package_sequence"] != verified_media.manifest["package_sequence"]
        or parsed_review["profile"] != verified_media.manifest["profile"]
    ):
        raise PolicyError("Phase 43 media review differs from the verified package")
    if type(sequence) is not int or sequence < 1:
        raise PolicyError("Phase 43 custody event sequence is invalid")
    if (
        type(created_unix) is not int or type(expires_unix) is not int
        or created_unix < 1 or not created_unix < expires_unix
        or expires_unix > created_unix + MAX_EVENT_LIFETIME
    ):
        raise PolicyError("Phase 43 custody event lifetime is invalid")
    challenge = _sha(challenge_nonce, "Phase 43 custody challenge")
    if challenge != verified_media.manifest["challenge_nonce"]:
        raise PolicyError("Phase 43 custody challenge differs from the media package")
    transfer = _token(transfer_id, "Phase 43 custody transfer ID")
    event = _token(event_type, "Phase 43 custody event type")
    if event not in EVENT_ROLE:
        raise PolicyError("Phase 43 custody event type is unknown")
    station = _token(station_id, "Phase 43 custody station")
    primary = _fpr(operator_primary_fingerprint, "Phase 43 custody operator primary")
    signer = _fpr(operator_signing_fingerprint, "Phase 43 custody operator signer")
    keyring = _sha(operator_keyring_sha256, "Phase 43 custody operator keyring")
    previous = _sha(previous_event_digest, "Phase 43 previous event", allow_zero=True)
    if sequence == 1 and previous != ZERO_SHA:
        raise PolicyError("Phase 43 first custody event must use a zero previous digest")
    if sequence > 1 and previous == ZERO_SHA:
        raise PolicyError("Phase 43 later custody events require a previous digest")
    if type(fixture_mode) is not bool:
        raise PolicyError("Phase 43 custody fixture flag is invalid")
    if fixture_mode != verified_media.fixture_mode or fixture_mode != parsed_review["fixture_mode"]:
        raise PolicyError("Phase 43 custody fixture state differs from the media package")
    unsigned = {
        "format": EVENT_FORMAT,
        "contract_digest": offline_custody_contract_digest(),
        "phase42_contract_digest": PHASE42_CONTRACT_DIGEST,
        "sequence": sequence,
        "created_unix": created_unix,
        "expires_unix": expires_unix,
        "challenge_nonce": challenge,
        "transfer_id": transfer,
        "event_type": event,
        "operator_role": EVENT_ROLE[event],
        "station_id": station,
        "operator_primary_fingerprint": primary,
        "operator_signing_fingerprint": signer,
        "operator_keyring_sha256": keyring,
        "package_profile": verified_media.manifest["profile"],
        "package_sequence": verified_media.manifest["package_sequence"],
        "package_manifest_digest": verified_media.manifest_digest,
        "media_verification_digest": verified_media.verification_digest,
        "media_review_digest": parsed_review["review_digest"],
        "media_inventory_digest": _inventory_digest(verified_media),
        "previous_event_digest": previous,
        "fixture_mode": fixture_mode,
        "transport_integrity_verified": True,
        "signature_present": False,
        "operator_authenticated": False,
        "owner_authority_created": False,
        "gate1_approved": False,
        "production_gates_approved": 0,
        "production_dispatch_allowed": False,
        "iso_release_allowed": False,
    }
    return {**unsigned, "event_digest": _digest(EVENT_DOMAIN, unsigned)}


def parse_custody_event(value: Mapping[str, Any], *, now_unix: int | None = None) -> dict[str, Any]:
    required = set(event_schema()["required"])
    if type(value) is not dict or set(value) != required:
        raise PolicyError("Phase 43 custody event fields are not closed")
    candidate = json.loads(canonical_json_bytes(value))
    if candidate["format"] != EVENT_FORMAT:
        raise PolicyError("Phase 43 custody event format is invalid")
    if candidate["contract_digest"] != offline_custody_contract_digest():
        raise PolicyError("Phase 43 custody event contract drifted")
    if candidate["phase42_contract_digest"] != PHASE42_CONTRACT_DIGEST:
        raise PolicyError("Phase 43 custody event Phase 42 contract drifted")
    if type(candidate["sequence"]) is not int or candidate["sequence"] < 1:
        raise PolicyError("Phase 43 custody event sequence is invalid")
    if (
        type(candidate["created_unix"]) is not int
        or type(candidate["expires_unix"]) is not int
        or candidate["created_unix"] < 1
        or not candidate["created_unix"] < candidate["expires_unix"]
        or candidate["expires_unix"] > candidate["created_unix"] + MAX_EVENT_LIFETIME
    ):
        raise PolicyError("Phase 43 custody event lifetime is invalid")
    if now_unix is not None and not candidate["created_unix"] <= now_unix <= candidate["expires_unix"]:
        raise PolicyError("Phase 43 custody event is not valid at the supplied time")
    for field in (
        "challenge_nonce", "operator_keyring_sha256", "package_manifest_digest",
        "media_verification_digest", "media_review_digest", "media_inventory_digest",
    ):
        _sha(candidate[field], f"Phase 43 custody event {field}")
    _sha(candidate["previous_event_digest"], "Phase 43 previous event", allow_zero=True)
    for field in ("transfer_id", "station_id"):
        _token(candidate[field], f"Phase 43 custody event {field}")
    for field in ("operator_primary_fingerprint", "operator_signing_fingerprint"):
        _fpr(candidate[field], f"Phase 43 custody event {field}")
    event_type = candidate["event_type"]
    if event_type not in EVENT_ROLE or candidate["operator_role"] != EVENT_ROLE[event_type]:
        raise PolicyError("Phase 43 custody event role is invalid")
    if candidate["package_profile"] not in phase42_media.PACKAGE_PROFILES:
        raise PolicyError("Phase 43 custody package profile is unknown")
    if type(candidate["package_sequence"]) is not int or candidate["package_sequence"] < 1:
        raise PolicyError("Phase 43 custody package sequence is invalid")
    if type(candidate["fixture_mode"]) is not bool:
        raise PolicyError("Phase 43 custody fixture flag is invalid")
    if candidate["sequence"] == 1 and candidate["previous_event_digest"] != ZERO_SHA:
        raise PolicyError("Phase 43 first custody event previous digest is invalid")
    if candidate["sequence"] > 1 and candidate["previous_event_digest"] == ZERO_SHA:
        raise PolicyError("Phase 43 later custody event previous digest is invalid")
    if (
        candidate["transport_integrity_verified"] is not True
        or candidate["signature_present"] is not False
        or candidate["operator_authenticated"] is not False
        or candidate["owner_authority_created"] is not False
        or candidate["gate1_approved"] is not False
        or candidate["production_gates_approved"] != 0
        or candidate["production_dispatch_allowed"] is not False
        or candidate["iso_release_allowed"] is not False
    ):
        raise PolicyError("Phase 43 unsigned custody event attempted authority promotion")
    unsigned = {key: candidate[key] for key in candidate if key != "event_digest"}
    if candidate["event_digest"] != _digest(EVENT_DOMAIN, unsigned):
        raise PolicyError("Phase 43 custody event digest is invalid")
    return candidate


@dataclass(frozen=True)
class VerifiedCustodyEvent:
    document: dict[str, Any]
    signed_input_sha256: dict[str, str]
    signature_verified: bool
    local_pin_verified: bool
    operator_authenticated: bool
    verification_digest: str

    @property
    def fixture_mode(self) -> bool:
        return bool(self.document["fixture_mode"])

    def to_dict(self) -> dict[str, Any]:
        return {
            "format": EVENT_VERIFICATION_FORMAT,
            "event_digest": self.document["event_digest"],
            "sequence": self.document["sequence"],
            "event_type": self.document["event_type"],
            "operator_role": self.document["operator_role"],
            "operator_signing_fingerprint": self.document["operator_signing_fingerprint"],
            "signed_input_sha256": dict(self.signed_input_sha256),
            "signature_verified": self.signature_verified,
            "local_pin_verified": self.local_pin_verified,
            "fixture_mode": self.fixture_mode,
            "operator_authenticated": self.operator_authenticated,
            "owner_authority_created": False,
            "gate1_approved": False,
            "production_gates_approved": 0,
            "production_dispatch_allowed": False,
            "iso_release_allowed": False,
            "verification_digest": self.verification_digest,
        }


def verify_signed_custody_event(
    *, event_path: Path, signature_path: Path, keyring_path: Path,
    expected_operator_primary_fingerprint: str,
    expected_operator_signing_fingerprint: str,
    expected_operator_keyring_sha256: str,
    now_unix: int, gpgv_executable: str | Path = "/usr/bin/gpgv",
    gpg_executable: str | Path = "/usr/bin/gpg",
) -> VerifiedCustodyEvent:
    event_meta, event_bytes = phase40.measure_file(
        event_path, maximum=MAX_EVENT_BYTES, context="Phase 43 custody event")
    signature_meta, signature = phase40.measure_file(
        signature_path, maximum=phase40.MAX_SIGNATURE_BYTES,
        context="Phase 43 custody event signature")
    keyring_meta, keyring = phase40.measure_file(
        keyring_path, maximum=phase40.MAX_KEYRING_BYTES,
        context="Phase 43 custody verification keyring")
    document = parse_custody_event(
        _strict_json(event_bytes, "Phase 43 custody event"), now_unix=now_unix)
    expected_primary = _fpr(
        expected_operator_primary_fingerprint, "Phase 43 locally pinned operator primary")
    expected_signing = _fpr(
        expected_operator_signing_fingerprint, "Phase 43 locally pinned operator signer")
    expected_keyring = _sha(
        expected_operator_keyring_sha256, "Phase 43 locally pinned operator keyring")
    if (
        document["operator_primary_fingerprint"] != expected_primary
        or document["operator_signing_fingerprint"] != expected_signing
        or document["operator_keyring_sha256"] != expected_keyring
        or keyring_meta.sha256 != expected_keyring
    ):
        raise PolicyError("Phase 43 custody event differs from local operator pins")
    if not document["fixture_mode"]:
        phase40._inspect_verification_keyring_payload(  # type: ignore[attr-defined]
            measured=keyring_meta,
            payload=keyring,
            expected_primary_fingerprint=expected_primary,
            expected_signing_fingerprint=expected_signing,
            valid_through_unix=document["expires_unix"],
            gpg_executable=gpg_executable,
            fixture_mode=False,
        )
    phase39._verify_signature(  # type: ignore[attr-defined]
        payload=event_bytes,
        signature=signature,
        keyring=keyring,
        expected_fingerprint=expected_signing,
        gpgv_executable=gpgv_executable,
        fixture_mode=document["fixture_mode"],
        role="phase43-custody-event",
    )
    authenticated = bool(not document["fixture_mode"])
    signed_inputs = {
        "event": event_meta.sha256,
        "signature": signature_meta.sha256,
        "keyring": keyring_meta.sha256,
    }
    unsigned = {
        "format": EVENT_VERIFICATION_FORMAT,
        "event_digest": document["event_digest"],
        "sequence": document["sequence"],
        "event_type": document["event_type"],
        "operator_role": document["operator_role"],
        "operator_signing_fingerprint": expected_signing,
        "signed_input_sha256": signed_inputs,
        "signature_verified": True,
        "local_pin_verified": True,
        "fixture_mode": document["fixture_mode"],
        "operator_authenticated": authenticated,
        "owner_authority_created": False,
        "gate1_approved": False,
        "production_gates_approved": 0,
        "production_dispatch_allowed": False,
        "iso_release_allowed": False,
    }
    return VerifiedCustodyEvent(
        document=document,
        signed_input_sha256=signed_inputs,
        signature_verified=True,
        local_pin_verified=True,
        operator_authenticated=authenticated,
        verification_digest=_digest(EVENT_VERIFICATION_DOMAIN, unsigned),
    )


def empty_custody_ledger() -> dict[str, Any]:
    unsigned = {
        "format": LEDGER_FORMAT,
        "contract_digest": offline_custody_contract_digest(),
        "generation": 0,
        "transfer_id": "",
        "challenge_nonce": ZERO_SHA,
        "package_profile": "",
        "package_sequence": 0,
        "package_manifest_digest": ZERO_SHA,
        "media_verification_digest": ZERO_SHA,
        "media_review_digest": ZERO_SHA,
        "media_inventory_digest": ZERO_SHA,
        "status": "empty",
        "current_event_digest": ZERO_SHA,
        "records": [],
        "fixture_mode": False,
        "all_signatures_verified": False,
        "dual_control_verified": False,
        "transport_integrity_verified": False,
        "custody_chain_authenticated": False,
        "transport_accepted": False,
        "package_quarantined": False,
        "owner_authority_created": False,
        "eligible_for_phase41_decision": False,
        "gate1_approved": False,
        "production_gates_approved": 0,
        "production_dispatch_allowed": False,
        "iso_release_allowed": False,
    }
    return {**unsigned, "ledger_digest": _digest(LEDGER_DOMAIN, unsigned)}


def _expected_next(status: str, event_type: str) -> bool:
    allowed = {
        "empty": {"exported"},
        "exported": {"received", "quarantined"},
        "received": {"verified", "quarantined"},
        "verified": {"imported", "quarantined"},
        "imported": set(),
        "quarantined": set(),
    }
    return event_type in allowed[status]


def _record(verified: VerifiedCustodyEvent) -> dict[str, Any]:
    document = verified.document
    return {
        "sequence": document["sequence"],
        "event_type": document["event_type"],
        "event_digest": document["event_digest"],
        "verification_digest": verified.verification_digest,
        "previous_event_digest": document["previous_event_digest"],
        "operator_role": document["operator_role"],
        "station_id": document["station_id"],
        "operator_signing_fingerprint": document["operator_signing_fingerprint"],
        "signature_verified": verified.signature_verified,
        "local_pin_verified": verified.local_pin_verified,
        "operator_authenticated": verified.operator_authenticated,
        "fixture_mode": verified.fixture_mode,
    }


def append_custody_event(
    *, ledger: Mapping[str, Any], verified: VerifiedCustodyEvent,
) -> dict[str, Any]:
    current = parse_custody_ledger(ledger)
    if not isinstance(verified, VerifiedCustodyEvent):
        raise PolicyError("Phase 43 requires a verified custody event")
    event = parse_custody_event(verified.document)
    if not verified.signature_verified or not verified.local_pin_verified:
        raise PolicyError("Phase 43 custody event signature is incomplete")
    if current["status"] in TERMINAL_EVENTS:
        raise PolicyError("Phase 43 custody ledger is already terminal")
    if not _expected_next(current["status"], event["event_type"]):
        raise PolicyError("Phase 43 custody event order is invalid")
    if event["sequence"] != current["generation"] + 1:
        raise PolicyError("Phase 43 custody event sequence is not monotonic")
    if event["previous_event_digest"] != current["current_event_digest"]:
        raise PolicyError("Phase 43 custody event chain is discontinuous")
    if current["generation"] == 0:
        if event["sequence"] != 1 or event["event_type"] != "exported":
            raise PolicyError("Phase 43 custody chain must begin with export")
    else:
        for field in (
            "transfer_id", "challenge_nonce", "package_profile", "package_sequence",
            "package_manifest_digest", "media_verification_digest",
            "media_review_digest", "media_inventory_digest",
        ):
            if current[field] != event[field]:
                raise PolicyError(f"Phase 43 custody package binding changed: {field}")
    records = [dict(item) for item in current["records"]]
    if any(item["event_digest"] == event["event_digest"] for item in records):
        raise PolicyError("Phase 43 custody event is a replay")
    signers = {item["event_type"]: item["operator_signing_fingerprint"] for item in records}
    stations = {item["event_type"]: item["station_id"] for item in records}
    signer = event["operator_signing_fingerprint"]
    event_type = event["event_type"]
    if event_type == "received":
        if signer == signers.get("exported"):
            raise PolicyError("Phase 43 exporter and receiver identities must differ")
    if event_type == "verified":
        if signer in {signers.get("exported"), signers.get("received")}:
            raise PolicyError("Phase 43 independent verifier identity is not independent")
        if event["station_id"] != stations.get("received"):
            raise PolicyError("Phase 43 verifier station differs from the receiving station")
    if event_type in TERMINAL_EVENTS:
        receiver = signers.get("received")
        if receiver is None or signer != receiver:
            raise PolicyError("Phase 43 terminal event must be signed by the receiver")
        if event["station_id"] != stations.get("received"):
            raise PolicyError("Phase 43 terminal event station differs from the receiver")
    records.append(_record(verified))
    fixture_mode = bool(current["fixture_mode"] or verified.fixture_mode)
    all_signatures = all(
        item["signature_verified"] and item["local_pin_verified"] for item in records)
    distinct = False
    if {item["event_type"] for item in records} >= {"exported", "received", "verified"}:
        exporter = next(item["operator_signing_fingerprint"] for item in records if item["event_type"] == "exported")
        receiver = next(item["operator_signing_fingerprint"] for item in records if item["event_type"] == "received")
        verifier = next(item["operator_signing_fingerprint"] for item in records if item["event_type"] == "verified")
        distinct = len({exporter, receiver, verifier}) == 3
    custody_authenticated = bool(
        event_type == "imported" and all_signatures and distinct and not fixture_mode
        and all(item["operator_authenticated"] for item in records)
    )
    transport_integrity = bool(
        event_type in {"verified", "imported"} and all_signatures and not event_type == "quarantined"
    )
    unsigned = {
        "format": LEDGER_FORMAT,
        "contract_digest": offline_custody_contract_digest(),
        "generation": len(records),
        "transfer_id": event["transfer_id"],
        "challenge_nonce": event["challenge_nonce"],
        "package_profile": event["package_profile"],
        "package_sequence": event["package_sequence"],
        "package_manifest_digest": event["package_manifest_digest"],
        "media_verification_digest": event["media_verification_digest"],
        "media_review_digest": event["media_review_digest"],
        "media_inventory_digest": event["media_inventory_digest"],
        "status": event_type,
        "current_event_digest": event["event_digest"],
        "records": records,
        "fixture_mode": fixture_mode,
        "all_signatures_verified": all_signatures,
        "dual_control_verified": distinct,
        "transport_integrity_verified": transport_integrity,
        "custody_chain_authenticated": custody_authenticated,
        "transport_accepted": custody_authenticated,
        "package_quarantined": event_type == "quarantined",
        "owner_authority_created": False,
        "eligible_for_phase41_decision": False,
        "gate1_approved": False,
        "production_gates_approved": 0,
        "production_dispatch_allowed": False,
        "iso_release_allowed": False,
    }
    return {**unsigned, "ledger_digest": _digest(LEDGER_DOMAIN, unsigned)}


def parse_custody_ledger(value: Mapping[str, Any]) -> dict[str, Any]:
    required = set(ledger_schema()["required"])
    if type(value) is not dict or set(value) != required:
        raise PolicyError("Phase 43 custody ledger fields are not closed")
    candidate = json.loads(canonical_json_bytes(value))
    if candidate["format"] != LEDGER_FORMAT or candidate["contract_digest"] != offline_custody_contract_digest():
        raise PolicyError("Phase 43 custody ledger identity drifted")
    if type(candidate["generation"]) is not int or candidate["generation"] < 0:
        raise PolicyError("Phase 43 custody ledger generation is invalid")
    if type(candidate["records"]) is not list or len(candidate["records"]) != candidate["generation"]:
        raise PolicyError("Phase 43 custody ledger record count drifted")
    if len(candidate["records"]) > MAX_LEDGER_RECORDS:
        raise PolicyError("Phase 43 custody ledger is too large")
    status = candidate["status"]
    if status not in {"empty", *EVENT_ROLE}:
        raise PolicyError("Phase 43 custody ledger status is invalid")
    if candidate["generation"] == 0:
        empty = empty_custody_ledger()
        if candidate != empty:
            raise PolicyError("Phase 43 empty custody ledger differs from policy")
        return candidate
    for field in (
        "challenge_nonce", "package_manifest_digest", "media_verification_digest",
        "media_review_digest", "media_inventory_digest", "current_event_digest",
    ):
        _sha(candidate[field], f"Phase 43 custody ledger {field}")
    _token(candidate["transfer_id"], "Phase 43 custody ledger transfer ID")
    if candidate["package_profile"] not in phase42_media.PACKAGE_PROFILES:
        raise PolicyError("Phase 43 custody ledger profile is invalid")
    if type(candidate["package_sequence"]) is not int or candidate["package_sequence"] < 1:
        raise PolicyError("Phase 43 custody ledger package sequence is invalid")
    previous = ZERO_SHA
    expected_status = "empty"
    seen_digests: set[str] = set()
    signers: dict[str, str] = {}
    stations: dict[str, str] = {}
    fixture = False
    all_signatures = True
    all_authenticated = True
    for index, item in enumerate(candidate["records"], 1):
        expected_fields = set(ledger_schema()["properties"]["records"]["items"]["required"])
        if type(item) is not dict or set(item) != expected_fields:
            raise PolicyError("Phase 43 custody ledger record fields are not closed")
        if item["sequence"] != index or item["previous_event_digest"] != previous:
            raise PolicyError("Phase 43 custody ledger event chain is invalid")
        if not _expected_next(expected_status, item["event_type"]):
            raise PolicyError("Phase 43 custody ledger event order is invalid")
        if item["operator_role"] != EVENT_ROLE[item["event_type"]]:
            raise PolicyError("Phase 43 custody ledger role drifted")
        for field in ("event_digest", "verification_digest"):
            _sha(item[field], f"Phase 43 custody ledger record {field}")
        _sha(item["previous_event_digest"], "Phase 43 custody previous record", allow_zero=True)
        _fpr(item["operator_signing_fingerprint"], "Phase 43 custody ledger signer")
        _token(item["station_id"], "Phase 43 custody ledger station")
        if item["event_digest"] in seen_digests:
            raise PolicyError("Phase 43 custody ledger contains a replay")
        seen_digests.add(item["event_digest"])
        if item["signature_verified"] is not True or item["local_pin_verified"] is not True:
            raise PolicyError("Phase 43 custody ledger contains an unverified signature")
        if type(item["operator_authenticated"]) is not bool or type(item["fixture_mode"]) is not bool:
            raise PolicyError("Phase 43 custody ledger authentication flags are invalid")
        signers[item["event_type"]] = item["operator_signing_fingerprint"]
        stations[item["event_type"]] = item["station_id"]
        previous = item["event_digest"]
        expected_status = item["event_type"]
        fixture = fixture or item["fixture_mode"]
        all_signatures = all_signatures and item["signature_verified"] and item["local_pin_verified"]
        all_authenticated = all_authenticated and item["operator_authenticated"]
    if status != expected_status or candidate["current_event_digest"] != previous:
        raise PolicyError("Phase 43 custody ledger terminal identity drifted")
    if "received" in signers and signers.get("exported") == signers["received"]:
        raise PolicyError("Phase 43 custody ledger exporter/receiver identity reuse detected")
    distinct = False
    if {"exported", "received", "verified"} <= set(signers):
        distinct = len({signers["exported"], signers["received"], signers["verified"]}) == 3
        if not distinct:
            raise PolicyError("Phase 43 custody ledger dual control is invalid")
        if stations["received"] != stations["verified"]:
            raise PolicyError("Phase 43 custody ledger verification station drifted")
    if status in TERMINAL_EVENTS:
        if signers.get(status) != signers.get("received") or stations.get(status) != stations.get("received"):
            raise PolicyError("Phase 43 custody terminal signer/station drifted")
    custody_authenticated = bool(
        status == "imported" and all_signatures and all_authenticated and distinct and not fixture
    )
    transport_integrity = bool(status in {"verified", "imported"} and all_signatures)
    expected_bools = {
        "fixture_mode": fixture,
        "all_signatures_verified": all_signatures,
        "dual_control_verified": distinct,
        "transport_integrity_verified": transport_integrity,
        "custody_chain_authenticated": custody_authenticated,
        "transport_accepted": custody_authenticated,
        "package_quarantined": status == "quarantined",
    }
    for field, expected in expected_bools.items():
        if candidate[field] is not expected:
            raise PolicyError(f"Phase 43 custody ledger {field} relationship drifted")
    if (
        candidate["owner_authority_created"] is not False
        or candidate["eligible_for_phase41_decision"] is not False
        or candidate["gate1_approved"] is not False
        or candidate["production_gates_approved"] != 0
        or candidate["production_dispatch_allowed"] is not False
        or candidate["iso_release_allowed"] is not False
    ):
        raise PolicyError("Phase 43 custody ledger attempted authority promotion")
    unsigned = {key: candidate[key] for key in candidate if key != "ledger_digest"}
    if candidate["ledger_digest"] != _digest(LEDGER_DOMAIN, unsigned):
        raise PolicyError("Phase 43 custody ledger digest is invalid")
    return candidate


def _load_ledger(path: Path) -> dict[str, Any] | None:
    if not path.exists() and not path.is_symlink():
        return None
    _, payload = phase40.measure_file(
        path, maximum=MAX_LEDGER_BYTES, context="Phase 43 custody ledger")
    return parse_custody_ledger(_strict_json(payload, "Phase 43 custody ledger"))


def publish_custody_event(path: Path, verified: VerifiedCustodyEvent) -> dict[str, Any]:
    destination = path.absolute()
    parent = phase41._private_parent(destination, "Phase 43 custody ledger")  # type: ignore[attr-defined]
    lock_path = parent / f".{destination.name}.lock"
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        lock_fd = os.open(lock_path, flags, 0o600)
    except OSError as exc:
        raise PolicyError("Phase 43 custody ledger lock cannot be opened") from exc
    try:
        os.fchmod(lock_fd, 0o600)
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        current = _load_ledger(destination) or empty_custody_ledger()
        updated = append_custody_event(ledger=current, verified=verified)
        phase41._atomic_write(  # type: ignore[attr-defined]
            destination, canonical_json_bytes(updated), mode=0o600)
        return updated
    finally:
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
        finally:
            os.close(lock_fd)


def create_gate1_preflight(
    *, created_unix: int, custody_ledger: Mapping[str, Any],
    ceremony_state: Mapping[str, Any], ceremony_store: Mapping[str, Any],
    trust_state: Mapping[str, Any], gate_job: Mapping[str, Any],
    exchange: phase39.VerifiedGateExchange,
    semantic_receipt: phase40_gate1.VerifiedGate1Admission,
    witness: phase42_ceremony.VerifiedWitnessCheckpoint,
    transcript: phase42_ceremony.VerifiedCeremonyTranscript,
) -> dict[str, Any]:
    if type(created_unix) is not int or created_unix < 1:
        raise PolicyError("Phase 43 preflight timestamp is invalid")
    ledger = parse_custody_ledger(custody_ledger)
    state = phase41.parse_ceremony_state(ceremony_state)
    store = phase41.parse_ceremony_store(ceremony_store)
    trust = phase40.parse_trust_state(trust_state)
    job = phase39.parse_gate_job(gate_job, now_unix=created_unix)
    if not isinstance(exchange, phase39.VerifiedGateExchange):
        raise PolicyError("Phase 43 preflight requires a verified Phase 39 exchange")
    if not isinstance(semantic_receipt, phase40_gate1.VerifiedGate1Admission):
        raise PolicyError("Phase 43 preflight requires a verified Phase 40 admission")
    if not isinstance(witness, phase42_ceremony.VerifiedWitnessCheckpoint):
        raise PolicyError("Phase 43 preflight requires a verified Phase 42 witness")
    if not isinstance(transcript, phase42_ceremony.VerifiedCeremonyTranscript):
        raise PolicyError("Phase 43 preflight requires a verified Phase 42 transcript")
    if ledger["status"] not in TERMINAL_EVENTS or ledger["package_profile"] != "gate1-import":
        raise PolicyError("Phase 43 preflight requires a terminal Gate 1 import custody chain")
    if job.gate_name != phase39.GATE_NAMES[0] or job.gate_index != 1:
        raise PolicyError("Phase 43 preflight accepts only Gate 1")
    if ledger["challenge_nonce"] != job.document["challenge_nonce"]:
        raise PolicyError("Phase 43 custody and Gate 1 job challenges differ")
    if state["trust_state_digest"] != trust["state_digest"]:
        raise PolicyError("Phase 43 ceremony and trust state differ")
    if store["current_state"]["state_digest"] != state["state_digest"]:
        raise PolicyError("Phase 43 ceremony store and state differ")
    if (
        exchange.job_digest != job.job_digest
        or exchange.job_digest != semantic_receipt.phase39_job_digest
        or exchange.result_digest != semantic_receipt.phase39_result_digest
        or exchange.verification_digest != semantic_receipt.phase39_verification_digest
    ):
        raise PolicyError("Phase 43 Phase 39 and Phase 40 receipts differ")
    witness_doc = witness.document
    transcript_doc = transcript.document
    if (
        witness_doc["ceremony_state_digest"] != state["state_digest"]
        or witness_doc["ceremony_store_digest"] != store["store_digest"]
        or witness_doc["trust_state_digest"] != trust["state_digest"]
    ):
        raise PolicyError("Phase 43 witness differs from ceremony state")
    if (
        transcript_doc["final_ceremony_state_digest"] != state["state_digest"]
        or transcript_doc["final_ceremony_store_digest"] != store["store_digest"]
        or transcript_doc["final_trust_state_digest"] != trust["state_digest"]
        or transcript_doc["witness_checkpoint_digest"] != witness_doc["checkpoint_digest"]
        or transcript_doc["witness_verification_digest"] != witness.verification_digest
    ):
        raise PolicyError("Phase 43 transcript differs from the witnessed ceremony chain")
    if (
        state["owner_signing_fingerprint"] != trust["owner_job_signer_fingerprint"]
        or state["build_node_signing_fingerprint"] != trust["build_node_result_signer_fingerprint"]
        or state["build_node_id"] != trust["build_node_id"]
        or job.owner_fingerprint != state["owner_signing_fingerprint"]
        or job.result_fingerprint != state["build_node_signing_fingerprint"]
        or job.document["build_node_id"] != state["build_node_id"]
    ):
        raise PolicyError("Phase 43 owner/build-node identities are not cross-bound")
    phase39_verified = bool(
        exchange.owner_signature_verified and exchange.result_signature_verified
        and exchange.evidence_inventory_verified and exchange.replay_ledger_updated
    )
    phase40_verified = bool(semantic_receipt.semantic_evidence_verified)
    fixture_mode = bool(
        ledger["fixture_mode"] or state["fixture_mode"] or trust["fixture_mode"]
        or job.fixture_mode or exchange.fixture_mode or semantic_receipt.fixture_mode
        or witness.fixture_mode or transcript.document["fixture_mode"]
    )
    all_bindings = True
    eligible = bool(
        ledger["status"] == "imported"
        and ledger["custody_chain_authenticated"]
        and ledger["transport_accepted"]
        and state["status"] == "active"
        and state["gate1_jobs_allowed"]
        and phase39_verified
        and phase40_verified
        and exchange.owner_authenticated
        and exchange.gate_approved
        and semantic_receipt.owner_trust_authenticated
        and semantic_receipt.input_closure_authenticated
        and semantic_receipt.gate_approved
        and witness.witness_authenticated
        and transcript.transcript_authenticated
        and not fixture_mode
    )
    unsigned = {
        "format": PREFLIGHT_FORMAT,
        "contract_digest": offline_custody_contract_digest(),
        "created_unix": created_unix,
        "transfer_id": ledger["transfer_id"],
        "challenge_nonce": ledger["challenge_nonce"],
        "custody_ledger_digest": ledger["ledger_digest"],
        "custody_status": ledger["status"],
        "custody_chain_authenticated": ledger["custody_chain_authenticated"],
        "package_profile": ledger["package_profile"],
        "package_manifest_digest": ledger["package_manifest_digest"],
        "ceremony_state_digest": state["state_digest"],
        "ceremony_store_digest": store["store_digest"],
        "trust_state_digest": trust["state_digest"],
        "trust_root_digest": semantic_receipt.trust_root_digest,
        "input_closure_digest": semantic_receipt.input_closure_digest,
        "phase39_job_digest": exchange.job_digest,
        "phase39_result_digest": exchange.result_digest,
        "phase39_verification_digest": exchange.verification_digest,
        "phase39_exchange_verified": phase39_verified,
        "phase40_semantic_receipt_digest": semantic_receipt.receipt_digest,
        "phase40_semantics_verified": phase40_verified,
        "witness_checkpoint_digest": witness_doc["checkpoint_digest"],
        "witness_verification_digest": witness.verification_digest,
        "witness_authenticated": witness.witness_authenticated,
        "transcript_digest": transcript_doc["transcript_digest"],
        "transcript_verification_digest": transcript.verification_digest,
        "transcript_authenticated": transcript.transcript_authenticated,
        "fixture_mode": fixture_mode,
        "all_bindings_verified": all_bindings,
        "eligible_for_phase41_decision": eligible,
        "phase41_decision_required": True,
        "gate1_approved": False,
        "production_gates_approved": 0,
        "production_dispatch_allowed": False,
        "iso_release_allowed": False,
        "iso_bytes_present": False,
    }
    return {**unsigned, "preflight_digest": _digest(PREFLIGHT_DOMAIN, unsigned)}


def parse_gate1_preflight(value: Mapping[str, Any]) -> dict[str, Any]:
    required = set(preflight_schema()["required"])
    if type(value) is not dict or set(value) != required:
        raise PolicyError("Phase 43 Gate 1 preflight fields are not closed")
    candidate = json.loads(canonical_json_bytes(value))
    if candidate["format"] != PREFLIGHT_FORMAT or candidate["contract_digest"] != offline_custody_contract_digest():
        raise PolicyError("Phase 43 Gate 1 preflight identity drifted")
    if type(candidate["created_unix"]) is not int or candidate["created_unix"] < 1:
        raise PolicyError("Phase 43 Gate 1 preflight timestamp is invalid")
    _token(candidate["transfer_id"], "Phase 43 Gate 1 transfer ID")
    for field in (
        "challenge_nonce", "custody_ledger_digest", "package_manifest_digest",
        "ceremony_state_digest", "ceremony_store_digest", "trust_state_digest",
        "trust_root_digest", "input_closure_digest", "phase39_job_digest",
        "phase39_result_digest", "phase39_verification_digest",
        "phase40_semantic_receipt_digest", "witness_checkpoint_digest",
        "witness_verification_digest", "transcript_digest",
        "transcript_verification_digest",
    ):
        _sha(candidate[field], f"Phase 43 Gate 1 preflight {field}")
    if candidate["custody_status"] not in TERMINAL_EVENTS or candidate["package_profile"] != "gate1-import":
        raise PolicyError("Phase 43 Gate 1 preflight package boundary is invalid")
    for field in (
        "custody_chain_authenticated", "phase39_exchange_verified",
        "phase40_semantics_verified", "witness_authenticated",
        "transcript_authenticated", "fixture_mode", "all_bindings_verified",
        "eligible_for_phase41_decision", "phase41_decision_required",
        "gate1_approved", "production_dispatch_allowed", "iso_release_allowed",
        "iso_bytes_present",
    ):
        if type(candidate[field]) is not bool:
            raise PolicyError(f"Phase 43 Gate 1 preflight {field} is invalid")
    expected_eligible = bool(
        candidate["custody_status"] == "imported"
        and candidate["custody_chain_authenticated"]
        and candidate["phase39_exchange_verified"]
        and candidate["phase40_semantics_verified"]
        and candidate["witness_authenticated"]
        and candidate["transcript_authenticated"]
        and candidate["all_bindings_verified"]
        and not candidate["fixture_mode"]
    )
    if candidate["eligible_for_phase41_decision"] != expected_eligible:
        raise PolicyError("Phase 43 Gate 1 preflight eligibility relationship drifted")
    if (
        candidate["phase41_decision_required"] is not True
        or candidate["gate1_approved"] is not False
        or candidate["production_gates_approved"] != 0
        or candidate["production_dispatch_allowed"] is not False
        or candidate["iso_release_allowed"] is not False
        or candidate["iso_bytes_present"] is not False
    ):
        raise PolicyError("Phase 43 preflight attempted Gate 1 or release promotion")
    unsigned = {key: candidate[key] for key in candidate if key != "preflight_digest"}
    if candidate["preflight_digest"] != _digest(PREFLIGHT_DOMAIN, unsigned):
        raise PolicyError("Phase 43 Gate 1 preflight digest is invalid")
    return candidate


def blocked_observation() -> dict[str, Any]:
    unsigned = {
        "format": "securityops-phase43-offline-custody-observation/1",
        "status": BLOCKED_STATUS,
        "real_owner_pins_present": False,
        "real_build_node_pins_present": False,
        "real_witness_pins_present": False,
        "authenticated_35_artifact_closure_present": False,
        "nonfixture_custody_chain_present": False,
        "nonfixture_phase39_exchange_present": False,
        "phase40_semantic_admission_present": False,
        "phase41_monotonic_decision_present": False,
        "gate1_approved": False,
        "production_gates_approved": 0,
        "production_dispatch_allowed": False,
        "iso_release_allowed": False,
        "iso_bytes_present": False,
    }
    return {**unsigned, "observation_digest": _digest(PREFLIGHT_DOMAIN, unsigned)}


def run_negative_matrix() -> dict[str, Any]:
    # The exhaustive executable mutations live in tests.  This immutable list is
    # also part of the cross-tree contract and prevents silent test-surface loss.
    unsigned = {
        "format": "securityops-phase43-offline-custody-negative-matrix/1",
        "cases": list(NEGATIVE_CASES),
        "rejected": len(NEGATIVE_CASES),
        "all_rejected": True,
        "production_gates_approved": 0,
        "production_dispatch_allowed": False,
        "iso_release_allowed": False,
    }
    return {**unsigned, "matrix_digest": _digest(NEGATIVE_DOMAIN, unsigned)}


def phase43_selftest() -> dict[str, Any]:
    contract = parse_offline_custody_contract(offline_custody_contract())
    empty = parse_custody_ledger(empty_custody_ledger())
    negative = run_negative_matrix()
    observation = blocked_observation()
    unsigned = {
        "format": "securityops-phase43-offline-custody-selftest/1",
        "status": STATUS,
        "contract_digest": contract["contract_digest"],
        "empty_ledger_digest": empty["ledger_digest"],
        "negative_matrix_digest": negative["matrix_digest"],
        "negative_cases": negative["rejected"],
        "gate1_approved": observation["gate1_approved"],
        "production_gates_approved": 0,
        "production_dispatch_allowed": False,
        "iso_release_allowed": False,
    }
    return {**unsigned, "selftest_digest": _digest(CONTRACT_DOMAIN, unsigned)}



def _kit_command(subcommand: str) -> bytes:
    # The wrapper requires an explicit absolute CLI path.  It never resolves an
    # authority-sensitive executable through PATH.  Production admission still
    # belongs to the inherited Guix Store and signed-receipt boundaries.
    return (
        "#!/usr/bin/env python3\n"
        "# Secret-free wrapper; argv[1] must be the explicit installed CLI.\n"
        "import os,stat,sys\n"
        "if len(sys.argv)<2 or not os.path.isabs(sys.argv[1]):\n"
        " raise SystemExit('usage: wrapper /absolute/path/securityops-phase43-custody [arguments...]')\n"
        "raw=sys.argv[1]\n"
        "flags=os.O_RDONLY|getattr(os,'O_CLOEXEC',0)|getattr(os,'O_NOFOLLOW',0)\n"
        "fd=os.open(raw,flags)\n"
        "info=os.fstat(fd)\n"
        "mode=stat.S_IMODE(info.st_mode)\n"
        "if not stat.S_ISREG(info.st_mode) or info.st_nlink!=1 or mode&0o022 or info.st_uid not in {0,os.getuid()}:\n"
        " raise SystemExit('refusing unsafe Phase 43 CLI identity')\n"
        "os.set_inheritable(fd,True)\n"
        "env={'PATH':'/usr/bin:/bin','HOME':'/','LANG':'C.UTF-8','LC_ALL':'C.UTF-8','PYTHONNOUSERSITE':'1','PYTHONDONTWRITEBYTECODE':'1','PYTHONSAFEPATH':'1'}\n"
        f"os.execve('/proc/self/fd/'+str(fd),[raw,'{subcommand}',*sys.argv[2:]],env)\n"
    ).encode("utf-8")


def generate_operator_kit(destination: Path) -> dict[str, Any]:
    if destination.exists() or destination.is_symlink():
        raise PolicyError("Phase 43 operator-kit destination already exists")
    parent = destination.absolute().parent
    if parent.is_symlink():
        raise PolicyError("Phase 43 operator-kit parent cannot be a symbolic link")
    info = parent.stat()
    if (
        not stat.S_ISDIR(info.st_mode)
        or stat.S_IMODE(info.st_mode) & 0o022
        or info.st_uid not in {0, os.getuid()}
    ):
        raise PolicyError("Phase 43 operator-kit parent is not private")
    readme = """# Security Ops OS Phase 43 offline custody kit

This public, secret-free kit records an independently signed chain of custody
for a Phase 42 media package and validates the additional Gate 1 preflight
bindings. It does not generate keys, perform signing, create owner authority,
or approve Gate 1. Keep export, receiving, and independent-verifier signing
identities separate and pin their public keyrings out of band. Each helper
script also requires the explicit absolute path of the installed custody CLI.

A completed custody ledger proves the admitted transport chain only. Gate 1
still requires the real Phase 39 dual-signed exchange, Phase 40 authenticated
35-artifact semantic admission, Phase 41 monotonic decision, and Phase 42
owner+witness ceremony chain.
""".encode("utf-8")
    readme_pt = """# Kit de custódia offline da Phase 43 do Security Ops OS

Este kit público e sem segredos registra uma cadeia de custódia com assinaturas
independentes para um pacote de mídia da Phase 42 e valida os vínculos extras
do preflight do Gate 1. Ele não gera chaves, não assina, não cria autoridade do
proprietário e não aprova o Gate 1. Mantenha separadas as identidades do
exportador, do recebedor e do verificador independente e fixe suas chaves
públicas fora de banda. Cada script auxiliar também exige o caminho absoluto
explícito do CLI de custódia instalado.

Uma cadeia de custódia completa comprova somente o transporte admitido. O Gate
1 ainda exige a troca com duas assinaturas da Phase 39, a admissão semântica
autenticada dos 35 artefatos da Phase 40, a decisão monotônica da Phase 41 e a
cadeia de cerimônia proprietário+testemunha da Phase 42.
""".encode("utf-8")
    pins = {
        "format": "securityops-phase43-custody-pins-template/1",
        "export_operator": {"primary_fingerprint": "0" * 40, "signing_fingerprint": "0" * 40, "keyring_sha256": ZERO_SHA},
        "receiving_operator": {"primary_fingerprint": "0" * 40, "signing_fingerprint": "0" * 40, "keyring_sha256": ZERO_SHA},
        "independent_verifier": {"primary_fingerprint": "0" * 40, "signing_fingerprint": "0" * 40, "keyring_sha256": ZERO_SHA},
        "identities_must_be_distinct": True,
        "creates_owner_authority": False,
        "production_dispatch_allowed": False,
        "iso_release_allowed": False,
    }
    event_request = {
        "format": "securityops-phase43-custody-event-request-template/1",
        "package": "PHASE42_PACKAGE_DIRECTORY",
        "sequence": 1,
        "event_type": "exported",
        "challenge_nonce": ZERO_SHA,
        "transfer_id": "OPERATOR_ASSIGNED_TRANSFER_ID",
        "station_id": "OPERATOR_ASSIGNED_STATION_ID",
        "operator_primary_fingerprint": "0" * 40,
        "operator_signing_fingerprint": "0" * 40,
        "operator_keyring_sha256": ZERO_SHA,
        "previous_event_digest": ZERO_SHA,
        "fixture": False,
        "signature_performed_by_kit": False,
        "gate1_approved": False,
    }
    preflight_request = {
        "format": "securityops-phase43-gate1-preflight-request-template/1",
        "custody_ledger": "CUSTODY_LEDGER.json",
        "ceremony_state": "CEREMONY_STATE.json",
        "ceremony_store": "CEREMONY_STORE.json",
        "trust_state": "TRUST_STATE.json",
        "gate_job": "PHASE39_GATE1_JOB.json",
        "phase39_exchange": "PHASE39_VERIFIED_EXCHANGE.json",
        "phase40_semantic_receipt": "PHASE40_SEMANTIC_RECEIPT.json",
        "phase42_witness_verification": "PHASE42_WITNESS_VERIFICATION.json",
        "phase42_transcript_verification": "PHASE42_TRANSCRIPT_VERIFICATION.json",
        "preflight_can_close_gate1": False,
        "phase41_decision_required": True,
        "production_dispatch_allowed": False,
        "iso_release_allowed": False,
    }
    files: dict[str, tuple[bytes, int]] = {
        "README.md": (readme, 0o444),
        "README.pt-BR.md": (readme_pt, 0o444),
        "phase43-offline-custody-contract.json": (canonical_json_bytes(offline_custody_contract()), 0o444),
        "phase43-custody-event.schema.json": (canonical_json_bytes(event_schema()), 0o444),
        "phase43-custody-ledger.schema.json": (canonical_json_bytes(ledger_schema()), 0o444),
        "phase43-gate1-preflight.schema.json": (canonical_json_bytes(preflight_schema()), 0o444),
        "custody-pins.template.json": (canonical_json_bytes(pins), 0o444),
        "custody-event.request.template.json": (canonical_json_bytes(event_request), 0o444),
        "gate1-preflight.request.template.json": (canonical_json_bytes(preflight_request), 0o444),
        "scripts/create-event.py": (_kit_command("create-event"), 0o555),
        "scripts/verify-event.py": (_kit_command("verify-event"), 0o555),
        "scripts/verify-ledger.py": (_kit_command("verify-ledger"), 0o555),
        "scripts/verify-preflight.py": (_kit_command("verify-preflight"), 0o555),
    }
    if tuple(files) != KIT_FILES:
        raise PolicyError("Phase 43 operator-kit inventory drifted")
    temporary: Path | None = Path(tempfile.mkdtemp(prefix=f".{destination.name}.tmp-", dir=parent))
    temporary.chmod(0o700)
    records: list[dict[str, Any]] = []
    try:
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
                        raise PolicyError("Phase 43 operator-kit write did not complete")
                    view = view[count:]
                os.fsync(fd)
            finally:
                os.close(fd)
            records.append({
                "path": relative,
                "sha256": hashlib.sha256(payload).hexdigest(),
                "bytes": len(payload),
                "mode": mode,
            })
        phase42_media._fsync_directory(temporary / "scripts")  # type: ignore[attr-defined]
        phase42_media._fsync_directory(temporary)  # type: ignore[attr-defined]
        phase42_media._rename_noreplace(  # type: ignore[attr-defined]
            temporary, destination, context="Phase 43 operator kit")
        temporary = None
        unsigned = {
            "format": KIT_FORMAT,
            "status": "PASS_PHASE43_DETERMINISTIC_SECRET_FREE_CUSTODY_KIT",
            "contract_digest": offline_custody_contract_digest(),
            "files": records,
            "file_count": len(records),
            "contains_secret_keys": False,
            "generates_production_secret_keys": False,
            "performs_signing": False,
            "creates_owner_authority": False,
            "creates_witness_authority": False,
            "creates_custody_operator_authority": False,
            "gate1_approved": False,
            "production_gates_approved": 0,
            "production_dispatch_allowed": False,
            "iso_release_allowed": False,
        }
        return {**unsigned, "kit_digest": _digest(KIT_DOMAIN, unsigned)}
    finally:
        if temporary is not None and temporary.exists():
            shutil.rmtree(temporary)
