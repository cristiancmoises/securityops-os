# CodeMark v1 project=4c63e0fe-589c-4944-8449-97e211a38b72 file=c21e86a967ba5900a5d1eddd326a31a2 owner="Cristian Cezar Mois\u00e9s"
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Phase 41 offline owner ceremony and monotonic trust-transition boundary.

Phase 40 admits one owner-controlled trust root and a local monotonic trust
state.  Phase 41 adds the missing lifecycle around that state without creating
or holding signing authority:

* initialization requires proof of possession from both admitted identities;
* rotation is authorized by the current owner and, when identities change,
  proof of possession from every incoming signer;
* build-node revocation immediately quarantines Gate 1 job creation;
* recovery can restore only an exact, externally anchored ceremony checkpoint;
* a single atomic ceremony store detects stale updates, rollback and
  equivocation;
* detached signatures are verified from kernel-sealed measured bytes through
  the inherited Phase 39 gpgv boundary.

Fixture ceremonies exercise the implementation but can never authenticate the
owner, authorize Gate 1, approve production dispatch, or approve an ISO.
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
except ImportError:  # pragma: no cover - installed Guix Center copy
    import phase39_owner_execution as phase39  # type: ignore[no-redef]
    import phase40_owner_trust as phase40  # type: ignore[no-redef]

PolicyError = phase40.PolicyError
canonical_json_bytes = phase40.canonical_json_bytes

CONTRACT_FORMAT: Final[str] = "securityops-phase41-owner-ceremony-contract/1"
TRANSITION_FORMAT: Final[str] = "securityops-phase41-owner-ceremony-transition/1"
VERIFICATION_FORMAT: Final[str] = (
    "securityops-phase41-owner-ceremony-transition-verification/1"
)
STATE_FORMAT: Final[str] = "securityops-phase41-owner-ceremony-state/1"
STORE_FORMAT: Final[str] = "securityops-phase41-owner-ceremony-store/1"
KIT_FORMAT: Final[str] = "securityops-phase41-owner-ceremony-kit/1"
STATUS: Final[str] = (
    "PASS_PHASE41_OWNER_CEREMONY_ROTATION_REVOCATION_RECOVERY_BOUNDARY"
)
BLOCKED_STATUS: Final[str] = (
    "BLOCKED_PHASE41_REAL_OWNER_CEREMONY_AND_NONFIXTURE_GATE1_REQUIRED"
)

CONTRACT_DOMAIN: Final[bytes] = b"SECURITYOPS-PHASE41-OWNER-CEREMONY-CONTRACT-V1\x00"
TRANSITION_DOMAIN: Final[bytes] = b"SECURITYOPS-PHASE41-OWNER-TRANSITION-V1\x00"
VERIFICATION_DOMAIN: Final[bytes] = b"SECURITYOPS-PHASE41-OWNER-TRANSITION-VERIFICATION-V1\x00"
STATE_DOMAIN: Final[bytes] = b"SECURITYOPS-PHASE41-OWNER-CEREMONY-STATE-V1\x00"
STORE_DOMAIN: Final[bytes] = b"SECURITYOPS-PHASE41-OWNER-CEREMONY-STORE-V1\x00"
KIT_DOMAIN: Final[bytes] = b"SECURITYOPS-PHASE41-OWNER-CEREMONY-KIT-V1\x00"

PHASE40_IDENTITIES: Final[dict[str, str]] = {
    "runtime_commit": "602a32ec31468dc6a841db277f5f5dce2ba064d5",
    "runtime_tree": "3dea27a0feb942611248c113cc4c2b142570f311",
    "securityops_os_commit": "4f1b7fd9301c70c8dc85d113ff43ba2ed5e23ec4",
    "securityops_os_tree": "698d5137228377e2a50274476ad0dd58bf507598",
    "stable_v1_13_0": "8373fd789c9a525d6128abfd3d7a93ad4db3348b",
}
PHASE40_OWNER_CONTRACT_DIGEST: Final[str] = (
    "a2234f4e0def156e23de31f7661cb4c15b56451ab9bd7ab4a8f45d7814350b6c"
)
PHASE40_GATE1_CONTRACT_DIGEST: Final[str] = (
    "3e692b76ec7d7c468019bd17625463626a8e45b116e23e0376f52849539fc0b3"
)
PHASE39_CONTRACT_DIGEST: Final[str] = phase40.PHASE39_CONTRACT_DIGEST

ZERO_SHA: Final[str] = "0" * 64
ZERO_FINGERPRINT: Final[str] = "0" * 40
MAX_TRANSITION_BYTES: Final[int] = 2 * 1024 * 1024
MAX_SIGNATURE_BYTES: Final[int] = phase40.MAX_SIGNATURE_BYTES
MAX_KEYRING_BYTES: Final[int] = phase40.MAX_KEYRING_BYTES
MAX_TRANSITION_LIFETIME: Final[int] = 30 * 24 * 60 * 60
MAX_STORE_BYTES: Final[int] = 16 * 1024 * 1024
MAX_STORE_RECORDS: Final[int] = 4096

TRANSITION_TYPES: Final[tuple[str, ...]] = (
    "initialize",
    "rotate",
    "revoke-build-node",
    "recover-state",
)
REASON_CODES: Final[dict[str, tuple[str, ...]]] = {
    "initialize": ("initial-owner-bootstrap",),
    "rotate": (
        "scheduled-rotation",
        "owner-key-rotation",
        "build-node-key-rotation",
        "build-node-replacement",
        "incident-response-rotation",
    ),
    "revoke-build-node": (
        "build-node-compromise",
        "build-node-key-revoked",
        "build-node-decommissioned",
    ),
    "recover-state": (
        "local-state-recovery",
        "verified-backup-recovery",
    ),
}
SIGNATURE_ROLES: Final[tuple[str, ...]] = (
    "current-owner",
    "next-owner-proof",
    "next-build-node-proof",
)
STATE_STATUSES: Final[tuple[str, ...]] = ("active", "quarantined")

_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_FINGERPRINT = re.compile(r"[0-9A-F]{40}\Z")
_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")

NEGATIVE_CASES: Final[tuple[str, ...]] = (
    "extra-contract-field",
    "phase40-owner-contract-drift",
    "phase40-gate1-contract-drift",
    "phase40-source-identity-drift",
    "transition-type-removed",
    "signature-role-removed",
    "initial-transition-with-previous-state",
    "rotation-without-current-owner-signature",
    "incoming-owner-without-proof",
    "incoming-node-without-proof",
    "rotation-without-identity-change",
    "nonconsecutive-trust-generation",
    "revoke-with-node-proof-substitution",
    "revoked-state-can-create-gate1-job",
    "recovery-clears-quarantine",
    "recovery-changes-trust-state",
    "stale-sequence-accepted",
    "equivocation-accepted",
    "rollback-recovery-accepted",
    "unanchored-recovery-accepted",
    "fixture-owner-promotion",
    "secret-key-use-by-runtime-enabled",
    "original-path-signature-verification-enabled",
    "production-promotion",
    "iso-promotion",
)

KIT_FILES: Final[tuple[str, ...]] = (
    "README.md",
    "README.pt-BR.md",
    "phase41-owner-ceremony-contract.json",
    "phase41-gate1-execution-contract.json",
    "phase41-owner-transition.schema.json",
    "phase41-owner-ceremony-state.schema.json",
    "phase41-owner-ceremony-store.schema.json",
    "phase41-gate1-decision.schema.json",
    "phase41-gate1-decision-ledger.schema.json",
    "initialize.request.template.json",
    "rotate.request.template.json",
    "revoke-build-node.request.template.json",
    "recover-state.request.template.json",
    "gate1-import.request.template.json",
    "scripts/create-transition.py",
    "scripts/verify-transition.py",
    "scripts/import-gate1-decision.py",
)


def _digest(domain: bytes, value: Mapping[str, Any]) -> str:
    return hashlib.sha256(domain + canonical_json_bytes(value)).hexdigest()


def _sha(value: Any, context: str, *, allow_zero: bool = False) -> str:
    if not isinstance(value, str) or not _HEX64.fullmatch(value):
        raise PolicyError(f"{context} must be a lowercase SHA-256 digest")
    if not allow_zero and value == ZERO_SHA:
        raise PolicyError(f"{context} cannot be the zero digest")
    return value


def _fpr(value: Any, context: str, *, allow_zero: bool = False) -> str:
    if not isinstance(value, str) or not _FINGERPRINT.fullmatch(value):
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

    try:
        value = json.loads(payload.decode("utf-8", errors="strict"), object_pairs_hook=hook)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PolicyError(f"{context} is not strict UTF-8 JSON") from exc
    if duplicates or type(value) is not dict:
        raise PolicyError(f"{context} has duplicate fields or is not an object")
    return value


def _trust_identity(state: Mapping[str, Any]) -> dict[str, str]:
    parsed = phase40.parse_trust_state(state)
    return {
        "trust_state_digest": parsed["state_digest"],
        "owner_primary_fingerprint": parsed["owner_primary_fingerprint"],
        "owner_signing_fingerprint": parsed["owner_job_signer_fingerprint"],
        "owner_keyring_sha256": parsed["owner_keyring_sha256"],
        "build_node_primary_fingerprint": parsed["build_node_primary_fingerprint"],
        "build_node_signing_fingerprint": parsed[
            "build_node_result_signer_fingerprint"
        ],
        "build_node_keyring_sha256": parsed["build_node_keyring_sha256"],
        "build_node_id": parsed["build_node_id"],
    }


def transition_schema() -> dict[str, Any]:
    sha = {"type": "string", "pattern": "^[0-9a-f]{64}$"}
    fpr = {"type": "string", "pattern": "^[0-9A-F]{40}$"}
    required = [
        "format", "contract_digest", "phase40_owner_contract_digest",
        "phase40_gate1_contract_digest", "phase40_identities", "sequence",
        "transition_type", "reason_code", "created_unix", "expires_unix",
        "challenge_nonce", "previous_ceremony_state_digest",
        "previous_trust_state_digest", "next_trust_state_digest",
        "current_owner_signing_fingerprint", "next_owner_signing_fingerprint",
        "current_owner_keyring_sha256", "next_owner_keyring_sha256",
        "current_build_node_signing_fingerprint",
        "next_build_node_signing_fingerprint",
        "current_build_node_keyring_sha256", "next_build_node_keyring_sha256",
        "current_build_node_id", "next_build_node_id",
        "required_signature_roles", "runtime_handles_secret_keys",
        "fixture_mode", "production_gate_approved",
        "production_dispatch_allowed", "iso_release_allowed",
        "transition_digest",
    ]
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": (
            "https://securityops.co/schemas/guix-center/"
            "phase41-owner-transition.schema.json"
        ),
        "title": "Security Ops Phase 41 owner ceremony transition",
        "type": "object",
        "additionalProperties": False,
        "required": required,
        "properties": {
            "format": {"const": TRANSITION_FORMAT},
            "contract_digest": sha,
            "phase40_owner_contract_digest": sha,
            "phase40_gate1_contract_digest": sha,
            "phase40_identities": {
                "type": "object", "additionalProperties": False,
                "required": list(PHASE40_IDENTITIES),
                "properties": {
                    key: {"const": value}
                    for key, value in PHASE40_IDENTITIES.items()
                },
            },
            "sequence": {"type": "integer", "minimum": 1},
            "transition_type": {"enum": list(TRANSITION_TYPES)},
            "reason_code": {
                "type": "string", "minLength": 1, "maxLength": 128,
            },
            "created_unix": {"type": "integer", "minimum": 1},
            "expires_unix": {"type": "integer", "minimum": 1},
            "challenge_nonce": sha,
            "previous_ceremony_state_digest": sha,
            "previous_trust_state_digest": sha,
            "next_trust_state_digest": sha,
            "current_owner_signing_fingerprint": fpr,
            "next_owner_signing_fingerprint": fpr,
            "current_owner_keyring_sha256": sha,
            "next_owner_keyring_sha256": sha,
            "current_build_node_signing_fingerprint": fpr,
            "next_build_node_signing_fingerprint": fpr,
            "current_build_node_keyring_sha256": sha,
            "next_build_node_keyring_sha256": sha,
            "current_build_node_id": {"type": "string", "maxLength": 128},
            "next_build_node_id": {"type": "string", "maxLength": 128},
            "required_signature_roles": {
                "type": "array", "minItems": 1,
                "maxItems": len(SIGNATURE_ROLES),
                "items": {"enum": list(SIGNATURE_ROLES)},
                "uniqueItems": True,
            },
            "runtime_handles_secret_keys": {"const": False},
            "fixture_mode": {"type": "boolean"},
            "production_gate_approved": {"const": False},
            "production_dispatch_allowed": {"const": False},
            "iso_release_allowed": {"const": False},
            "transition_digest": sha,
        },
    }


def state_schema() -> dict[str, Any]:
    sha = {"type": "string", "pattern": "^[0-9a-f]{64}$"}
    fpr = {"type": "string", "pattern": "^[0-9A-F]{40}$"}
    required = [
        "format", "contract_digest", "sequence", "trust_generation",
        "transition_type", "status", "quarantine_reason",
        "transition_digest", "previous_ceremony_state_digest",
        "trust_state_digest", "owner_signing_fingerprint",
        "owner_keyring_sha256", "build_node_signing_fingerprint",
        "build_node_keyring_sha256", "build_node_id", "fixture_mode",
        "transition_signatures_verified", "owner_trust_authenticated",
        "gate1_jobs_allowed", "production_gate_approved",
        "production_dispatch_allowed", "iso_release_allowed", "state_digest",
    ]
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": (
            "https://securityops.co/schemas/guix-center/"
            "phase41-owner-ceremony-state.schema.json"
        ),
        "title": "Security Ops Phase 41 owner ceremony state",
        "type": "object", "additionalProperties": False,
        "required": required,
        "properties": {
            "format": {"const": STATE_FORMAT},
            "contract_digest": sha,
            "sequence": {"type": "integer", "minimum": 1},
            "trust_generation": {"type": "integer", "minimum": 1},
            "transition_type": {"enum": list(TRANSITION_TYPES)},
            "status": {"enum": list(STATE_STATUSES)},
            "quarantine_reason": {"type": "string", "maxLength": 128},
            "transition_digest": sha,
            "previous_ceremony_state_digest": sha,
            "trust_state_digest": sha,
            "owner_signing_fingerprint": fpr,
            "owner_keyring_sha256": sha,
            "build_node_signing_fingerprint": fpr,
            "build_node_keyring_sha256": sha,
            "build_node_id": {"type": "string", "minLength": 1, "maxLength": 128},
            "fixture_mode": {"type": "boolean"},
            "transition_signatures_verified": {"type": "boolean"},
            "owner_trust_authenticated": {"type": "boolean"},
            "gate1_jobs_allowed": {"type": "boolean"},
            "production_gate_approved": {"const": False},
            "production_dispatch_allowed": {"const": False},
            "iso_release_allowed": {"const": False},
            "state_digest": sha,
        },
    }


def store_schema() -> dict[str, Any]:
    sha = {"type": "string", "pattern": "^[0-9a-f]{64}$"}
    record = {
        "type": "object", "additionalProperties": False,
        "required": [
            "sequence", "transition_type", "status", "transition_digest",
            "state_digest", "previous_state_digest", "trust_state_digest",
        ],
        "properties": {
            "sequence": {"type": "integer", "minimum": 1},
            "transition_type": {"enum": list(TRANSITION_TYPES)},
            "status": {"enum": list(STATE_STATUSES)},
            "transition_digest": sha,
            "state_digest": sha,
            "previous_state_digest": sha,
            "trust_state_digest": sha,
        },
    }
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": (
            "https://securityops.co/schemas/guix-center/"
            "phase41-owner-ceremony-store.schema.json"
        ),
        "title": "Security Ops Phase 41 atomic ceremony store",
        "type": "object", "additionalProperties": False,
        "required": [
            "format", "contract_digest", "generation", "highest_sequence",
            "current_state", "records", "equivocation_detected",
            "production_dispatch_allowed", "iso_release_allowed", "store_digest",
        ],
        "properties": {
            "format": {"const": STORE_FORMAT},
            "contract_digest": sha,
            "generation": {"type": "integer", "minimum": 1},
            "highest_sequence": {"type": "integer", "minimum": 1},
            "current_state": state_schema(),
            "records": {
                "type": "array", "minItems": 1,
                "maxItems": MAX_STORE_RECORDS, "items": record,
            },
            "equivocation_detected": {"const": False},
            "production_dispatch_allowed": {"const": False},
            "iso_release_allowed": {"const": False},
            "store_digest": sha,
        },
    }


def _contract_unsigned() -> dict[str, Any]:
    transition = transition_schema()
    state = state_schema()
    store = store_schema()
    return {
        "format": CONTRACT_FORMAT,
        "status": STATUS,
        "phase40_owner_contract_digest": PHASE40_OWNER_CONTRACT_DIGEST,
        "phase40_gate1_contract_digest": PHASE40_GATE1_CONTRACT_DIGEST,
        "phase39_contract_digest": PHASE39_CONTRACT_DIGEST,
        "phase40_identities": dict(PHASE40_IDENTITIES),
        "schemas": {
            "transition": {
                "id": transition["$id"],
                "canonical_sha256": hashlib.sha256(
                    canonical_json_bytes(transition)).hexdigest(),
            },
            "state": {
                "id": state["$id"],
                "canonical_sha256": hashlib.sha256(
                    canonical_json_bytes(state)).hexdigest(),
            },
            "store": {
                "id": store["$id"],
                "canonical_sha256": hashlib.sha256(
                    canonical_json_bytes(store)).hexdigest(),
            },
            "additional_properties_allowed": False,
        },
        "transition_types": list(TRANSITION_TYPES),
        "reason_codes": {
            key: list(value) for key, value in REASON_CODES.items()
        },
        "signature_policy": {
            "roles": list(SIGNATURE_ROLES),
            "initialize_requires_incoming_owner_proof": True,
            "initialize_requires_incoming_build_node_proof": True,
            "rotation_requires_current_owner_authorization": True,
            "changed_owner_requires_incoming_proof": True,
            "changed_build_node_requires_incoming_proof": True,
            "revocation_requires_current_owner_authorization": True,
            "recovery_requires_current_owner_authorization": True,
            "verification_uses_kernel_sealed_memfd": True,
            "original_paths_reopened_after_measurement": False,
            "runtime_handles_secret_keys": False,
        },
        "state_policy": {
            "sequence_strictly_consecutive": True,
            "trust_generation_consecutive_on_rotation": True,
            "revocation_quarantines_gate1": True,
            "recovery_cannot_change_trust_state": True,
            "recovery_cannot_clear_quarantine": True,
            "fixture_can_authenticate_owner": False,
            "fixture_can_create_gate1_job": False,
        },
        "store_policy": {
            "single_atomic_file": True,
            "private_lock_required": True,
            "file_and_directory_fsync_required": True,
            "rollback_rejected": True,
            "stale_transition_rejected": True,
            "same_sequence_different_state_is_equivocation": True,
            "externally_anchored_recovery_required": True,
            "maximum_records": MAX_STORE_RECORDS,
        },
        "network_fetch_allowed": False,
        "production_gates_approved": 0,
        "production_dispatch_allowed": False,
        "iso_release_allowed": False,
        "execution_status": BLOCKED_STATUS,
    }


def ceremony_contract() -> dict[str, Any]:
    unsigned = _contract_unsigned()
    return {**unsigned, "contract_digest": _digest(CONTRACT_DOMAIN, unsigned)}


def ceremony_contract_digest() -> str:
    return ceremony_contract()["contract_digest"]


def parse_ceremony_contract(value: Mapping[str, Any]) -> dict[str, Any]:
    expected = ceremony_contract()
    if type(value) is not dict or value != expected:
        raise PolicyError("Phase 41 owner-ceremony contract differs from policy")
    return json.loads(canonical_json_bytes(value))


def _required_roles(
    transition_type: str,
    previous_trust_state: Mapping[str, Any] | None,
    next_trust_state: Mapping[str, Any] | None,
) -> tuple[str, ...]:
    if transition_type == "initialize":
        return ("next-owner-proof", "next-build-node-proof")
    if transition_type in {"revoke-build-node", "recover-state"}:
        return ("current-owner",)
    if previous_trust_state is None or next_trust_state is None:
        raise PolicyError("Phase 41 rotation requires current and next trust states")
    current = _trust_identity(previous_trust_state)
    nxt = _trust_identity(next_trust_state)
    roles = ["current-owner"]
    if (
        current["owner_signing_fingerprint"] != nxt["owner_signing_fingerprint"]
        or current["owner_keyring_sha256"] != nxt["owner_keyring_sha256"]
    ):
        roles.append("next-owner-proof")
    if (
        current["build_node_signing_fingerprint"]
        != nxt["build_node_signing_fingerprint"]
        or current["build_node_keyring_sha256"]
        != nxt["build_node_keyring_sha256"]
        or current["build_node_id"] != nxt["build_node_id"]
    ):
        roles.append("next-build-node-proof")
    return tuple(roles)


def create_transition(
    *, transition_type: str, reason_code: str, sequence: int,
    created_unix: int, expires_unix: int, challenge_nonce: str,
    previous_ceremony_state: Mapping[str, Any] | None,
    previous_trust_state: Mapping[str, Any] | None,
    next_trust_state: Mapping[str, Any] | None,
    fixture_mode: bool,
) -> dict[str, Any]:
    if transition_type not in TRANSITION_TYPES:
        raise PolicyError("Phase 41 transition type is invalid")
    if reason_code not in REASON_CODES[transition_type]:
        raise PolicyError("Phase 41 transition reason is not admitted")
    if type(sequence) is not int or sequence < 1:
        raise PolicyError("Phase 41 transition sequence is invalid")
    if (
        type(created_unix) is not int
        or type(expires_unix) is not int
        or created_unix < 1
        or not created_unix < expires_unix
        or expires_unix > created_unix + MAX_TRANSITION_LIFETIME
    ):
        raise PolicyError("Phase 41 transition lifetime is invalid")
    nonce = _sha(challenge_nonce, "Phase 41 transition challenge")
    if type(fixture_mode) is not bool:
        raise PolicyError("Phase 41 transition fixture state is invalid")

    previous_ceremony = (
        None if previous_ceremony_state is None
        else parse_ceremony_state(previous_ceremony_state)
    )
    previous_trust = (
        None if previous_trust_state is None
        else phase40.parse_trust_state(previous_trust_state)
    )
    next_trust = (
        None if next_trust_state is None
        else phase40.parse_trust_state(next_trust_state)
    )

    if transition_type == "initialize":
        if previous_ceremony is not None or previous_trust is not None:
            raise PolicyError("Phase 41 initialization cannot have previous state")
        if sequence != 1 or next_trust is None or next_trust["generation"] != 1:
            raise PolicyError("Phase 41 initialization requires trust generation one")
        if next_trust["fixture_mode"] != fixture_mode:
            raise PolicyError("Phase 41 initialization fixture state drifted")
        previous_ceremony_digest = ZERO_SHA
        previous_trust_digest = ZERO_SHA
        current = {
            "owner_signing_fingerprint": ZERO_FINGERPRINT,
            "owner_keyring_sha256": ZERO_SHA,
            "build_node_signing_fingerprint": ZERO_FINGERPRINT,
            "build_node_keyring_sha256": ZERO_SHA,
            "build_node_id": "none",
        }
        nxt = _trust_identity(next_trust)
    else:
        if previous_ceremony is None or previous_trust is None:
            raise PolicyError("Phase 41 transition requires previous state")
        if sequence != previous_ceremony["sequence"] + 1:
            raise PolicyError("Phase 41 transition sequence is not consecutive")
        if previous_ceremony["trust_state_digest"] != previous_trust["state_digest"]:
            raise PolicyError("Phase 41 previous ceremony/trust state binding drifted")
        if previous_ceremony["fixture_mode"] != fixture_mode:
            raise PolicyError("Phase 41 previous ceremony fixture state drifted")
        previous_ceremony_digest = previous_ceremony["state_digest"]
        previous_trust_digest = previous_trust["state_digest"]
        current = _trust_identity(previous_trust)
        if transition_type == "rotate":
            if next_trust is None:
                raise PolicyError("Phase 41 rotation requires a next trust state")
            if next_trust["generation"] != previous_trust["generation"] + 1:
                raise PolicyError("Phase 41 rotated trust generation is not consecutive")
            if next_trust["previous_state_digest"] != previous_trust["state_digest"]:
                raise PolicyError("Phase 41 rotated trust state does not chain")
            if next_trust["fixture_mode"] != fixture_mode:
                raise PolicyError("Phase 41 rotated trust fixture state drifted")
            nxt = _trust_identity(next_trust)
            changed = any(current[key] != nxt[key] for key in (
                "owner_signing_fingerprint", "owner_keyring_sha256",
                "build_node_signing_fingerprint", "build_node_keyring_sha256",
                "build_node_id",
            ))
            if not changed:
                raise PolicyError("Phase 41 rotation did not change an admitted identity")
        elif transition_type == "revoke-build-node":
            if next_trust is not None:
                raise PolicyError("Phase 41 revocation cannot publish a next trust state")
            nxt = {
                "trust_state_digest": ZERO_SHA,
                "owner_primary_fingerprint": current.get(
                    "owner_primary_fingerprint", ZERO_FINGERPRINT),
                "owner_signing_fingerprint": current["owner_signing_fingerprint"],
                "owner_keyring_sha256": current["owner_keyring_sha256"],
                "build_node_primary_fingerprint": ZERO_FINGERPRINT,
                "build_node_signing_fingerprint": ZERO_FINGERPRINT,
                "build_node_keyring_sha256": ZERO_SHA,
                "build_node_id": "revoked",
            }
        else:  # recover-state
            if next_trust is None or next_trust != previous_trust:
                raise PolicyError("Phase 41 recovery cannot change the trust state")
            nxt = _trust_identity(next_trust)

    roles = _required_roles(transition_type, previous_trust, next_trust)
    if transition_type == "rotate" and roles == ("current-owner",):
        raise PolicyError("Phase 41 rotation lacks an incoming identity proof")
    unsigned = {
        "format": TRANSITION_FORMAT,
        "contract_digest": ceremony_contract_digest(),
        "phase40_owner_contract_digest": PHASE40_OWNER_CONTRACT_DIGEST,
        "phase40_gate1_contract_digest": PHASE40_GATE1_CONTRACT_DIGEST,
        "phase40_identities": dict(PHASE40_IDENTITIES),
        "sequence": sequence,
        "transition_type": transition_type,
        "reason_code": reason_code,
        "created_unix": created_unix,
        "expires_unix": expires_unix,
        "challenge_nonce": nonce,
        "previous_ceremony_state_digest": previous_ceremony_digest,
        "previous_trust_state_digest": previous_trust_digest,
        "next_trust_state_digest": (
            ZERO_SHA if next_trust is None else next_trust["state_digest"]
        ),
        "current_owner_signing_fingerprint": current[
            "owner_signing_fingerprint"
        ],
        "next_owner_signing_fingerprint": nxt["owner_signing_fingerprint"],
        "current_owner_keyring_sha256": current["owner_keyring_sha256"],
        "next_owner_keyring_sha256": nxt["owner_keyring_sha256"],
        "current_build_node_signing_fingerprint": current[
            "build_node_signing_fingerprint"
        ],
        "next_build_node_signing_fingerprint": nxt[
            "build_node_signing_fingerprint"
        ],
        "current_build_node_keyring_sha256": current[
            "build_node_keyring_sha256"
        ],
        "next_build_node_keyring_sha256": nxt[
            "build_node_keyring_sha256"
        ],
        "current_build_node_id": current["build_node_id"],
        "next_build_node_id": nxt["build_node_id"],
        "required_signature_roles": list(roles),
        "runtime_handles_secret_keys": False,
        "fixture_mode": fixture_mode,
        "production_gate_approved": False,
        "production_dispatch_allowed": False,
        "iso_release_allowed": False,
    }
    return {**unsigned, "transition_digest": _digest(TRANSITION_DOMAIN, unsigned)}


def parse_transition(value: Mapping[str, Any], *, now_unix: int | None = None) -> dict[str, Any]:
    required = set(transition_schema()["required"])
    if type(value) is not dict or set(value) != required:
        raise PolicyError("Phase 41 transition fields are not closed")
    candidate = json.loads(canonical_json_bytes(value))
    if candidate["format"] != TRANSITION_FORMAT:
        raise PolicyError("Phase 41 transition format is invalid")
    if candidate["contract_digest"] != ceremony_contract_digest():
        raise PolicyError("Phase 41 transition contract digest drifted")
    if candidate["phase40_owner_contract_digest"] != PHASE40_OWNER_CONTRACT_DIGEST:
        raise PolicyError("Phase 41 transition Phase 40 owner contract drifted")
    if candidate["phase40_gate1_contract_digest"] != PHASE40_GATE1_CONTRACT_DIGEST:
        raise PolicyError("Phase 41 transition Phase 40 Gate 1 contract drifted")
    if candidate["phase40_identities"] != PHASE40_IDENTITIES:
        raise PolicyError("Phase 41 transition source identities drifted")
    transition_type = candidate["transition_type"]
    if transition_type not in TRANSITION_TYPES:
        raise PolicyError("Phase 41 transition type is invalid")
    if candidate["reason_code"] not in REASON_CODES[transition_type]:
        raise PolicyError("Phase 41 transition reason is invalid")
    if type(candidate["sequence"]) is not int or candidate["sequence"] < 1:
        raise PolicyError("Phase 41 transition sequence is invalid")
    if (
        type(candidate["created_unix"]) is not int
        or type(candidate["expires_unix"]) is not int
        or candidate["created_unix"] < 1
        or not candidate["created_unix"] < candidate["expires_unix"]
        or candidate["expires_unix"]
        > candidate["created_unix"] + MAX_TRANSITION_LIFETIME
    ):
        raise PolicyError("Phase 41 transition lifetime is invalid")
    _sha(candidate["challenge_nonce"], "Phase 41 transition challenge")
    for field in (
        "previous_ceremony_state_digest", "previous_trust_state_digest",
        "next_trust_state_digest", "current_owner_keyring_sha256",
        "next_owner_keyring_sha256", "current_build_node_keyring_sha256",
        "next_build_node_keyring_sha256",
    ):
        _sha(candidate[field], f"Phase 41 transition {field}", allow_zero=True)
    for field in (
        "current_owner_signing_fingerprint", "next_owner_signing_fingerprint",
        "current_build_node_signing_fingerprint",
        "next_build_node_signing_fingerprint",
    ):
        _fpr(candidate[field], f"Phase 41 transition {field}", allow_zero=True)
    for field in ("current_build_node_id", "next_build_node_id"):
        _token(candidate[field], f"Phase 41 transition {field}")
    roles = candidate["required_signature_roles"]
    if (
        type(roles) is not list
        or not roles
        or len(roles) != len(set(roles))
        or any(role not in SIGNATURE_ROLES for role in roles)
    ):
        raise PolicyError("Phase 41 transition signature roles are invalid")
    expected_roles: list[str]
    if transition_type == "initialize":
        expected_roles = ["next-owner-proof", "next-build-node-proof"]
        if (
            candidate["sequence"] != 1
            or candidate["previous_ceremony_state_digest"] != ZERO_SHA
            or candidate["previous_trust_state_digest"] != ZERO_SHA
            or candidate["current_owner_signing_fingerprint"] != ZERO_FINGERPRINT
            or candidate["current_build_node_signing_fingerprint"] != ZERO_FINGERPRINT
            or candidate["next_trust_state_digest"] == ZERO_SHA
            or candidate["next_owner_signing_fingerprint"] == ZERO_FINGERPRINT
            or candidate["next_owner_keyring_sha256"] == ZERO_SHA
            or candidate["next_build_node_signing_fingerprint"] == ZERO_FINGERPRINT
            or candidate["next_build_node_keyring_sha256"] == ZERO_SHA
            or candidate["next_build_node_id"] in {"none", "revoked"}
        ):
            raise PolicyError("Phase 41 initialization transition is malformed")
    elif transition_type in {"revoke-build-node", "recover-state"}:
        expected_roles = ["current-owner"]
        if (
            candidate["previous_ceremony_state_digest"] == ZERO_SHA
            or candidate["previous_trust_state_digest"] == ZERO_SHA
            or candidate["current_owner_signing_fingerprint"] == ZERO_FINGERPRINT
            or candidate["current_owner_keyring_sha256"] == ZERO_SHA
            or candidate["current_build_node_signing_fingerprint"] == ZERO_FINGERPRINT
            or candidate["current_build_node_keyring_sha256"] == ZERO_SHA
        ):
            raise PolicyError("Phase 41 transition lacks previous ceremony state")
        if transition_type == "revoke-build-node" and (
            candidate["next_trust_state_digest"] != ZERO_SHA
            or candidate["next_owner_signing_fingerprint"]
            != candidate["current_owner_signing_fingerprint"]
            or candidate["next_owner_keyring_sha256"]
            != candidate["current_owner_keyring_sha256"]
            or candidate["next_build_node_signing_fingerprint"] != ZERO_FINGERPRINT
            or candidate["next_build_node_keyring_sha256"] != ZERO_SHA
            or candidate["next_build_node_id"] != "revoked"
        ):
            raise PolicyError("Phase 41 revocation transition is malformed")
        if transition_type == "recover-state" and (
            candidate["previous_trust_state_digest"]
            != candidate["next_trust_state_digest"]
            or candidate["next_owner_signing_fingerprint"]
            != candidate["current_owner_signing_fingerprint"]
            or candidate["next_owner_keyring_sha256"]
            != candidate["current_owner_keyring_sha256"]
            or candidate["next_build_node_signing_fingerprint"]
            != candidate["current_build_node_signing_fingerprint"]
            or candidate["next_build_node_keyring_sha256"]
            != candidate["current_build_node_keyring_sha256"]
            or candidate["next_build_node_id"] != candidate["current_build_node_id"]
        ):
            raise PolicyError("Phase 41 recovery changed the trust state")
    else:
        expected_roles = ["current-owner"]
        if (
            candidate["previous_ceremony_state_digest"] == ZERO_SHA
            or candidate["previous_trust_state_digest"] == ZERO_SHA
            or candidate["next_trust_state_digest"] == ZERO_SHA
            or candidate["current_owner_signing_fingerprint"] == ZERO_FINGERPRINT
            or candidate["current_owner_keyring_sha256"] == ZERO_SHA
            or candidate["current_build_node_signing_fingerprint"] == ZERO_FINGERPRINT
            or candidate["current_build_node_keyring_sha256"] == ZERO_SHA
            or candidate["next_owner_signing_fingerprint"] == ZERO_FINGERPRINT
            or candidate["next_owner_keyring_sha256"] == ZERO_SHA
            or candidate["next_build_node_signing_fingerprint"] == ZERO_FINGERPRINT
            or candidate["next_build_node_keyring_sha256"] == ZERO_SHA
            or candidate["next_build_node_id"] in {"none", "revoked"}
        ):
            raise PolicyError("Phase 41 rotation contains an empty identity")
        owner_changed = (
            candidate["current_owner_signing_fingerprint"]
            != candidate["next_owner_signing_fingerprint"]
            or candidate["current_owner_keyring_sha256"]
            != candidate["next_owner_keyring_sha256"]
        )
        node_changed = (
            candidate["current_build_node_signing_fingerprint"]
            != candidate["next_build_node_signing_fingerprint"]
            or candidate["current_build_node_keyring_sha256"]
            != candidate["next_build_node_keyring_sha256"]
            or candidate["current_build_node_id"] != candidate["next_build_node_id"]
        )
        if owner_changed:
            expected_roles.append("next-owner-proof")
        if node_changed:
            expected_roles.append("next-build-node-proof")
        if not owner_changed and not node_changed:
            raise PolicyError("Phase 41 rotation did not change an identity")
    if roles != expected_roles:
        raise PolicyError("Phase 41 required signature role order drifted")
    if candidate["runtime_handles_secret_keys"] is not False:
        raise PolicyError("Phase 41 runtime cannot handle secret keys")
    if type(candidate["fixture_mode"]) is not bool:
        raise PolicyError("Phase 41 transition fixture state is invalid")
    for flag in (
        "production_gate_approved", "production_dispatch_allowed",
        "iso_release_allowed",
    ):
        if candidate[flag] is not False:
            raise PolicyError("Phase 41 transition attempted release promotion")
    unsigned = {key: candidate[key] for key in candidate if key != "transition_digest"}
    if candidate["transition_digest"] != _digest(TRANSITION_DOMAIN, unsigned):
        raise PolicyError("Phase 41 transition digest is invalid")
    if now_unix is not None and not (
        candidate["created_unix"] <= now_unix <= candidate["expires_unix"]
    ):
        raise PolicyError("Phase 41 transition is not valid at the supplied time")
    return candidate


@dataclass(frozen=True)
class VerifiedCeremonyTransition:
    document: dict[str, Any]
    transition_digest: str
    signature_roles_verified: tuple[str, ...]
    signed_input_sha256: dict[str, str]
    fixture_mode: bool
    signatures_verified: bool
    owner_authenticated: bool
    verification_digest: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "format": VERIFICATION_FORMAT,
            "transition_digest": self.transition_digest,
            "transition_type": self.document["transition_type"],
            "sequence": self.document["sequence"],
            "signature_roles_verified": list(self.signature_roles_verified),
            "signed_input_sha256": dict(self.signed_input_sha256),
            "fixture_mode": self.fixture_mode,
            "signatures_verified": self.signatures_verified,
            "owner_authenticated": self.owner_authenticated,
            "production_gate_approved": False,
            "production_dispatch_allowed": False,
            "iso_release_allowed": False,
            "verification_digest": self.verification_digest,
        }


def _expected_signature_binding(
    role: str,
    transition: Mapping[str, Any],
    previous_trust_state: Mapping[str, Any] | None,
    next_trust_state: Mapping[str, Any] | None,
) -> tuple[str, str]:
    if role == "current-owner":
        if previous_trust_state is None:
            raise PolicyError("Phase 41 current owner has no previous trust state")
        parsed = phase40.parse_trust_state(previous_trust_state)
        return parsed["owner_job_signer_fingerprint"], parsed["owner_keyring_sha256"]
    if next_trust_state is None:
        raise PolicyError("Phase 41 incoming signer has no next trust state")
    parsed = phase40.parse_trust_state(next_trust_state)
    if role == "next-owner-proof":
        return parsed["owner_job_signer_fingerprint"], parsed["owner_keyring_sha256"]
    if role == "next-build-node-proof":
        return (
            parsed["build_node_result_signer_fingerprint"],
            parsed["build_node_keyring_sha256"],
        )
    raise PolicyError("Phase 41 signature role is unknown")


def verify_transition_signatures(
    *, transition_path: Path,
    signature_paths: Mapping[str, Path],
    keyring_paths: Mapping[str, Path],
    previous_ceremony_state: Mapping[str, Any] | None,
    previous_trust_state: Mapping[str, Any] | None,
    next_trust_state: Mapping[str, Any] | None,
    now_unix: int,
    gpgv_executable: str | Path = "/usr/bin/gpgv",
) -> VerifiedCeremonyTransition:
    transition_meta, transition_bytes = phase40.measure_file(
        transition_path, maximum=MAX_TRANSITION_BYTES,
        context="Phase 41 signed owner transition")
    transition = parse_transition(
        _strict_json(transition_bytes, "Phase 41 owner transition"),
        now_unix=now_unix)
    recreated = create_transition(
        transition_type=transition["transition_type"],
        reason_code=transition["reason_code"],
        sequence=transition["sequence"],
        created_unix=transition["created_unix"],
        expires_unix=transition["expires_unix"],
        challenge_nonce=transition["challenge_nonce"],
        previous_ceremony_state=previous_ceremony_state,
        previous_trust_state=previous_trust_state,
        next_trust_state=next_trust_state,
        fixture_mode=transition["fixture_mode"],
    )
    if transition != recreated:
        raise PolicyError("Phase 41 transition differs from supplied trust states")
    roles = tuple(transition["required_signature_roles"])
    if set(signature_paths) != set(roles) or set(keyring_paths) != set(roles):
        raise PolicyError("Phase 41 detached signature inventory is incomplete or extra")
    signed_inputs = {"transition": transition_meta.sha256}
    seen_identities: set[tuple[int, int]] = set()
    for role in roles:
        signature_meta, signature = phase40.measure_file(
            signature_paths[role], maximum=MAX_SIGNATURE_BYTES,
            context=f"Phase 41 {role} detached signature")
        keyring_meta, keyring = phase40.measure_file(
            keyring_paths[role], maximum=MAX_KEYRING_BYTES,
            context=f"Phase 41 {role} verification keyring")
        identity = (keyring_meta.device, keyring_meta.inode)
        # The same owner keyring may satisfy current-owner and next-owner-proof
        # only when the transition does not claim an owner change.  Such a
        # duplicate role is never generated by create_transition.
        if identity in seen_identities:
            raise PolicyError("Phase 41 signature keyrings alias a file identity")
        seen_identities.add(identity)
        expected_fingerprint, expected_keyring_digest = _expected_signature_binding(
            role, transition, previous_trust_state, next_trust_state)
        if keyring_meta.sha256 != expected_keyring_digest:
            raise PolicyError("Phase 41 signature keyring differs from trust state")
        phase39._verify_signature(  # type: ignore[attr-defined]
            payload=transition_bytes,
            signature=signature,
            keyring=keyring,
            expected_fingerprint=expected_fingerprint,
            gpgv_executable=gpgv_executable,
            fixture_mode=transition["fixture_mode"],
            role=f"phase41-{role}",
        )
        signed_inputs[f"{role}-signature"] = signature_meta.sha256
        signed_inputs[f"{role}-keyring"] = keyring_meta.sha256
    previous_trust = (
        None if previous_trust_state is None
        else phase40.parse_trust_state(previous_trust_state)
    )
    next_trust = (
        None if next_trust_state is None
        else phase40.parse_trust_state(next_trust_state)
    )
    trust_authenticated = bool(
        (next_trust or previous_trust)
        and (next_trust or previous_trust)["owner_trust_authenticated"]
    )
    fixture_mode = bool(
        transition["fixture_mode"]
        or (previous_trust is not None and previous_trust["fixture_mode"])
        or (next_trust is not None and next_trust["fixture_mode"])
    )
    owner_authenticated = bool(trust_authenticated and not fixture_mode)
    unsigned = {
        "format": VERIFICATION_FORMAT,
        "transition_digest": transition["transition_digest"],
        "transition_type": transition["transition_type"],
        "sequence": transition["sequence"],
        "signature_roles_verified": list(roles),
        "signed_input_sha256": signed_inputs,
        "fixture_mode": fixture_mode,
        "signatures_verified": True,
        "owner_authenticated": owner_authenticated,
        "production_gate_approved": False,
        "production_dispatch_allowed": False,
        "iso_release_allowed": False,
    }
    verification_digest = _digest(VERIFICATION_DOMAIN, unsigned)
    return VerifiedCeremonyTransition(
        document=transition,
        transition_digest=transition["transition_digest"],
        signature_roles_verified=roles,
        signed_input_sha256=signed_inputs,
        fixture_mode=fixture_mode,
        signatures_verified=True,
        owner_authenticated=owner_authenticated,
        verification_digest=verification_digest,
    )


def create_ceremony_state(
    *, verified_transition: VerifiedCeremonyTransition,
    previous_ceremony_state: Mapping[str, Any] | None,
    previous_trust_state: Mapping[str, Any] | None,
    next_trust_state: Mapping[str, Any] | None,
) -> dict[str, Any]:
    if not isinstance(verified_transition, VerifiedCeremonyTransition):
        raise PolicyError("Phase 41 verified transition is required")
    transition = verified_transition.document
    previous_ceremony = (
        None if previous_ceremony_state is None
        else parse_ceremony_state(previous_ceremony_state)
    )
    previous_trust = (
        None if previous_trust_state is None
        else phase40.parse_trust_state(previous_trust_state)
    )
    next_trust = (
        None if next_trust_state is None
        else phase40.parse_trust_state(next_trust_state)
    )
    transition_type = transition["transition_type"]
    if transition_type in {"initialize", "rotate"}:
        if next_trust is None:
            raise PolicyError("Phase 41 active transition lacks next trust state")
        trust = next_trust
        status = "active"
        quarantine_reason = ""
    elif transition_type == "revoke-build-node":
        if previous_trust is None:
            raise PolicyError("Phase 41 revocation lacks current trust state")
        trust = previous_trust
        status = "quarantined"
        quarantine_reason = transition["reason_code"]
    else:
        if previous_ceremony is None or previous_trust is None or next_trust is None:
            raise PolicyError("Phase 41 recovery lacks the anchored state")
        if previous_trust != next_trust:
            raise PolicyError("Phase 41 recovery changed trust state")
        trust = previous_trust
        status = previous_ceremony["status"]
        quarantine_reason = previous_ceremony["quarantine_reason"]
    owner_authenticated = bool(
        verified_transition.owner_authenticated
        and trust["owner_trust_authenticated"]
        and not verified_transition.fixture_mode
    )
    gate1_jobs_allowed = bool(status == "active" and owner_authenticated)
    unsigned = {
        "format": STATE_FORMAT,
        "contract_digest": ceremony_contract_digest(),
        "sequence": transition["sequence"],
        "trust_generation": trust["generation"],
        "transition_type": transition_type,
        "status": status,
        "quarantine_reason": quarantine_reason,
        "transition_digest": transition["transition_digest"],
        "previous_ceremony_state_digest": transition[
            "previous_ceremony_state_digest"
        ],
        "trust_state_digest": trust["state_digest"],
        "owner_signing_fingerprint": trust["owner_job_signer_fingerprint"],
        "owner_keyring_sha256": trust["owner_keyring_sha256"],
        "build_node_signing_fingerprint": trust[
            "build_node_result_signer_fingerprint"
        ],
        "build_node_keyring_sha256": trust["build_node_keyring_sha256"],
        "build_node_id": trust["build_node_id"],
        "fixture_mode": verified_transition.fixture_mode,
        "transition_signatures_verified": verified_transition.signatures_verified,
        "owner_trust_authenticated": owner_authenticated,
        "gate1_jobs_allowed": gate1_jobs_allowed,
        "production_gate_approved": False,
        "production_dispatch_allowed": False,
        "iso_release_allowed": False,
    }
    return {**unsigned, "state_digest": _digest(STATE_DOMAIN, unsigned)}


def parse_ceremony_state(value: Mapping[str, Any]) -> dict[str, Any]:
    required = set(state_schema()["required"])
    if type(value) is not dict or set(value) != required:
        raise PolicyError("Phase 41 ceremony-state fields are not closed")
    candidate = json.loads(canonical_json_bytes(value))
    if candidate["format"] != STATE_FORMAT:
        raise PolicyError("Phase 41 ceremony-state format is invalid")
    if candidate["contract_digest"] != ceremony_contract_digest():
        raise PolicyError("Phase 41 ceremony-state contract drifted")
    if type(candidate["sequence"]) is not int or candidate["sequence"] < 1:
        raise PolicyError("Phase 41 ceremony-state sequence is invalid")
    if type(candidate["trust_generation"]) is not int or candidate["trust_generation"] < 1:
        raise PolicyError("Phase 41 ceremony-state trust generation is invalid")
    if candidate["transition_type"] not in TRANSITION_TYPES:
        raise PolicyError("Phase 41 ceremony-state transition type is invalid")
    if candidate["status"] not in STATE_STATUSES:
        raise PolicyError("Phase 41 ceremony-state status is invalid")
    if type(candidate["quarantine_reason"]) is not str or len(
        candidate["quarantine_reason"]
    ) > 128:
        raise PolicyError("Phase 41 ceremony-state quarantine reason is invalid")
    for field in (
        "transition_digest", "previous_ceremony_state_digest",
        "trust_state_digest", "owner_keyring_sha256",
        "build_node_keyring_sha256",
    ):
        _sha(candidate[field], f"Phase 41 ceremony-state {field}",
             allow_zero=(field == "previous_ceremony_state_digest"))
    _fpr(candidate["owner_signing_fingerprint"], "Phase 41 ceremony owner")
    _fpr(candidate["build_node_signing_fingerprint"], "Phase 41 ceremony node")
    _token(candidate["build_node_id"], "Phase 41 ceremony node ID")
    for field in (
        "fixture_mode", "transition_signatures_verified",
        "owner_trust_authenticated", "gate1_jobs_allowed",
        "production_gate_approved", "production_dispatch_allowed",
        "iso_release_allowed",
    ):
        if type(candidate[field]) is not bool:
            raise PolicyError(f"Phase 41 ceremony-state {field} is invalid")
    if (
        candidate["production_gate_approved"]
        or candidate["production_dispatch_allowed"]
        or candidate["iso_release_allowed"]
    ):
        raise PolicyError("Phase 41 ceremony state attempted release promotion")
    expected_auth = bool(
        candidate["transition_signatures_verified"] and not candidate["fixture_mode"]
    )
    if candidate["owner_trust_authenticated"] and not expected_auth:
        raise PolicyError("Phase 41 ceremony state fabricated owner authentication")
    expected_jobs = bool(
        candidate["status"] == "active"
        and candidate["owner_trust_authenticated"]
        and not candidate["fixture_mode"]
    )
    if candidate["gate1_jobs_allowed"] != expected_jobs:
        raise PolicyError("Phase 41 ceremony-state Gate 1 policy drifted")
    if candidate["status"] == "active" and candidate["quarantine_reason"]:
        raise PolicyError("Phase 41 active ceremony state has a quarantine reason")
    if candidate["status"] == "quarantined" and not candidate["quarantine_reason"]:
        raise PolicyError("Phase 41 quarantined state lacks a reason")
    if candidate["sequence"] == 1:
        if candidate["previous_ceremony_state_digest"] != ZERO_SHA:
            raise PolicyError("Phase 41 initial ceremony state has a predecessor")
    elif candidate["previous_ceremony_state_digest"] == ZERO_SHA:
        raise PolicyError("Phase 41 later ceremony state lacks a predecessor")
    unsigned = {key: candidate[key] for key in candidate if key != "state_digest"}
    if candidate["state_digest"] != _digest(STATE_DOMAIN, unsigned):
        raise PolicyError("Phase 41 ceremony-state digest is invalid")
    return candidate


def _record_for_state(state: Mapping[str, Any]) -> dict[str, Any]:
    parsed = parse_ceremony_state(state)
    return {
        "sequence": parsed["sequence"],
        "transition_type": parsed["transition_type"],
        "status": parsed["status"],
        "transition_digest": parsed["transition_digest"],
        "state_digest": parsed["state_digest"],
        "previous_state_digest": parsed["previous_ceremony_state_digest"],
        "trust_state_digest": parsed["trust_state_digest"],
    }


def create_ceremony_store(
    *, state: Mapping[str, Any], previous_store: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    parsed_state = parse_ceremony_state(state)
    if previous_store is None:
        if parsed_state["sequence"] != 1:
            raise PolicyError("Phase 41 initial ceremony store requires sequence one")
        records = [_record_for_state(parsed_state)]
        generation = 1
    else:
        previous = parse_ceremony_store(previous_store)
        current = previous["current_state"]
        if parsed_state["sequence"] != previous["highest_sequence"] + 1:
            raise PolicyError("Phase 41 ceremony store rejected a stale sequence")
        if parsed_state["previous_ceremony_state_digest"] != current["state_digest"]:
            raise PolicyError("Phase 41 ceremony store state chain drifted")
        records = [*previous["records"], _record_for_state(parsed_state)]
        if len(records) > MAX_STORE_RECORDS:
            raise PolicyError("Phase 41 ceremony store record limit exceeded")
        generation = previous["generation"] + 1
    unsigned = {
        "format": STORE_FORMAT,
        "contract_digest": ceremony_contract_digest(),
        "generation": generation,
        "highest_sequence": parsed_state["sequence"],
        "current_state": parsed_state,
        "records": records,
        "equivocation_detected": False,
        "production_dispatch_allowed": False,
        "iso_release_allowed": False,
    }
    return {**unsigned, "store_digest": _digest(STORE_DOMAIN, unsigned)}


def parse_ceremony_store(value: Mapping[str, Any]) -> dict[str, Any]:
    required = set(store_schema()["required"])
    if type(value) is not dict or set(value) != required:
        raise PolicyError("Phase 41 ceremony-store fields are not closed")
    candidate = json.loads(canonical_json_bytes(value))
    if candidate["format"] != STORE_FORMAT:
        raise PolicyError("Phase 41 ceremony-store format is invalid")
    if candidate["contract_digest"] != ceremony_contract_digest():
        raise PolicyError("Phase 41 ceremony-store contract drifted")
    if type(candidate["generation"]) is not int or candidate["generation"] < 1:
        raise PolicyError("Phase 41 ceremony-store generation is invalid")
    if type(candidate["highest_sequence"]) is not int or candidate[
        "highest_sequence"
    ] < 1:
        raise PolicyError("Phase 41 ceremony-store sequence is invalid")
    current = parse_ceremony_state(candidate["current_state"])
    records = candidate["records"]
    if (
        type(records) is not list
        or not records
        or len(records) > MAX_STORE_RECORDS
        or candidate["generation"] != len(records)
        or candidate["highest_sequence"] != len(records)
        or current["sequence"] != candidate["highest_sequence"]
    ):
        raise PolicyError("Phase 41 ceremony-store inventory is invalid")
    previous = ZERO_SHA
    seen_sequences: dict[int, str] = {}
    for expected_sequence, record in enumerate(records, 1):
        fields = {
            "sequence", "transition_type", "status", "transition_digest",
            "state_digest", "previous_state_digest", "trust_state_digest",
        }
        if type(record) is not dict or set(record) != fields:
            raise PolicyError("Phase 41 ceremony-store record fields are not closed")
        if record["sequence"] != expected_sequence:
            raise PolicyError("Phase 41 ceremony-store record sequence drifted")
        if record["transition_type"] not in TRANSITION_TYPES:
            raise PolicyError("Phase 41 ceremony-store transition type drifted")
        if record["status"] not in STATE_STATUSES:
            raise PolicyError("Phase 41 ceremony-store status drifted")
        for field in (
            "transition_digest", "state_digest", "previous_state_digest",
            "trust_state_digest",
        ):
            _sha(record[field], f"Phase 41 store record {field}",
                 allow_zero=(field == "previous_state_digest"))
        if record["previous_state_digest"] != previous:
            raise PolicyError("Phase 41 ceremony-store digest chain drifted")
        existing = seen_sequences.get(record["sequence"])
        if existing is not None and existing != record["state_digest"]:
            raise PolicyError("Phase 41 ceremony-store equivocation detected")
        seen_sequences[record["sequence"]] = record["state_digest"]
        previous = record["state_digest"]
    if records[-1] != _record_for_state(current):
        raise PolicyError("Phase 41 ceremony-store current state drifted")
    if candidate["equivocation_detected"] is not False:
        raise PolicyError("Phase 41 ceremony store cannot clear equivocation")
    if (
        candidate["production_dispatch_allowed"] is not False
        or candidate["iso_release_allowed"] is not False
    ):
        raise PolicyError("Phase 41 ceremony store attempted release promotion")
    unsigned = {key: candidate[key] for key in candidate if key != "store_digest"}
    if candidate["store_digest"] != _digest(STORE_DOMAIN, unsigned):
        raise PolicyError("Phase 41 ceremony-store digest is invalid")
    return candidate


def _private_parent(path: Path, context: str) -> Path:
    parent = path.absolute().parent
    parent.mkdir(parents=True, mode=0o700, exist_ok=True)
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
    parent = _private_parent(path, "Phase 41 atomic publication")
    fd, raw = tempfile.mkstemp(prefix=".phase41-store-", dir=parent)
    temporary = Path(raw)
    try:
        os.fchmod(fd, mode)
        view = memoryview(payload)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise PolicyError("Phase 41 atomic write did not complete")
            view = view[written:]
        os.fsync(fd)
        os.close(fd)
        fd = -1
        os.replace(temporary, path)
        directory_fd = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if fd >= 0:
            os.close(fd)
        temporary.unlink(missing_ok=True)


def _load_store(path: Path) -> dict[str, Any] | None:
    if not path.exists() and not path.is_symlink():
        return None
    _, payload = phase40.measure_file(
        path, maximum=MAX_STORE_BYTES, context="Phase 41 ceremony store")
    return parse_ceremony_store(_strict_json(payload, "Phase 41 ceremony store"))


def publish_ceremony_store(path: Path, state: Mapping[str, Any]) -> dict[str, Any]:
    destination = path.absolute()
    parent = _private_parent(destination, "Phase 41 ceremony store")
    lock_path = parent / f".{destination.name}.lock"
    flags = (
        os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        lock_fd = os.open(lock_path, flags, 0o600)
    except OSError as exc:
        raise PolicyError("Phase 41 ceremony-store lock cannot be opened") from exc
    try:
        os.fchmod(lock_fd, 0o600)
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        previous = _load_store(destination)
        parsed_state = parse_ceremony_state(state)
        if previous is not None:
            for record in previous["records"]:
                if record["sequence"] == parsed_state["sequence"]:
                    if record["state_digest"] != parsed_state["state_digest"]:
                        raise PolicyError("Phase 41 ceremony equivocation detected")
                    raise PolicyError("Phase 41 ceremony transition is a replay")
        store = create_ceremony_store(state=parsed_state, previous_store=previous)
        _atomic_write(destination, canonical_json_bytes(store), mode=0o600)
        return store
    finally:
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
        finally:
            os.close(lock_fd)


def recover_ceremony_store(
    *, destination: Path, checkpoint: Mapping[str, Any],
    minimum_sequence: int, expected_state_digest: str,
) -> dict[str, Any]:
    recovered = parse_ceremony_store(checkpoint)
    if type(minimum_sequence) is not int or minimum_sequence < 1:
        raise PolicyError("Phase 41 recovery anchor sequence is invalid")
    expected = _sha(expected_state_digest, "Phase 41 recovery anchor digest")
    if (
        recovered["highest_sequence"] < minimum_sequence
        or recovered["current_state"]["state_digest"] != expected
    ):
        raise PolicyError("Phase 41 recovery checkpoint is below the external anchor")
    target = destination.absolute()
    parent = _private_parent(target, "Phase 41 recovery destination")
    lock_path = parent / f".{target.name}.recovery.lock"
    flags = (
        os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    lock_fd = os.open(lock_path, flags, 0o600)
    try:
        os.fchmod(lock_fd, 0o600)
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        current = _load_store(target)
        if current is not None:
            if current["highest_sequence"] > recovered["highest_sequence"]:
                raise PolicyError("Phase 41 recovery attempted rollback")
            if (
                current["highest_sequence"] == recovered["highest_sequence"]
                and current["store_digest"] != recovered["store_digest"]
            ):
                raise PolicyError("Phase 41 recovery detected equivocation")
            if current["store_digest"] == recovered["store_digest"]:
                raise PolicyError("Phase 41 recovery checkpoint is already installed")
        _atomic_write(target, canonical_json_bytes(recovered), mode=0o600)
        return recovered
    finally:
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
        finally:
            os.close(lock_fd)


def _transition_request_template(transition_type: str) -> dict[str, Any]:
    if transition_type not in TRANSITION_TYPES:
        raise PolicyError("Phase 41 kit transition type is invalid")
    previous_required = transition_type != "initialize"
    next_required = transition_type in {"initialize", "rotate", "recover-state"}
    return {
        "format": "securityops-phase41-transition-request-template/1",
        "transition_type": transition_type,
        "reason_code": REASON_CODES[transition_type][0],
        "sequence": 1 if transition_type == "initialize" else "NEXT_SEQUENCE",
        "created_unix": "OWNER_SELECTED_UNIX_TIME",
        "expires_unix": "OWNER_SELECTED_BOUNDED_EXPIRY",
        "challenge_nonce": "OWNER_GENERATED_64_HEX_NONCE",
        "previous_ceremony_state": (
            "VERIFIED_PREVIOUS_CEREMONY_STATE.json" if previous_required else None
        ),
        "previous_trust_state": (
            "VERIFIED_PREVIOUS_PHASE40_TRUST_STATE.json" if previous_required else None
        ),
        "next_trust_state": (
            "VERIFIED_NEXT_PHASE40_TRUST_STATE.json" if next_required else None
        ),
        "fixture": False,
        "secret_key_material_in_request": False,
        "production_gate_approved": False,
        "production_dispatch_allowed": False,
        "iso_release_allowed": False,
    }


def generate_ceremony_kit(destination: Path) -> dict[str, Any]:
    """Generate a deterministic, secret-free offline ceremony operator kit."""

    try:
        from . import phase41_gate1_execution as gate1
    except ImportError:  # pragma: no cover - installed sibling module
        import phase41_gate1_execution as gate1  # type: ignore[no-redef]

    root = destination.absolute()
    if root.exists() or root.is_symlink():
        raise PolicyError("Phase 41 ceremony-kit destination already exists")
    parent = root.parent
    parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix=".phase41-kit-", dir=parent))
    temporary.chmod(0o700)
    try:
        readme = (
            "# Security Ops OS Phase 41 owner ceremony kit\n\n"
            "This deterministic kit contains only public contracts, schemas, "
            "request templates, and command stubs. It never generates, imports, "
            "or uses a secret signing key. Perform signing on the independently "
            "controlled offline owner system. Keep owner and build-node identities "
            "separate, pin fingerprints and public-keyring hashes out of band, and "
            "use the installed `securityops-phase41-ceremony` command to create and "
            "verify transitions. Initialization, rotation, revocation, and recovery "
            "do not approve a production gate. Gate 1 remains blocked until a real "
            "non-fixture Phase 39 exchange and Phase 40 semantic receipt pass.\n"
        ).encode("utf-8")
        readme_pt = (
            "# Kit de cerimônia do proprietário — Security Ops OS Fase 41\n\n"
            "Este kit determinístico contém somente contratos públicos, esquemas, "
            "modelos de requisição e comandos auxiliares. Ele nunca gera, importa "
            "ou utiliza chave secreta de assinatura. Assine no sistema offline "
            "controlado pelo proprietário, mantenha separadas as identidades do "
            "proprietário e do nó de build e fixe fingerprints e hashes dos "
            "chaveiros públicos por canal externo. Use o comando instalado "
            "`securityops-phase41-ceremony` para criar e verificar transições. "
            "Inicialização, rotação, revogação e recuperação não aprovam produção; "
            "o Gate 1 exige o recibo real, não-fixture, das Fases 39 e 40.\n"
        ).encode("utf-8")
        command_stub = (
            "#!/usr/bin/env python3\n"
            "raise SystemExit('Use the measured installed securityops-phase41-ceremony command')\n"
        ).encode("utf-8")
        files: dict[str, tuple[bytes, int]] = {
            "README.md": (readme, 0o444),
            "README.pt-BR.md": (readme_pt, 0o444),
            "phase41-owner-ceremony-contract.json": (
                canonical_json_bytes(ceremony_contract()), 0o444),
            "phase41-gate1-execution-contract.json": (
                canonical_json_bytes(gate1.gate1_execution_contract()), 0o444),
            "phase41-owner-transition.schema.json": (
                canonical_json_bytes(transition_schema()), 0o444),
            "phase41-owner-ceremony-state.schema.json": (
                canonical_json_bytes(state_schema()), 0o444),
            "phase41-owner-ceremony-store.schema.json": (
                canonical_json_bytes(store_schema()), 0o444),
            "phase41-gate1-decision.schema.json": (
                canonical_json_bytes(gate1.decision_schema()), 0o444),
            "phase41-gate1-decision-ledger.schema.json": (
                canonical_json_bytes(gate1.ledger_schema()), 0o444),
            "initialize.request.template.json": (
                canonical_json_bytes(_transition_request_template("initialize")), 0o444),
            "rotate.request.template.json": (
                canonical_json_bytes(_transition_request_template("rotate")), 0o444),
            "revoke-build-node.request.template.json": (
                canonical_json_bytes(
                    _transition_request_template("revoke-build-node")), 0o444),
            "recover-state.request.template.json": (
                canonical_json_bytes(_transition_request_template("recover-state")), 0o444),
            "gate1-import.request.template.json": (
                canonical_json_bytes({
                    "format": "securityops-phase41-gate1-import-request-template/1",
                    "ceremony_state": "ACTIVE_NONFIXTURE_CEREMONY_STATE.json",
                    "phase40_trust_state": "AUTHENTICATED_PHASE40_TRUST_STATE.json",
                    "phase39_verified_exchange": "DUAL_SIGNED_PHASE39_EXCHANGE.json",
                    "phase40_semantic_admission": "PHASE40_GATE1_ADMISSION.json",
                    "fixture": False,
                    "production_dispatch_allowed": False,
                    "iso_release_allowed": False,
                }), 0o444),
            "scripts/create-transition.py": (command_stub, 0o555),
            "scripts/verify-transition.py": (command_stub, 0o555),
            "scripts/import-gate1-decision.py": (command_stub, 0o555),
        }
        if tuple(sorted(files)) != tuple(sorted(KIT_FILES)):
            raise PolicyError("Phase 41 ceremony-kit inventory drifted")
        records: list[dict[str, Any]] = []
        for relative in KIT_FILES:
            payload, mode = files[relative]
            target = temporary / relative
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            target.write_bytes(payload)
            target.chmod(mode)
            records.append({
                "path": relative,
                "sha256": hashlib.sha256(payload).hexdigest(),
                "bytes": len(payload),
                "mode": mode,
            })
        os.replace(temporary, root)
        temporary = Path("/nonexistent")
        unsigned = {
            "format": KIT_FORMAT,
            "status": "PASS_PHASE41_DETERMINISTIC_SECRET_FREE_CEREMONY_KIT_GENERATED",
            "ceremony_contract_digest": ceremony_contract_digest(),
            "gate1_contract_digest": gate1.gate1_execution_contract_digest(),
            "files": records,
            "file_count": len(records),
            "contains_secret_keys": False,
            "generates_secret_keys": False,
            "performs_signing": False,
            "creates_owner_authority": False,
            "production_gates_approved": 0,
            "production_dispatch_allowed": False,
            "iso_release_allowed": False,
        }
        return {**unsigned, "kit_digest": _digest(KIT_DOMAIN, unsigned)}
    finally:
        if temporary.exists():
            shutil.rmtree(temporary)


def blocked_ceremony_observation() -> dict[str, Any]:
    unsigned = {
        "format": "securityops-phase41-owner-ceremony-observation/1",
        "status": BLOCKED_STATUS,
        "phase41_contract_digest": ceremony_contract_digest(),
        "real_owner_keys_supplied": False,
        "owner_signed_transition_present": False,
        "independent_build_node_proof_present": False,
        "authenticated_input_closure_present": False,
        "gate1_receipt_present": False,
        "production_gates_approved": 0,
        "production_dispatch_allowed": False,
        "iso_release_allowed": False,
        "iso_bytes_present": False,
    }
    return {
        **unsigned,
        "observation_digest": hashlib.sha256(
            b"SECURITYOPS-PHASE41-CEREMONY-OBSERVATION-V1\x00"
            + canonical_json_bytes(unsigned)
        ).hexdigest(),
    }


def run_negative_matrix() -> dict[str, Any]:
    contract = ceremony_contract()
    rejected = 0

    def expect_reject(value: Mapping[str, Any]) -> None:
        nonlocal rejected
        try:
            parse_ceremony_contract(value)
        except PolicyError:
            rejected += 1
        else:  # pragma: no cover - defensive
            raise AssertionError("Phase 41 negative contract mutation was accepted")

    mutations: list[dict[str, Any]] = []
    for name in NEGATIVE_CASES:
        value = json.loads(canonical_json_bytes(contract))
        if name == "extra-contract-field":
            value["unexpected"] = True
        elif name == "phase40-owner-contract-drift":
            value["phase40_owner_contract_digest"] = "1" * 64
        elif name == "phase40-gate1-contract-drift":
            value["phase40_gate1_contract_digest"] = "2" * 64
        elif name == "phase40-source-identity-drift":
            value["phase40_identities"]["runtime_commit"] = "3" * 40
        elif name == "transition-type-removed":
            value["transition_types"].pop()
        elif name == "signature-role-removed":
            value["signature_policy"]["roles"].pop()
        elif name == "initial-transition-with-previous-state":
            value["state_policy"]["sequence_strictly_consecutive"] = False
        elif name == "rotation-without-current-owner-signature":
            value["signature_policy"]["rotation_requires_current_owner_authorization"] = False
        elif name == "incoming-owner-without-proof":
            value["signature_policy"]["changed_owner_requires_incoming_proof"] = False
        elif name == "incoming-node-without-proof":
            value["signature_policy"]["changed_build_node_requires_incoming_proof"] = False
        elif name == "rotation-without-identity-change":
            value["state_policy"]["trust_generation_consecutive_on_rotation"] = False
        elif name == "nonconsecutive-trust-generation":
            value["state_policy"]["trust_generation_consecutive_on_rotation"] = False
        elif name == "revoke-with-node-proof-substitution":
            value["signature_policy"]["revocation_requires_current_owner_authorization"] = False
        elif name == "revoked-state-can-create-gate1-job":
            value["state_policy"]["revocation_quarantines_gate1"] = False
        elif name == "recovery-clears-quarantine":
            value["state_policy"]["recovery_cannot_clear_quarantine"] = False
        elif name == "recovery-changes-trust-state":
            value["state_policy"]["recovery_cannot_change_trust_state"] = False
        elif name == "stale-sequence-accepted":
            value["store_policy"]["stale_transition_rejected"] = False
        elif name == "equivocation-accepted":
            value["store_policy"]["same_sequence_different_state_is_equivocation"] = False
        elif name == "rollback-recovery-accepted":
            value["store_policy"]["rollback_rejected"] = False
        elif name == "unanchored-recovery-accepted":
            value["store_policy"]["externally_anchored_recovery_required"] = False
        elif name == "fixture-owner-promotion":
            value["state_policy"]["fixture_can_authenticate_owner"] = True
        elif name == "secret-key-use-by-runtime-enabled":
            value["signature_policy"]["runtime_handles_secret_keys"] = True
        elif name == "original-path-signature-verification-enabled":
            value["signature_policy"]["original_paths_reopened_after_measurement"] = True
        elif name == "production-promotion":
            value["production_dispatch_allowed"] = True
        elif name == "iso-promotion":
            value["iso_release_allowed"] = True
        else:  # pragma: no cover
            raise AssertionError(name)
        unsigned = dict(value)
        unsigned.pop("contract_digest", None)
        value["contract_digest"] = _digest(CONTRACT_DOMAIN, unsigned)
        mutations.append(value)
    for mutation in mutations:
        expect_reject(mutation)
    return {
        "format": "securityops-phase41-owner-ceremony-negative-results/1",
        "cases": list(NEGATIVE_CASES),
        "rejected": rejected,
        "total": len(NEGATIVE_CASES),
        "all_rejected": rejected == len(NEGATIVE_CASES),
        "production_gates_approved": 0,
        "production_dispatch_allowed": False,
        "iso_release_allowed": False,
    }


def phase41_selftest() -> dict[str, Any]:
    parsed = parse_ceremony_contract(ceremony_contract())
    negatives = run_negative_matrix()
    observation = blocked_ceremony_observation()
    unsigned = {
        "format": "securityops-phase41-owner-ceremony-selftest/1",
        "status": STATUS,
        "contract_digest": parsed["contract_digest"],
        "schemas": {
            "transition": hashlib.sha256(
                canonical_json_bytes(transition_schema())).hexdigest(),
            "state": hashlib.sha256(
                canonical_json_bytes(state_schema())).hexdigest(),
            "store": hashlib.sha256(
                canonical_json_bytes(store_schema())).hexdigest(),
        },
        "negative_cases_rejected": negatives["rejected"],
        "negative_cases_total": negatives["total"],
        "real_owner_authority_created": False,
        "blocked_observation_digest": observation["observation_digest"],
        "production_gates_approved": 0,
        "production_dispatch_allowed": False,
        "iso_release_allowed": False,
    }
    return {
        **unsigned,
        "selftest_digest": hashlib.sha256(
            b"SECURITYOPS-PHASE41-CEREMONY-SELFTEST-V1\x00"
            + canonical_json_bytes(unsigned)
        ).hexdigest(),
    }
