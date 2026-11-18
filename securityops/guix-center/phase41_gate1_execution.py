# CodeMark v1 project=4c63e0fe-589c-4944-8449-97e211a38b72 file=011ddf63679e50c887b7f6d84ecfc091 owner="Cristian Cezar Mois\u00e9s"
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Phase 41 Gate 1 decision and semantic-receipt replay boundary.

This module chains the Phase 41 ceremony state to the Phase 39 dual-signed
exchange and the Phase 40 semantic Gate 1 receipt.  It does not repeat or
weaken either verifier.  A local decision is approved only when the active
ceremony, trust state, signed exchange, semantic evidence and all digests are
exactly consistent and non-fixture.
"""
from __future__ import annotations

import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tempfile
from typing import Any, Final, Mapping

try:
    from . import phase39_owner_execution as phase39
    from . import phase40_gate1_admission as phase40_gate1
    from . import phase40_owner_trust as phase40
    from . import phase41_owner_ceremony as ceremony
except ImportError:  # pragma: no cover - installed Guix Center copy
    import phase39_owner_execution as phase39  # type: ignore[no-redef]
    import phase40_gate1_admission as phase40_gate1  # type: ignore[no-redef]
    import phase40_owner_trust as phase40  # type: ignore[no-redef]
    import phase41_owner_ceremony as ceremony  # type: ignore[no-redef]

PolicyError = phase40.PolicyError
canonical_json_bytes = phase40.canonical_json_bytes

CONTRACT_FORMAT: Final[str] = "securityops-phase41-gate1-execution-contract/1"
DECISION_FORMAT: Final[str] = "securityops-phase41-gate1-decision/1"
LEDGER_FORMAT: Final[str] = "securityops-phase41-gate1-decision-ledger/1"
STATUS: Final[str] = "PASS_PHASE41_GATE1_CEREMONY_SEMANTIC_RECEIPT_BOUNDARY"
BLOCKED_STATUS: Final[str] = (
    "BLOCKED_PHASE41_NONFIXTURE_AUTHENTICATED_GUIX_QT_GATE1_RECEIPT_REQUIRED"
)

CONTRACT_DOMAIN: Final[bytes] = b"SECURITYOPS-PHASE41-GATE1-EXECUTION-CONTRACT-V1\x00"
DECISION_DOMAIN: Final[bytes] = b"SECURITYOPS-PHASE41-GATE1-DECISION-V1\x00"
LEDGER_DOMAIN: Final[bytes] = b"SECURITYOPS-PHASE41-GATE1-DECISION-LEDGER-V1\x00"
OBSERVATION_DOMAIN: Final[bytes] = b"SECURITYOPS-PHASE41-GATE1-OBSERVATION-V1\x00"

FIRST_GATE: Final[str] = phase39.GATE_NAMES[0]
MAX_LEDGER_RECORDS: Final[int] = 4096
MAX_LEDGER_BYTES: Final[int] = 8 * 1024 * 1024
ZERO_SHA: Final[str] = "0" * 64
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")

NEGATIVE_CASES: Final[tuple[str, ...]] = (
    "extra-contract-field",
    "ceremony-contract-drift",
    "phase40-owner-contract-drift",
    "phase40-gate1-contract-drift",
    "phase39-contract-drift",
    "gate-name-drift",
    "ceremony-active-optional",
    "ceremony-job-authorization-optional",
    "ceremony-trust-binding-optional",
    "phase39-dual-signatures-optional",
    "phase39-replay-ledger-optional",
    "phase40-semantics-optional",
    "input-closure-authentication-optional",
    "fixture-can-pass",
    "quarantine-can-pass",
    "same-job-different-decision-accepted",
    "stale-job-id-accepted",
    "production-promotion",
    "iso-promotion",
)


def _digest(domain: bytes, value: Mapping[str, Any]) -> str:
    return hashlib.sha256(domain + canonical_json_bytes(value)).hexdigest()


def _sha(value: Any, context: str, *, allow_zero: bool = False) -> str:
    if not isinstance(value, str) or not _HEX64.fullmatch(value):
        raise PolicyError(f"{context} must be a lowercase SHA-256 digest")
    if not allow_zero and value == ZERO_SHA:
        raise PolicyError(f"{context} cannot be zero")
    return value


def decision_schema() -> dict[str, Any]:
    sha = {"type": "string", "pattern": "^[0-9a-f]{64}$"}
    required = [
        "format", "contract_digest", "gate_name", "gate_index", "job_id",
        "ceremony_state_digest", "trust_state_digest", "trust_root_digest",
        "input_closure_digest", "phase39_job_digest", "phase39_result_digest",
        "phase39_verification_digest", "phase40_semantic_receipt_digest",
        "ceremony_active", "ceremony_gate1_jobs_allowed",
        "phase39_exchange_verified", "phase40_semantics_verified",
        "owner_trust_authenticated", "input_closure_authenticated",
        "fixture_mode", "gate_approved", "production_gates_approved",
        "production_dispatch_allowed", "iso_release_allowed",
        "iso_bytes_present", "decision_digest",
    ]
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": (
            "https://securityops.co/schemas/guix-center/"
            "phase41-gate1-decision.schema.json"
        ),
        "title": "Security Ops Phase 41 Gate 1 local decision",
        "type": "object", "additionalProperties": False,
        "required": required,
        "properties": {
            "format": {"const": DECISION_FORMAT},
            "contract_digest": sha,
            "gate_name": {"const": FIRST_GATE},
            "gate_index": {"const": 1},
            "job_id": {"type": "integer", "minimum": 1},
            "ceremony_state_digest": sha,
            "trust_state_digest": sha,
            "trust_root_digest": sha,
            "input_closure_digest": sha,
            "phase39_job_digest": sha,
            "phase39_result_digest": sha,
            "phase39_verification_digest": sha,
            "phase40_semantic_receipt_digest": sha,
            "ceremony_active": {"type": "boolean"},
            "ceremony_gate1_jobs_allowed": {"type": "boolean"},
            "phase39_exchange_verified": {"type": "boolean"},
            "phase40_semantics_verified": {"type": "boolean"},
            "owner_trust_authenticated": {"type": "boolean"},
            "input_closure_authenticated": {"type": "boolean"},
            "fixture_mode": {"type": "boolean"},
            "gate_approved": {"type": "boolean"},
            "production_gates_approved": {"type": "integer", "minimum": 0, "maximum": 1},
            "production_dispatch_allowed": {"const": False},
            "iso_release_allowed": {"const": False},
            "iso_bytes_present": {"const": False},
            "decision_digest": sha,
        },
    }


def ledger_schema() -> dict[str, Any]:
    sha = {"type": "string", "pattern": "^[0-9a-f]{64}$"}
    record = {
        "type": "object", "additionalProperties": False,
        "required": [
            "job_id", "job_digest", "result_digest", "decision_digest",
            "ceremony_state_digest", "gate_approved",
        ],
        "properties": {
            "job_id": {"type": "integer", "minimum": 1},
            "job_digest": sha,
            "result_digest": sha,
            "decision_digest": sha,
            "ceremony_state_digest": sha,
            "gate_approved": {"type": "boolean"},
        },
    }
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": (
            "https://securityops.co/schemas/guix-center/"
            "phase41-gate1-decision-ledger.schema.json"
        ),
        "title": "Security Ops Phase 41 Gate 1 semantic decision ledger",
        "type": "object", "additionalProperties": False,
        "required": [
            "format", "contract_digest", "generation", "highest_job_id",
            "records", "production_dispatch_allowed", "iso_release_allowed",
            "ledger_digest",
        ],
        "properties": {
            "format": {"const": LEDGER_FORMAT},
            "contract_digest": sha,
            "generation": {"type": "integer", "minimum": 0},
            "highest_job_id": {"type": "integer", "minimum": 0},
            "records": {
                "type": "array", "maxItems": MAX_LEDGER_RECORDS,
                "items": record,
            },
            "production_dispatch_allowed": {"const": False},
            "iso_release_allowed": {"const": False},
            "ledger_digest": sha,
        },
    }


def _contract_unsigned() -> dict[str, Any]:
    decision = decision_schema()
    ledger = ledger_schema()
    return {
        "format": CONTRACT_FORMAT,
        "status": STATUS,
        "phase41_ceremony_contract_digest": ceremony.ceremony_contract_digest(),
        "phase40_owner_contract_digest": ceremony.PHASE40_OWNER_CONTRACT_DIGEST,
        "phase40_gate1_contract_digest": ceremony.PHASE40_GATE1_CONTRACT_DIGEST,
        "phase39_contract_digest": ceremony.PHASE39_CONTRACT_DIGEST,
        "gate_name": FIRST_GATE,
        "gate_index": 1,
        "schemas": {
            "decision": {
                "id": decision["$id"],
                "canonical_sha256": hashlib.sha256(
                    canonical_json_bytes(decision)).hexdigest(),
            },
            "ledger": {
                "id": ledger["$id"],
                "canonical_sha256": hashlib.sha256(
                    canonical_json_bytes(ledger)).hexdigest(),
            },
            "additional_properties_allowed": False,
        },
        "decision_policy": {
            "active_ceremony_required": True,
            "ceremony_gate1_authorization_required": True,
            "ceremony_trust_state_binding_required": True,
            "phase39_owner_signature_required": True,
            "phase39_result_signature_required": True,
            "phase39_evidence_remeasurement_required": True,
            "phase39_replay_ledger_required": True,
            "phase40_semantic_receipt_required": True,
            "phase40_owner_trust_authentication_required": True,
            "phase40_input_closure_authentication_required": True,
            "fixture_can_pass": False,
            "quarantined_ceremony_can_pass": False,
        },
        "ledger_policy": {
            "monotonic_job_id_required": True,
            "same_job_different_decision_is_equivocation": True,
            "decision_replay_rejected": True,
            "private_atomic_publication_required": True,
            "file_and_directory_fsync_required": True,
            "maximum_records": MAX_LEDGER_RECORDS,
        },
        "production_gates_approved": 0,
        "production_dispatch_allowed": False,
        "iso_release_allowed": False,
        "execution_status": BLOCKED_STATUS,
    }


def gate1_execution_contract() -> dict[str, Any]:
    unsigned = _contract_unsigned()
    return {**unsigned, "contract_digest": _digest(CONTRACT_DOMAIN, unsigned)}


def gate1_execution_contract_digest() -> str:
    return gate1_execution_contract()["contract_digest"]


def parse_gate1_execution_contract(value: Mapping[str, Any]) -> dict[str, Any]:
    expected = gate1_execution_contract()
    if type(value) is not dict or value != expected:
        raise PolicyError("Phase 41 Gate 1 execution contract differs from policy")
    return json.loads(canonical_json_bytes(value))


def create_gate1_decision(
    *, ceremony_state: Mapping[str, Any], trust_state: Mapping[str, Any],
    verification: phase39.VerifiedGateExchange,
    semantic_receipt: phase40_gate1.VerifiedGate1Admission,
) -> dict[str, Any]:
    state = ceremony.parse_ceremony_state(ceremony_state)
    trust = phase40.parse_trust_state(trust_state)
    if not isinstance(verification, phase39.VerifiedGateExchange):
        raise PolicyError("Phase 41 requires a verified Phase 39 exchange")
    if not isinstance(semantic_receipt, phase40_gate1.VerifiedGate1Admission):
        raise PolicyError("Phase 41 requires a verified Phase 40 semantic receipt")
    if verification.gate_name != FIRST_GATE or verification.gate_index != 1:
        raise PolicyError("Phase 41 decision accepts only Gate 1")
    if state["trust_state_digest"] != trust["state_digest"]:
        raise PolicyError("Phase 41 ceremony and trust state differ")
    if (
        state["owner_signing_fingerprint"]
        != trust["owner_job_signer_fingerprint"]
        or state["owner_keyring_sha256"] != trust["owner_keyring_sha256"]
        or state["build_node_signing_fingerprint"]
        != trust["build_node_result_signer_fingerprint"]
        or state["build_node_keyring_sha256"]
        != trust["build_node_keyring_sha256"]
        or state["build_node_id"] != trust["build_node_id"]
    ):
        raise PolicyError("Phase 41 ceremony identity differs from trust state")
    if (
        verification.job_digest != semantic_receipt.phase39_job_digest
        or verification.result_digest != semantic_receipt.phase39_result_digest
        or verification.verification_digest
        != semantic_receipt.phase39_verification_digest
    ):
        raise PolicyError("Phase 41 Phase 39 and Phase 40 receipt identities differ")
    ceremony_active = state["status"] == "active"
    phase39_verified = bool(
        verification.owner_signature_verified
        and verification.result_signature_verified
        and verification.evidence_inventory_verified
        and verification.replay_ledger_updated
    )
    phase40_verified = bool(semantic_receipt.semantic_evidence_verified)
    fixture_mode = bool(
        state["fixture_mode"]
        or trust["fixture_mode"]
        or verification.fixture_mode
        or semantic_receipt.fixture_mode
    )
    owner_authenticated = bool(
        state["owner_trust_authenticated"]
        and trust["owner_trust_authenticated"]
        and verification.owner_authenticated
        and semantic_receipt.owner_trust_authenticated
        and not fixture_mode
    )
    input_authenticated = bool(
        semantic_receipt.input_closure_authenticated and not fixture_mode
    )
    approved = bool(
        ceremony_active
        and state["gate1_jobs_allowed"]
        and phase39_verified
        and phase40_verified
        and owner_authenticated
        and input_authenticated
        and verification.gate_approved
        and semantic_receipt.gate_approved
        and not fixture_mode
    )
    unsigned = {
        "format": DECISION_FORMAT,
        "contract_digest": gate1_execution_contract_digest(),
        "gate_name": FIRST_GATE,
        "gate_index": 1,
        "job_id": verification.job_id,
        "ceremony_state_digest": state["state_digest"],
        "trust_state_digest": trust["state_digest"],
        "trust_root_digest": semantic_receipt.trust_root_digest,
        "input_closure_digest": semantic_receipt.input_closure_digest,
        "phase39_job_digest": verification.job_digest,
        "phase39_result_digest": verification.result_digest,
        "phase39_verification_digest": verification.verification_digest,
        "phase40_semantic_receipt_digest": semantic_receipt.receipt_digest,
        "ceremony_active": ceremony_active,
        "ceremony_gate1_jobs_allowed": state["gate1_jobs_allowed"],
        "phase39_exchange_verified": phase39_verified,
        "phase40_semantics_verified": phase40_verified,
        "owner_trust_authenticated": owner_authenticated,
        "input_closure_authenticated": input_authenticated,
        "fixture_mode": fixture_mode,
        "gate_approved": approved,
        "production_gates_approved": 1 if approved else 0,
        "production_dispatch_allowed": False,
        "iso_release_allowed": False,
        "iso_bytes_present": False,
    }
    return {**unsigned, "decision_digest": _digest(DECISION_DOMAIN, unsigned)}


def parse_gate1_decision(value: Mapping[str, Any]) -> dict[str, Any]:
    required = set(decision_schema()["required"])
    if type(value) is not dict or set(value) != required:
        raise PolicyError("Phase 41 Gate 1 decision fields are not closed")
    candidate = json.loads(canonical_json_bytes(value))
    if candidate["format"] != DECISION_FORMAT:
        raise PolicyError("Phase 41 Gate 1 decision format is invalid")
    if candidate["contract_digest"] != gate1_execution_contract_digest():
        raise PolicyError("Phase 41 Gate 1 decision contract drifted")
    if candidate["gate_name"] != FIRST_GATE or candidate["gate_index"] != 1:
        raise PolicyError("Phase 41 Gate 1 decision gate identity drifted")
    if type(candidate["job_id"]) is not int or candidate["job_id"] < 1:
        raise PolicyError("Phase 41 Gate 1 job ID is invalid")
    for field in (
        "ceremony_state_digest", "trust_state_digest", "trust_root_digest",
        "input_closure_digest", "phase39_job_digest", "phase39_result_digest",
        "phase39_verification_digest", "phase40_semantic_receipt_digest",
    ):
        _sha(candidate[field], f"Phase 41 Gate 1 decision {field}")
    for field in (
        "ceremony_active", "ceremony_gate1_jobs_allowed",
        "phase39_exchange_verified", "phase40_semantics_verified",
        "owner_trust_authenticated", "input_closure_authenticated",
        "fixture_mode", "gate_approved", "production_dispatch_allowed",
        "iso_release_allowed", "iso_bytes_present",
    ):
        if type(candidate[field]) is not bool:
            raise PolicyError(f"Phase 41 Gate 1 decision {field} is invalid")
    if type(candidate["production_gates_approved"]) is not int or candidate[
        "production_gates_approved"
    ] not in {0, 1}:
        raise PolicyError("Phase 41 Gate 1 decision count is invalid")
    expected = bool(
        candidate["ceremony_active"]
        and candidate["ceremony_gate1_jobs_allowed"]
        and candidate["phase39_exchange_verified"]
        and candidate["phase40_semantics_verified"]
        and candidate["owner_trust_authenticated"]
        and candidate["input_closure_authenticated"]
        and not candidate["fixture_mode"]
    )
    if candidate["gate_approved"] != expected:
        raise PolicyError("Phase 41 Gate 1 decision approval relationship drifted")
    if candidate["production_gates_approved"] != (1 if expected else 0):
        raise PolicyError("Phase 41 Gate 1 decision count drifted")
    if (
        candidate["production_dispatch_allowed"]
        or candidate["iso_release_allowed"]
        or candidate["iso_bytes_present"]
    ):
        raise PolicyError("Phase 41 Gate 1 decision attempted release promotion")
    unsigned = {key: candidate[key] for key in candidate if key != "decision_digest"}
    if candidate["decision_digest"] != _digest(DECISION_DOMAIN, unsigned):
        raise PolicyError("Phase 41 Gate 1 decision digest is invalid")
    return candidate


def empty_decision_ledger() -> dict[str, Any]:
    unsigned = {
        "format": LEDGER_FORMAT,
        "contract_digest": gate1_execution_contract_digest(),
        "generation": 0,
        "highest_job_id": 0,
        "records": [],
        "production_dispatch_allowed": False,
        "iso_release_allowed": False,
    }
    return {**unsigned, "ledger_digest": _digest(LEDGER_DOMAIN, unsigned)}


def parse_decision_ledger(value: Mapping[str, Any]) -> dict[str, Any]:
    required = set(ledger_schema()["required"])
    if type(value) is not dict or set(value) != required:
        raise PolicyError("Phase 41 decision-ledger fields are not closed")
    candidate = json.loads(canonical_json_bytes(value))
    if candidate["format"] != LEDGER_FORMAT:
        raise PolicyError("Phase 41 decision-ledger format is invalid")
    if candidate["contract_digest"] != gate1_execution_contract_digest():
        raise PolicyError("Phase 41 decision-ledger contract drifted")
    records = candidate["records"]
    if (
        type(records) is not list
        or len(records) > MAX_LEDGER_RECORDS
        or candidate["generation"] != len(records)
        or candidate["highest_job_id"] != (0 if not records else records[-1]["job_id"])
    ):
        raise PolicyError("Phase 41 decision-ledger inventory is invalid")
    previous_job = 0
    seen_job_digests: dict[str, str] = {}
    seen_decisions: set[str] = set()
    for record in records:
        fields = {
            "job_id", "job_digest", "result_digest", "decision_digest",
            "ceremony_state_digest", "gate_approved",
        }
        if type(record) is not dict or set(record) != fields:
            raise PolicyError("Phase 41 decision-ledger record fields are not closed")
        if type(record["job_id"]) is not int or record["job_id"] <= previous_job:
            raise PolicyError("Phase 41 decision-ledger job IDs are not monotonic")
        for field in (
            "job_digest", "result_digest", "decision_digest",
            "ceremony_state_digest",
        ):
            _sha(record[field], f"Phase 41 decision-ledger {field}")
        if type(record["gate_approved"]) is not bool:
            raise PolicyError("Phase 41 decision-ledger approval is invalid")
        existing = seen_job_digests.get(record["job_digest"])
        if existing is not None and existing != record["decision_digest"]:
            raise PolicyError("Phase 41 semantic-decision equivocation detected")
        if record["decision_digest"] in seen_decisions:
            raise PolicyError("Phase 41 semantic-decision replay detected")
        seen_job_digests[record["job_digest"]] = record["decision_digest"]
        seen_decisions.add(record["decision_digest"])
        previous_job = record["job_id"]
    if (
        candidate["production_dispatch_allowed"] is not False
        or candidate["iso_release_allowed"] is not False
    ):
        raise PolicyError("Phase 41 decision ledger attempted release promotion")
    unsigned = {key: candidate[key] for key in candidate if key != "ledger_digest"}
    if candidate["ledger_digest"] != _digest(LEDGER_DOMAIN, unsigned):
        raise PolicyError("Phase 41 decision-ledger digest is invalid")
    return candidate


def append_decision(
    *, ledger: Mapping[str, Any], decision: Mapping[str, Any],
) -> dict[str, Any]:
    current = parse_decision_ledger(ledger)
    parsed = parse_gate1_decision(decision)
    if parsed["job_id"] <= current["highest_job_id"]:
        raise PolicyError("Phase 41 decision job ID is stale")
    for record in current["records"]:
        if record["job_digest"] == parsed["phase39_job_digest"]:
            if record["decision_digest"] != parsed["decision_digest"]:
                raise PolicyError("Phase 41 semantic-decision equivocation detected")
            raise PolicyError("Phase 41 semantic-decision replay detected")
    record = {
        "job_id": parsed["job_id"],
        "job_digest": parsed["phase39_job_digest"],
        "result_digest": parsed["phase39_result_digest"],
        "decision_digest": parsed["decision_digest"],
        "ceremony_state_digest": parsed["ceremony_state_digest"],
        "gate_approved": parsed["gate_approved"],
    }
    records = [*current["records"], record]
    if len(records) > MAX_LEDGER_RECORDS:
        raise PolicyError("Phase 41 decision ledger is full")
    unsigned = {
        "format": LEDGER_FORMAT,
        "contract_digest": gate1_execution_contract_digest(),
        "generation": current["generation"] + 1,
        "highest_job_id": parsed["job_id"],
        "records": records,
        "production_dispatch_allowed": False,
        "iso_release_allowed": False,
    }
    return {**unsigned, "ledger_digest": _digest(LEDGER_DOMAIN, unsigned)}


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
        raise PolicyError(f"{context} is not strict JSON") from exc
    if duplicates or type(value) is not dict:
        raise PolicyError(f"{context} contains duplicate fields or is not an object")
    return value


def _private_parent(path: Path) -> Path:
    parent = path.absolute().parent
    parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    if parent.is_symlink():
        raise PolicyError("Phase 41 decision-ledger parent cannot be a symlink")
    info = parent.stat()
    if (
        not stat.S_ISDIR(info.st_mode)
        or stat.S_IMODE(info.st_mode) & 0o022
        or info.st_uid not in {0, os.getuid()}
    ):
        raise PolicyError("Phase 41 decision-ledger parent is not private")
    return parent


def publish_decision(path: Path, decision: Mapping[str, Any]) -> dict[str, Any]:
    destination = path.absolute()
    parent = _private_parent(destination)
    lock_path = parent / f".{destination.name}.lock"
    flags = (
        os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    lock_fd = os.open(lock_path, flags, 0o600)
    try:
        os.fchmod(lock_fd, 0o600)
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        if destination.exists() or destination.is_symlink():
            _, payload = phase40.measure_file(
                destination, maximum=MAX_LEDGER_BYTES,
                context="Phase 41 decision ledger")
            current = parse_decision_ledger(
                _strict_json(payload, "Phase 41 decision ledger"))
        else:
            current = empty_decision_ledger()
        updated = append_decision(ledger=current, decision=decision)
        payload = canonical_json_bytes(updated)
        fd, raw = tempfile.mkstemp(prefix=".phase41-decision-", dir=parent)
        temporary = Path(raw)
        try:
            os.fchmod(fd, 0o600)
            view = memoryview(payload)
            while view:
                written = os.write(fd, view)
                if written <= 0:
                    raise PolicyError("Phase 41 decision-ledger write did not complete")
                view = view[written:]
            os.fsync(fd)
            os.close(fd)
            fd = -1
            os.replace(temporary, destination)
            directory_fd = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        finally:
            if fd >= 0:
                os.close(fd)
            temporary.unlink(missing_ok=True)
        return updated
    finally:
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
        finally:
            os.close(lock_fd)


def blocked_gate1_observation() -> dict[str, Any]:
    unsigned = {
        "format": "securityops-phase41-gate1-observation/1",
        "status": BLOCKED_STATUS,
        "phase41_contract_digest": gate1_execution_contract_digest(),
        "ceremony_active": False,
        "owner_authenticated": False,
        "authenticated_input_closure_present": False,
        "phase39_dual_signed_exchange_present": False,
        "phase40_semantic_receipt_present": False,
        "production_gates_approved": 0,
        "production_dispatch_allowed": False,
        "iso_release_allowed": False,
        "iso_bytes_present": False,
    }
    return {**unsigned, "observation_digest": _digest(OBSERVATION_DOMAIN, unsigned)}


def run_negative_matrix() -> dict[str, Any]:
    contract = gate1_execution_contract()
    rejected = 0
    for name in NEGATIVE_CASES:
        value = json.loads(canonical_json_bytes(contract))
        if name == "extra-contract-field":
            value["unexpected"] = True
        elif name == "ceremony-contract-drift":
            value["phase41_ceremony_contract_digest"] = "1" * 64
        elif name == "phase40-owner-contract-drift":
            value["phase40_owner_contract_digest"] = "2" * 64
        elif name == "phase40-gate1-contract-drift":
            value["phase40_gate1_contract_digest"] = "3" * 64
        elif name == "phase39-contract-drift":
            value["phase39_contract_digest"] = "4" * 64
        elif name == "gate-name-drift":
            value["gate_name"] = phase39.GATE_NAMES[1]
        elif name == "ceremony-active-optional":
            value["decision_policy"]["active_ceremony_required"] = False
        elif name == "ceremony-job-authorization-optional":
            value["decision_policy"]["ceremony_gate1_authorization_required"] = False
        elif name == "ceremony-trust-binding-optional":
            value["decision_policy"]["ceremony_trust_state_binding_required"] = False
        elif name == "phase39-dual-signatures-optional":
            value["decision_policy"]["phase39_result_signature_required"] = False
        elif name == "phase39-replay-ledger-optional":
            value["decision_policy"]["phase39_replay_ledger_required"] = False
        elif name == "phase40-semantics-optional":
            value["decision_policy"]["phase40_semantic_receipt_required"] = False
        elif name == "input-closure-authentication-optional":
            value["decision_policy"]["phase40_input_closure_authentication_required"] = False
        elif name == "fixture-can-pass":
            value["decision_policy"]["fixture_can_pass"] = True
        elif name == "quarantine-can-pass":
            value["decision_policy"]["quarantined_ceremony_can_pass"] = True
        elif name == "same-job-different-decision-accepted":
            value["ledger_policy"]["same_job_different_decision_is_equivocation"] = False
        elif name == "stale-job-id-accepted":
            value["ledger_policy"]["monotonic_job_id_required"] = False
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
            parse_gate1_execution_contract(value)
        except PolicyError:
            rejected += 1
        else:  # pragma: no cover
            raise AssertionError(f"Phase 41 negative case accepted: {name}")
    return {
        "format": "securityops-phase41-gate1-negative-results/1",
        "cases": list(NEGATIVE_CASES),
        "rejected": rejected,
        "total": len(NEGATIVE_CASES),
        "all_rejected": rejected == len(NEGATIVE_CASES),
        "production_gates_approved": 0,
        "production_dispatch_allowed": False,
        "iso_release_allowed": False,
    }


def phase41_gate1_selftest() -> dict[str, Any]:
    parse_gate1_execution_contract(gate1_execution_contract())
    parse_decision_ledger(empty_decision_ledger())
    negatives = run_negative_matrix()
    observation = blocked_gate1_observation()
    unsigned = {
        "format": "securityops-phase41-gate1-selftest/1",
        "status": STATUS,
        "contract_digest": gate1_execution_contract_digest(),
        "decision_schema_sha256": hashlib.sha256(
            canonical_json_bytes(decision_schema())).hexdigest(),
        "ledger_schema_sha256": hashlib.sha256(
            canonical_json_bytes(ledger_schema())).hexdigest(),
        "negative_cases_rejected": negatives["rejected"],
        "negative_cases_total": negatives["total"],
        "blocked_observation_digest": observation["observation_digest"],
        "production_gates_approved": 0,
        "production_dispatch_allowed": False,
        "iso_release_allowed": False,
    }
    return {**unsigned, "selftest_digest": hashlib.sha256(
        b"SECURITYOPS-PHASE41-GATE1-SELFTEST-V1\x00"
        + canonical_json_bytes(unsigned)).hexdigest()}
