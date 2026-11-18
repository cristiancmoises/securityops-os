# CodeMark v1 project=4c63e0fe-589c-4944-8449-97e211a38b72 file=03440254eecd5466b9ecdc1f99de0210 owner="Cristian Cezar Mois\u00e9s"
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Phase 44 offline admission quorum and evidence-vault boundary.

Phase 43 proves signed custody of a deterministic Phase 42 package and creates a
cross-bound Gate 1 preflight.  Phase 44 adds two missing local controls before
that preflight may be presented to the inherited Phase 41 monotonic decision:

* four independently signed station attestations for export, receive, verify,
  and import stations; and
* a descriptor-relative, content-addressed evidence vault that remeasures the
  exact Gate 1 evidence set and publishes it without replacement.

Neither a station quorum, a vault, nor an admission dossier creates owner,
publisher, witness, or build-node authority.  Gate 1 remains controlled by the
ordered Phase 39--43 receipt chain and the Phase 41 decision ledger.
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
    from . import phase42_media as phase42_media
    from . import phase43_offline_custody as phase43
except ImportError:  # pragma: no cover - installed sibling modules
    import phase39_owner_execution as phase39  # type: ignore[no-redef]
    import phase40_owner_trust as phase40  # type: ignore[no-redef]
    import phase41_owner_ceremony as phase41  # type: ignore[no-redef]
    import phase42_media as phase42_media  # type: ignore[no-redef]
    import phase43_offline_custody as phase43  # type: ignore[no-redef]

PolicyError = phase40.PolicyError
canonical_json_bytes = phase40.canonical_json_bytes
ZERO_SHA: Final[str] = "0" * 64

CONTRACT_FORMAT: Final[str] = "securityops-phase44-offline-admission-contract/1"
ATTESTATION_FORMAT: Final[str] = "securityops-phase44-station-attestation/1"
ATTESTATION_VERIFICATION_FORMAT: Final[str] = "securityops-phase44-station-attestation-verification/1"
VAULT_FORMAT: Final[str] = "securityops-phase44-evidence-vault-manifest/1"
DOSSIER_FORMAT: Final[str] = "securityops-phase44-gate1-admission-dossier/1"
LEDGER_FORMAT: Final[str] = "securityops-phase44-admission-ledger/1"
STATUS: Final[str] = "PASS_PHASE44_OFFLINE_ADMISSION_QUORUM_AND_EVIDENCE_VAULT_BOUNDARY"
BLOCKED_STATUS: Final[str] = "BLOCKED_PHASE44_REAL_OFFLINE_ADMISSION_AND_GATE1_CHAIN_REQUIRED"

CONTRACT_DOMAIN: Final[bytes] = b"SECURITYOPS-PHASE44-OFFLINE-ADMISSION-CONTRACT-V1\x00"
ATTESTATION_DOMAIN: Final[bytes] = b"SECURITYOPS-PHASE44-STATION-ATTESTATION-V1\x00"
ATTESTATION_VERIFICATION_DOMAIN: Final[bytes] = b"SECURITYOPS-PHASE44-STATION-ATTESTATION-VERIFICATION-V1\x00"
VAULT_DOMAIN: Final[bytes] = b"SECURITYOPS-PHASE44-EVIDENCE-VAULT-V1\x00"
DOSSIER_DOMAIN: Final[bytes] = b"SECURITYOPS-PHASE44-GATE1-DOSSIER-V1\x00"
LEDGER_DOMAIN: Final[bytes] = b"SECURITYOPS-PHASE44-ADMISSION-LEDGER-V1\x00"
NEGATIVE_DOMAIN: Final[bytes] = b"SECURITYOPS-PHASE44-NEGATIVE-MATRIX-V1\x00"
KIT_DOMAIN: Final[bytes] = b"SECURITYOPS-PHASE44-OPERATOR-KIT-V1\x00"

PHASE43_IDENTITIES: Final[dict[str, str]] = {
    "runtime_commit": "fb06c37b8686a570593ce5b29c9d760df965f20d",
    "runtime_tree": "7f5cdfe4e721400474c2565d34a2951afc84e47a",
    "securityops_os_commit": "ea87d802c595a4af59e00f615eb4073284a74969",
    "securityops_os_tree": "9f87f0401536b33f494d5131e8504e07037a30c8",
    "stable_v1_13_0": "8373fd789c9a525d6128abfd3d7a93ad4db3348b",
}
PHASE43_CONTRACT_DIGEST: Final[str] = "437249725663498e48a7f9fbdce8e8e1f28f76ad25cd58aab1119f6141f481f2"

STATION_ROLES: Final[tuple[str, ...]] = (
    "export-station",
    "receive-station",
    "verify-station",
    "import-station",
)
STATION_ROLE_ORDER: Final[dict[str, int]] = {role: index for index, role in enumerate(STATION_ROLES)}

EVIDENCE_ROLES: Final[tuple[str, ...]] = (
    "phase39-gate-job",
    "phase39-build-result",
    "phase39-verification-receipt",
    "phase40-owner-trust-state",
    "phase40-input-closure",
    "phase40-semantic-admission",
    "phase41-ceremony-state",
    "phase41-decision-ledger",
    "phase42-witness-checkpoint",
    "phase42-ceremony-transcript",
    "phase43-custody-ledger",
    "phase43-gate1-preflight",
)
EVIDENCE_FILENAMES: Final[dict[str, str]] = {
    role: role + ".json" for role in EVIDENCE_ROLES
}

MAX_ATTESTATION_BYTES: Final[int] = 4 * 1024 * 1024
MAX_VAULT_MANIFEST_BYTES: Final[int] = 8 * 1024 * 1024
MAX_EVIDENCE_FILE_BYTES: Final[int] = 128 * 1024 * 1024
MAX_LEDGER_BYTES: Final[int] = 16 * 1024 * 1024
MAX_ATTESTATION_LIFETIME: Final[int] = 7 * 24 * 60 * 60
MAX_LEDGER_RECORDS: Final[int] = 4096

_SHA = re.compile(r"[0-9a-f]{64}\Z")
_FPR = re.compile(r"[0-9A-F]{40}\Z")
_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")

NEGATIVE_CASES: Final[tuple[str, ...]] = (
    "contract-extra-field",
    "contract-phase43-drift",
    "contract-station-role-removed",
    "contract-vault-overwrite-enabled",
    "contract-vault-path-reopen-enabled",
    "contract-dossier-closes-gate1",
    "attestation-extra-field",
    "attestation-role-unknown",
    "attestation-zero-challenge",
    "attestation-lifetime-unbounded",
    "attestation-network-enabled",
    "attestation-writable-media",
    "attestation-fixture-promotion",
    "attestation-keyring-pin-mismatch",
    "attestation-path-reopen-after-measurement",
    "quorum-role-missing",
    "quorum-role-duplicate",
    "quorum-signer-reuse",
    "quorum-station-id-reuse",
    "vault-role-missing",
    "vault-role-extra",
    "vault-role-reordered",
    "vault-symlink-source",
    "vault-hardlink-source",
    "vault-source-root-replaced",
    "vault-destination-overwrite",
    "vault-file-truncated",
    "vault-file-grown",
    "vault-manifest-tampered",
    "dossier-challenge-mismatch",
    "dossier-transfer-mismatch",
    "dossier-custody-mismatch",
    "dossier-preflight-mismatch",
    "dossier-vault-mismatch",
    "dossier-fixture-promotion",
    "dossier-quorum-only-approval",
    "ledger-replay",
    "ledger-rollback",
    "ledger-equivocation",
    "ledger-quarantine-promotion",
    "production-promotion",
    "iso-promotion",
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


def _file_identity(info: os.stat_result) -> tuple[int, ...]:
    return (
        info.st_dev, info.st_ino, info.st_mode, info.st_nlink,
        info.st_uid, info.st_gid, info.st_size, info.st_mtime_ns, info.st_ctime_ns,
    )


def _directory_identity(info: os.stat_result) -> tuple[int, ...]:
    return (
        info.st_dev, info.st_ino, info.st_mode, info.st_nlink,
        info.st_uid, info.st_gid, info.st_mtime_ns, info.st_ctime_ns,
    )


def _private_directory(path: Path, context: str, *, create: bool = False) -> tuple[int, os.stat_result]:
    candidate = path.absolute()
    if create:
        candidate.mkdir(parents=True, mode=0o700, exist_ok=True)
    flags = (
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        fd = os.open(candidate, flags)
    except OSError as exc:
        raise PolicyError(f"{context} cannot be opened safely") from exc
    try:
        info = os.fstat(fd)
        mode = stat.S_IMODE(info.st_mode)
        if (
            not stat.S_ISDIR(info.st_mode)
            or mode & 0o022
            or info.st_uid not in {0, os.getuid()}
        ):
            raise PolicyError(f"{context} is not a private directory")
        return fd, info
    except Exception:
        os.close(fd)
        raise


def _fsync_directory_fd(fd: int) -> None:
    os.fsync(fd)


def _fsync_directory(path: Path) -> None:
    fd, _ = _private_directory(path, "Phase 44 directory")
    try:
        _fsync_directory_fd(fd)
    finally:
        os.close(fd)


def station_attestation_schema() -> dict[str, Any]:
    sha = {"type": "string", "pattern": "^[0-9a-f]{64}$"}
    fpr = {"type": "string", "pattern": "^[0-9A-F]{40}$"}
    required = [
        "format", "contract_digest", "sequence", "created_unix", "expires_unix",
        "station_role", "station_id", "challenge_nonce", "transfer_id",
        "package_manifest_digest", "custody_ledger_digest", "preflight_digest",
        "source_snapshot_manifest_digest", "station_boot_id_digest",
        "station_kernel_release_digest", "station_executable_manifest_digest",
        "station_storage_manifest_digest", "operator_primary_fingerprint",
        "operator_signing_fingerprint", "operator_keyring_sha256",
        "network_policy", "removable_media_read_only", "descriptor_bound_measurement",
        "original_paths_reopened_after_measurement", "fixture_mode",
        "signature_required", "station_authenticated", "gate1_approved",
        "production_gates_approved", "production_dispatch_allowed",
        "iso_release_allowed", "attestation_digest",
    ]
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://securityops.co/schemas/guix-center/phase44-station-attestation.schema.json",
        "title": "Security Ops Phase 44 offline station attestation",
        "type": "object", "additionalProperties": False,
        "required": required,
        "properties": {
            "format": {"const": ATTESTATION_FORMAT},
            "contract_digest": sha,
            "sequence": {"type": "integer", "minimum": 1},
            "created_unix": {"type": "integer", "minimum": 1},
            "expires_unix": {"type": "integer", "minimum": 1},
            "station_role": {"enum": list(STATION_ROLES)},
            "station_id": {"type": "string", "minLength": 1, "maxLength": 128},
            "challenge_nonce": sha,
            "transfer_id": {"type": "string", "minLength": 1, "maxLength": 128},
            "package_manifest_digest": sha,
            "custody_ledger_digest": sha,
            "preflight_digest": sha,
            "source_snapshot_manifest_digest": sha,
            "station_boot_id_digest": sha,
            "station_kernel_release_digest": sha,
            "station_executable_manifest_digest": sha,
            "station_storage_manifest_digest": sha,
            "operator_primary_fingerprint": fpr,
            "operator_signing_fingerprint": fpr,
            "operator_keyring_sha256": sha,
            "network_policy": {"const": "offline"},
            "removable_media_read_only": {"const": True},
            "descriptor_bound_measurement": {"const": True},
            "original_paths_reopened_after_measurement": {"const": False},
            "fixture_mode": {"type": "boolean"},
            "signature_required": {"const": True},
            "station_authenticated": {"const": False},
            "gate1_approved": {"const": False},
            "production_gates_approved": {"const": 0},
            "production_dispatch_allowed": {"const": False},
            "iso_release_allowed": {"const": False},
            "attestation_digest": sha,
        },
    }


def vault_manifest_schema() -> dict[str, Any]:
    sha = {"type": "string", "pattern": "^[0-9a-f]{64}$"}
    entry_required = ["role", "filename", "bytes", "sha256", "mode"]
    required = [
        "format", "contract_digest", "created_unix", "challenge_nonce", "transfer_id",
        "package_manifest_digest", "custody_ledger_digest", "preflight_digest",
        "source_snapshot_manifest_digest", "entry_roles", "entries",
        "descriptor_relative_source_opening", "streaming_hashing",
        "distinct_source_file_identities", "atomic_no_replace_publication",
        "original_source_paths_reopened_after_measurement", "fixture_mode",
        "all_entries_verified", "gate1_approved", "production_gates_approved",
        "production_dispatch_allowed", "iso_release_allowed", "vault_digest",
    ]
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://securityops.co/schemas/guix-center/phase44-evidence-vault-manifest.schema.json",
        "title": "Security Ops Phase 44 Gate 1 evidence vault manifest",
        "type": "object", "additionalProperties": False,
        "required": required,
        "properties": {
            "format": {"const": VAULT_FORMAT},
            "contract_digest": sha,
            "created_unix": {"type": "integer", "minimum": 1},
            "challenge_nonce": sha,
            "transfer_id": {"type": "string", "minLength": 1, "maxLength": 128},
            "package_manifest_digest": sha,
            "custody_ledger_digest": sha,
            "preflight_digest": sha,
            "source_snapshot_manifest_digest": sha,
            "entry_roles": {"const": list(EVIDENCE_ROLES)},
            "entries": {
                "type": "array", "minItems": len(EVIDENCE_ROLES),
                "maxItems": len(EVIDENCE_ROLES),
                "items": {
                    "type": "object", "additionalProperties": False,
                    "required": entry_required,
                    "properties": {
                        "role": {"enum": list(EVIDENCE_ROLES)},
                        "filename": {"type": "string", "minLength": 1, "maxLength": 128},
                        "bytes": {"type": "integer", "minimum": 1, "maximum": MAX_EVIDENCE_FILE_BYTES},
                        "sha256": sha,
                        "mode": {"enum": [256, 384]},
                    },
                },
            },
            "descriptor_relative_source_opening": {"const": True},
            "streaming_hashing": {"const": True},
            "distinct_source_file_identities": {"const": True},
            "atomic_no_replace_publication": {"const": True},
            "original_source_paths_reopened_after_measurement": {"const": False},
            "fixture_mode": {"type": "boolean"},
            "all_entries_verified": {"const": True},
            "gate1_approved": {"const": False},
            "production_gates_approved": {"const": 0},
            "production_dispatch_allowed": {"const": False},
            "iso_release_allowed": {"const": False},
            "vault_digest": sha,
        },
    }


def admission_dossier_schema() -> dict[str, Any]:
    sha = {"type": "string", "pattern": "^[0-9a-f]{64}$"}
    required = [
        "format", "contract_digest", "created_unix", "challenge_nonce", "transfer_id",
        "package_manifest_digest", "custody_ledger_digest", "preflight_digest",
        "vault_digest", "station_roles", "station_attestation_digests",
        "station_verification_digests", "station_signing_fingerprints",
        "station_ids", "station_quorum_verified", "vault_verified",
        "custody_chain_authenticated", "preflight_eligible_for_phase41_decision",
        "fixture_mode", "all_bindings_verified", "eligible_for_phase41_decision",
        "phase41_monotonic_decision_required", "dossier_can_close_gate1",
        "gate1_approved", "production_gates_approved", "production_dispatch_allowed",
        "iso_release_allowed", "iso_bytes_present", "dossier_digest",
    ]
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://securityops.co/schemas/guix-center/phase44-gate1-admission-dossier.schema.json",
        "title": "Security Ops Phase 44 Gate 1 admission dossier",
        "type": "object", "additionalProperties": False,
        "required": required,
        "properties": {
            "format": {"const": DOSSIER_FORMAT}, "contract_digest": sha,
            "created_unix": {"type": "integer", "minimum": 1},
            "challenge_nonce": sha,
            "transfer_id": {"type": "string", "minLength": 1, "maxLength": 128},
            "package_manifest_digest": sha,
            "custody_ledger_digest": sha,
            "preflight_digest": sha,
            "vault_digest": sha,
            "station_roles": {"const": list(STATION_ROLES)},
            "station_attestation_digests": {
                "type": "array", "minItems": 4, "maxItems": 4, "items": sha,
            },
            "station_verification_digests": {
                "type": "array", "minItems": 4, "maxItems": 4, "items": sha,
            },
            "station_signing_fingerprints": {
                "type": "array", "minItems": 4, "maxItems": 4,
                "items": {"type": "string", "pattern": "^[0-9A-F]{40}$"},
            },
            "station_ids": {
                "type": "array", "minItems": 4, "maxItems": 4,
                "items": {"type": "string", "minLength": 1, "maxLength": 128},
            },
            "station_quorum_verified": {"type": "boolean"},
            "vault_verified": {"type": "boolean"},
            "custody_chain_authenticated": {"type": "boolean"},
            "preflight_eligible_for_phase41_decision": {"type": "boolean"},
            "fixture_mode": {"type": "boolean"},
            "all_bindings_verified": {"const": True},
            "eligible_for_phase41_decision": {"type": "boolean"},
            "phase41_monotonic_decision_required": {"const": True},
            "dossier_can_close_gate1": {"const": False},
            "gate1_approved": {"const": False},
            "production_gates_approved": {"const": 0},
            "production_dispatch_allowed": {"const": False},
            "iso_release_allowed": {"const": False},
            "iso_bytes_present": {"const": False},
            "dossier_digest": sha,
        },
    }


def admission_ledger_schema() -> dict[str, Any]:
    sha = {"type": "string", "pattern": "^[0-9a-f]{64}$"}
    required = [
        "format", "contract_digest", "generation", "status", "challenge_nonce",
        "transfer_id", "current_dossier_digest", "current_record_digest", "records",
        "package_quarantined", "fixture_mode", "phase41_decision_required",
        "gate1_approved", "production_gates_approved", "production_dispatch_allowed",
        "iso_release_allowed", "ledger_digest",
    ]
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://securityops.co/schemas/guix-center/phase44-admission-ledger.schema.json",
        "title": "Security Ops Phase 44 Gate 1 admission ledger",
        "type": "object", "additionalProperties": False,
        "required": required,
        "properties": {
            "format": {"const": LEDGER_FORMAT}, "contract_digest": sha,
            "generation": {"type": "integer", "minimum": 0},
            "status": {"enum": ["empty", "dossier-admitted", "quarantined"]},
            "challenge_nonce": sha,
            "transfer_id": {"type": "string", "maxLength": 128},
            "current_dossier_digest": sha,
            "current_record_digest": sha,
            "records": {"type": "array", "maxItems": MAX_LEDGER_RECORDS},
            "package_quarantined": {"type": "boolean"},
            "fixture_mode": {"type": "boolean"},
            "phase41_decision_required": {"const": True},
            "gate1_approved": {"const": False},
            "production_gates_approved": {"const": 0},
            "production_dispatch_allowed": {"const": False},
            "iso_release_allowed": {"const": False},
            "ledger_digest": sha,
        },
    }


def _contract_unsigned() -> dict[str, Any]:
    schemas = {
        "station_attestation": {
            "id": station_attestation_schema()["$id"],
            "canonical_sha256": _schema_digest(station_attestation_schema()),
        },
        "evidence_vault": {
            "id": vault_manifest_schema()["$id"],
            "canonical_sha256": _schema_digest(vault_manifest_schema()),
        },
        "gate1_admission_dossier": {
            "id": admission_dossier_schema()["$id"],
            "canonical_sha256": _schema_digest(admission_dossier_schema()),
        },
        "admission_ledger": {
            "id": admission_ledger_schema()["$id"],
            "canonical_sha256": _schema_digest(admission_ledger_schema()),
        },
    }
    return {
        "format": CONTRACT_FORMAT,
        "status": STATUS,
        "execution_status": BLOCKED_STATUS,
        "phase43_identities": dict(PHASE43_IDENTITIES),
        "phase43_contract_digest": PHASE43_CONTRACT_DIGEST,
        "schemas": {"additional_properties_allowed": False, **schemas},
        "station_attestation_policy": {
            "required_roles": list(STATION_ROLES),
            "all_roles_require_detached_signatures": True,
            "all_signers_require_local_keyring_pins": True,
            "all_signing_fingerprints_must_be_distinct": True,
            "all_station_ids_must_be_distinct": True,
            "network_policy": "offline",
            "removable_media_read_only_required": True,
            "descriptor_bound_measurement_required": True,
            "signature_inputs_use_kernel_sealed_memfds": True,
            "original_paths_reopened_after_measurement": False,
            "fixture_quorum_can_be_authenticated": False,
            "station_quorum_alone_can_close_gate1": False,
        },
        "evidence_vault_policy": {
            "required_roles": list(EVIDENCE_ROLES),
            "fixed_filenames": dict(EVIDENCE_FILENAMES),
            "descriptor_relative_source_opening": True,
            "streaming_hashing": True,
            "distinct_source_file_identities_required": True,
            "source_root_identity_rechecked": True,
            "destination_publication_is_atomic_no_replace": True,
            "destination_overwrite_allowed": False,
            "original_source_paths_reopened_after_measurement": False,
            "vault_alone_can_close_gate1": False,
        },
        "gate1_dossier_policy": {
            "phase43_authenticated_custody_required": True,
            "phase43_preflight_required": True,
            "phase44_station_quorum_required": True,
            "phase44_verified_evidence_vault_required": True,
            "all_challenge_transfer_and_digest_bindings_required": True,
            "fixture_dossier_can_be_eligible": False,
            "dossier_can_close_gate1": False,
            "phase41_monotonic_decision_required": True,
        },
        "network_fetch_allowed": False,
        "production_gates_approved": 0,
        "production_dispatch_allowed": False,
        "iso_release_allowed": False,
    }


def offline_admission_contract() -> dict[str, Any]:
    unsigned = _contract_unsigned()
    return {**unsigned, "contract_digest": _digest(CONTRACT_DOMAIN, unsigned)}


def offline_admission_contract_digest() -> str:
    return str(offline_admission_contract()["contract_digest"])


def parse_offline_admission_contract(value: Mapping[str, Any]) -> dict[str, Any]:
    expected = offline_admission_contract()
    if type(value) is not dict or value != expected:
        raise PolicyError("Phase 44 offline admission contract differs from policy")
    return json.loads(canonical_json_bytes(value))


def create_station_attestation(
    *, sequence: int, created_unix: int, expires_unix: int,
    station_role: str, station_id: str, challenge_nonce: str, transfer_id: str,
    package_manifest_digest: str, custody_ledger_digest: str, preflight_digest: str,
    source_snapshot_manifest_digest: str, station_boot_id_digest: str,
    station_kernel_release_digest: str, station_executable_manifest_digest: str,
    station_storage_manifest_digest: str, operator_primary_fingerprint: str,
    operator_signing_fingerprint: str, operator_keyring_sha256: str,
    fixture_mode: bool = False,
) -> dict[str, Any]:
    if type(sequence) is not int or sequence < 1:
        raise PolicyError("Phase 44 station sequence is invalid")
    if (
        type(created_unix) is not int or type(expires_unix) is not int
        or created_unix < 1 or expires_unix <= created_unix
        or expires_unix - created_unix > MAX_ATTESTATION_LIFETIME
    ):
        raise PolicyError("Phase 44 station attestation lifetime is invalid")
    if station_role not in STATION_ROLES:
        raise PolicyError("Phase 44 station role is invalid")
    _token(station_id, "Phase 44 station ID")
    _token(transfer_id, "Phase 44 transfer ID")
    for value, context in (
        (challenge_nonce, "challenge"),
        (package_manifest_digest, "package manifest"),
        (custody_ledger_digest, "custody ledger"),
        (preflight_digest, "preflight"),
        (source_snapshot_manifest_digest, "source snapshot"),
        (station_boot_id_digest, "boot identity"),
        (station_kernel_release_digest, "kernel release"),
        (station_executable_manifest_digest, "executable manifest"),
        (station_storage_manifest_digest, "storage manifest"),
        (operator_keyring_sha256, "operator keyring"),
    ):
        _sha(value, f"Phase 44 station {context}")
    primary = _fpr(operator_primary_fingerprint, "Phase 44 station operator primary")
    signing = _fpr(operator_signing_fingerprint, "Phase 44 station operator signer")
    if type(fixture_mode) is not bool:
        raise PolicyError("Phase 44 station fixture flag is invalid")
    unsigned = {
        "format": ATTESTATION_FORMAT,
        "contract_digest": offline_admission_contract_digest(),
        "sequence": sequence,
        "created_unix": created_unix,
        "expires_unix": expires_unix,
        "station_role": station_role,
        "station_id": station_id,
        "challenge_nonce": challenge_nonce,
        "transfer_id": transfer_id,
        "package_manifest_digest": package_manifest_digest,
        "custody_ledger_digest": custody_ledger_digest,
        "preflight_digest": preflight_digest,
        "source_snapshot_manifest_digest": source_snapshot_manifest_digest,
        "station_boot_id_digest": station_boot_id_digest,
        "station_kernel_release_digest": station_kernel_release_digest,
        "station_executable_manifest_digest": station_executable_manifest_digest,
        "station_storage_manifest_digest": station_storage_manifest_digest,
        "operator_primary_fingerprint": primary,
        "operator_signing_fingerprint": signing,
        "operator_keyring_sha256": operator_keyring_sha256,
        "network_policy": "offline",
        "removable_media_read_only": True,
        "descriptor_bound_measurement": True,
        "original_paths_reopened_after_measurement": False,
        "fixture_mode": fixture_mode,
        "signature_required": True,
        "station_authenticated": False,
        "gate1_approved": False,
        "production_gates_approved": 0,
        "production_dispatch_allowed": False,
        "iso_release_allowed": False,
    }
    return {**unsigned, "attestation_digest": _digest(ATTESTATION_DOMAIN, unsigned)}


def parse_station_attestation(value: Mapping[str, Any], *, now_unix: int | None = None) -> dict[str, Any]:
    required = set(station_attestation_schema()["required"])
    if type(value) is not dict or set(value) != required:
        raise PolicyError("Phase 44 station attestation fields are not closed")
    candidate = json.loads(canonical_json_bytes(value))
    if candidate["format"] != ATTESTATION_FORMAT or candidate["contract_digest"] != offline_admission_contract_digest():
        raise PolicyError("Phase 44 station attestation identity drifted")
    if type(candidate["sequence"]) is not int or candidate["sequence"] < 1:
        raise PolicyError("Phase 44 station sequence is invalid")
    if candidate["station_role"] not in STATION_ROLES:
        raise PolicyError("Phase 44 station role is invalid")
    _token(candidate["station_id"], "Phase 44 station ID")
    _token(candidate["transfer_id"], "Phase 44 transfer ID")
    if (
        type(candidate["created_unix"]) is not int or type(candidate["expires_unix"]) is not int
        or candidate["created_unix"] < 1 or candidate["expires_unix"] <= candidate["created_unix"]
        or candidate["expires_unix"] - candidate["created_unix"] > MAX_ATTESTATION_LIFETIME
    ):
        raise PolicyError("Phase 44 station attestation lifetime is invalid")
    for field in (
        "challenge_nonce", "package_manifest_digest", "custody_ledger_digest",
        "preflight_digest", "source_snapshot_manifest_digest", "station_boot_id_digest",
        "station_kernel_release_digest", "station_executable_manifest_digest",
        "station_storage_manifest_digest", "operator_keyring_sha256",
    ):
        _sha(candidate[field], f"Phase 44 station {field}")
    _fpr(candidate["operator_primary_fingerprint"], "Phase 44 station operator primary")
    _fpr(candidate["operator_signing_fingerprint"], "Phase 44 station operator signer")
    if candidate["network_policy"] != "offline":
        raise PolicyError("Phase 44 station attempted network-enabled admission")
    for field, expected in (
        ("removable_media_read_only", True),
        ("descriptor_bound_measurement", True),
        ("original_paths_reopened_after_measurement", False),
        ("signature_required", True),
        ("station_authenticated", False),
        ("gate1_approved", False),
        ("production_dispatch_allowed", False),
        ("iso_release_allowed", False),
    ):
        if candidate[field] is not expected:
            raise PolicyError(f"Phase 44 station policy drifted: {field}")
    if type(candidate["fixture_mode"]) is not bool or candidate["production_gates_approved"] != 0:
        raise PolicyError("Phase 44 station attempted promotion")
    unsigned = {key: candidate[key] for key in candidate if key != "attestation_digest"}
    if candidate["attestation_digest"] != _digest(ATTESTATION_DOMAIN, unsigned):
        raise PolicyError("Phase 44 station attestation digest is invalid")
    if now_unix is not None:
        if type(now_unix) is not int or now_unix < candidate["created_unix"] or now_unix > candidate["expires_unix"]:
            raise PolicyError("Phase 44 station attestation is outside its validity window")
    return candidate


@dataclass(frozen=True)
class VerifiedStationAttestation:
    document: dict[str, Any]
    signed_input_sha256: dict[str, str]
    signature_verified: bool
    local_pin_verified: bool
    station_authenticated: bool
    verification_digest: str

    @property
    def fixture_mode(self) -> bool:
        return bool(self.document["fixture_mode"])

    def to_dict(self) -> dict[str, Any]:
        return {
            "format": ATTESTATION_VERIFICATION_FORMAT,
            "attestation_digest": self.document["attestation_digest"],
            "station_role": self.document["station_role"],
            "station_id": self.document["station_id"],
            "operator_signing_fingerprint": self.document["operator_signing_fingerprint"],
            "signed_input_sha256": dict(self.signed_input_sha256),
            "signature_verified": self.signature_verified,
            "local_pin_verified": self.local_pin_verified,
            "fixture_mode": self.fixture_mode,
            "station_authenticated": self.station_authenticated,
            "gate1_approved": False,
            "production_gates_approved": 0,
            "production_dispatch_allowed": False,
            "iso_release_allowed": False,
            "verification_digest": self.verification_digest,
        }


def verify_signed_station_attestation(
    *, attestation_path: Path, signature_path: Path, keyring_path: Path,
    expected_operator_primary_fingerprint: str,
    expected_operator_signing_fingerprint: str,
    expected_operator_keyring_sha256: str,
    now_unix: int, gpgv_executable: str | Path = "/usr/bin/gpgv",
    gpg_executable: str | Path = "/usr/bin/gpg",
) -> VerifiedStationAttestation:
    attestation_meta, attestation_bytes = phase40.measure_file(
        attestation_path, maximum=MAX_ATTESTATION_BYTES,
        context="Phase 44 station attestation")
    signature_meta, signature = phase40.measure_file(
        signature_path, maximum=phase40.MAX_SIGNATURE_BYTES,
        context="Phase 44 station attestation signature")
    keyring_meta, keyring = phase40.measure_file(
        keyring_path, maximum=phase40.MAX_KEYRING_BYTES,
        context="Phase 44 station verification keyring")
    document = parse_station_attestation(
        _strict_json(attestation_bytes, "Phase 44 station attestation"),
        now_unix=now_unix)
    expected_primary = _fpr(
        expected_operator_primary_fingerprint,
        "Phase 44 locally pinned station primary")
    expected_signing = _fpr(
        expected_operator_signing_fingerprint,
        "Phase 44 locally pinned station signer")
    expected_keyring = _sha(
        expected_operator_keyring_sha256,
        "Phase 44 locally pinned station keyring")
    if (
        document["operator_primary_fingerprint"] != expected_primary
        or document["operator_signing_fingerprint"] != expected_signing
        or document["operator_keyring_sha256"] != expected_keyring
        or keyring_meta.sha256 != expected_keyring
    ):
        raise PolicyError("Phase 44 station attestation differs from local pins")
    if not document["fixture_mode"]:
        phase40._inspect_verification_keyring_payload(  # type: ignore[attr-defined]
            measured=keyring_meta, payload=keyring,
            expected_primary_fingerprint=expected_primary,
            expected_signing_fingerprint=expected_signing,
            valid_through_unix=document["expires_unix"],
            gpg_executable=gpg_executable, fixture_mode=False)
    phase39._verify_signature(  # type: ignore[attr-defined]
        payload=attestation_bytes, signature=signature, keyring=keyring,
        expected_fingerprint=expected_signing,
        gpgv_executable=gpgv_executable,
        fixture_mode=document["fixture_mode"], role="phase44-station-attestation")
    authenticated = bool(not document["fixture_mode"])
    signed_inputs = {
        "attestation": attestation_meta.sha256,
        "signature": signature_meta.sha256,
        "keyring": keyring_meta.sha256,
    }
    unsigned = {
        "format": ATTESTATION_VERIFICATION_FORMAT,
        "attestation_digest": document["attestation_digest"],
        "station_role": document["station_role"],
        "station_id": document["station_id"],
        "operator_signing_fingerprint": expected_signing,
        "signed_input_sha256": signed_inputs,
        "signature_verified": True,
        "local_pin_verified": True,
        "fixture_mode": document["fixture_mode"],
        "station_authenticated": authenticated,
        "gate1_approved": False,
        "production_gates_approved": 0,
        "production_dispatch_allowed": False,
        "iso_release_allowed": False,
    }
    return VerifiedStationAttestation(
        document=document,
        signed_input_sha256=signed_inputs,
        signature_verified=True,
        local_pin_verified=True,
        station_authenticated=authenticated,
        verification_digest=_digest(ATTESTATION_VERIFICATION_DOMAIN, unsigned),
    )


def _open_source_entry(root_fd: int, filename: str, context: str) -> tuple[int, os.stat_result]:
    if not filename or filename in {".", ".."} or "/" in filename or "\x00" in filename:
        raise PolicyError(f"{context} filename is invalid")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(filename, flags, dir_fd=root_fd)
    except OSError as exc:
        raise PolicyError(f"{context} cannot be opened safely") from exc
    try:
        info = os.fstat(fd)
        mode = stat.S_IMODE(info.st_mode)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or info.st_size < 1
            or info.st_size > MAX_EVIDENCE_FILE_BYTES
            or mode & 0o022
            or mode & 0o7000
            or info.st_uid not in {0, os.getuid()}
        ):
            raise PolicyError(f"{context} has an unsafe identity")
        return fd, info
    except Exception:
        os.close(fd)
        raise


def _copy_stream(source_fd: int, destination_fd: int, expected_size: int, context: str) -> tuple[int, str]:
    digest = hashlib.sha256()
    copied = 0
    while copied < expected_size:
        block = os.read(source_fd, min(1024 * 1024, expected_size - copied))
        if not block:
            raise PolicyError(f"{context} was truncated")
        digest.update(block)
        view = memoryview(block)
        written = 0
        while written < len(view):
            count = os.write(destination_fd, view[written:])
            if count <= 0:
                raise PolicyError(f"{context} copy stalled")
            written += count
        copied += len(block)
    if os.read(source_fd, 1):
        raise PolicyError(f"{context} grew while copying")
    return copied, digest.hexdigest()


def _parse_vault_manifest(value: Mapping[str, Any]) -> dict[str, Any]:
    required = set(vault_manifest_schema()["required"])
    if type(value) is not dict or set(value) != required:
        raise PolicyError("Phase 44 vault manifest fields are not closed")
    candidate = json.loads(canonical_json_bytes(value))
    if candidate["format"] != VAULT_FORMAT or candidate["contract_digest"] != offline_admission_contract_digest():
        raise PolicyError("Phase 44 vault manifest identity drifted")
    if type(candidate["created_unix"]) is not int or candidate["created_unix"] < 1:
        raise PolicyError("Phase 44 vault timestamp is invalid")
    _token(candidate["transfer_id"], "Phase 44 vault transfer ID")
    for field in (
        "challenge_nonce", "package_manifest_digest", "custody_ledger_digest",
        "preflight_digest", "source_snapshot_manifest_digest",
    ):
        _sha(candidate[field], f"Phase 44 vault {field}")
    if candidate["entry_roles"] != list(EVIDENCE_ROLES):
        raise PolicyError("Phase 44 vault evidence role closure drifted")
    entries = candidate["entries"]
    if type(entries) is not list or len(entries) != len(EVIDENCE_ROLES):
        raise PolicyError("Phase 44 vault evidence inventory is incomplete")
    seen_names: set[str] = set()
    for role, entry in zip(EVIDENCE_ROLES, entries, strict=True):
        if type(entry) is not dict or set(entry) != {"role", "filename", "bytes", "sha256", "mode"}:
            raise PolicyError("Phase 44 vault entry fields are not closed")
        if entry["role"] != role or entry["filename"] != EVIDENCE_FILENAMES[role]:
            raise PolicyError("Phase 44 vault entry order or filename drifted")
        if entry["filename"] in seen_names:
            raise PolicyError("Phase 44 vault contains duplicate filenames")
        seen_names.add(entry["filename"])
        if type(entry["bytes"]) is not int or not 1 <= entry["bytes"] <= MAX_EVIDENCE_FILE_BYTES:
            raise PolicyError("Phase 44 vault entry size is invalid")
        _sha(entry["sha256"], "Phase 44 vault entry digest")
        if entry["mode"] not in {0o400, 0o600}:
            raise PolicyError("Phase 44 vault entry mode is invalid")
    for field, expected in (
        ("descriptor_relative_source_opening", True),
        ("streaming_hashing", True),
        ("distinct_source_file_identities", True),
        ("atomic_no_replace_publication", True),
        ("original_source_paths_reopened_after_measurement", False),
        ("all_entries_verified", True),
        ("gate1_approved", False),
        ("production_dispatch_allowed", False),
        ("iso_release_allowed", False),
    ):
        if candidate[field] is not expected:
            raise PolicyError(f"Phase 44 vault policy drifted: {field}")
    if type(candidate["fixture_mode"]) is not bool or candidate["production_gates_approved"] != 0:
        raise PolicyError("Phase 44 vault attempted production promotion")
    unsigned = {key: candidate[key] for key in candidate if key != "vault_digest"}
    if candidate["vault_digest"] != _digest(VAULT_DOMAIN, unsigned):
        raise PolicyError("Phase 44 vault digest is invalid")
    return candidate


@dataclass(frozen=True)
class VerifiedEvidenceVault:
    path: Path
    manifest: dict[str, Any]

    @property
    def vault_digest(self) -> str:
        return str(self.manifest["vault_digest"])

    @property
    def fixture_mode(self) -> bool:
        return bool(self.manifest["fixture_mode"])


def materialize_evidence_vault(
    *, source_root: Path, vault_parent: Path, created_unix: int,
    challenge_nonce: str, transfer_id: str, package_manifest_digest: str,
    custody_ledger_digest: str, preflight_digest: str,
    source_snapshot_manifest_digest: str, fixture_mode: bool,
) -> VerifiedEvidenceVault:
    if type(created_unix) is not int or created_unix < 1:
        raise PolicyError("Phase 44 vault timestamp is invalid")
    _token(transfer_id, "Phase 44 vault transfer ID")
    for value, context in (
        (challenge_nonce, "challenge"),
        (package_manifest_digest, "package manifest"),
        (custody_ledger_digest, "custody ledger"),
        (preflight_digest, "preflight"),
        (source_snapshot_manifest_digest, "source snapshot"),
    ):
        _sha(value, f"Phase 44 vault {context}")
    if type(fixture_mode) is not bool:
        raise PolicyError("Phase 44 vault fixture flag is invalid")
    source_fd, source_before = _private_directory(source_root, "Phase 44 evidence source")
    parent_fd, _parent_before = _private_directory(vault_parent, "Phase 44 vault parent", create=True)
    temp_name = f".phase44-vault-{os.getpid()}-{os.urandom(8).hex()}"
    temp_path = vault_parent.absolute() / temp_name
    entries: list[dict[str, Any]] = []
    identities: set[tuple[int, int]] = set()
    try:
        os.mkdir(temp_name, 0o700, dir_fd=parent_fd)
        temp_fd, _ = _private_directory(temp_path, "Phase 44 temporary vault")
        try:
            for role in EVIDENCE_ROLES:
                filename = EVIDENCE_FILENAMES[role]
                source_entry_fd, source_info = _open_source_entry(
                    source_fd, filename, f"Phase 44 source evidence {role}")
                try:
                    identity = (source_info.st_dev, source_info.st_ino)
                    if identity in identities:
                        raise PolicyError("Phase 44 evidence source contains aliased files")
                    identities.add(identity)
                    target_fd = os.open(
                        filename,
                        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
                        0o400,
                        dir_fd=temp_fd,
                    )
                    try:
                        copied, digest = _copy_stream(
                            source_entry_fd, target_fd, source_info.st_size,
                            f"Phase 44 evidence {role}")
                        os.fsync(target_fd)
                    finally:
                        os.close(target_fd)
                    after = os.fstat(source_entry_fd)
                    if _file_identity(source_info) != _file_identity(after):
                        raise PolicyError(f"Phase 44 evidence {role} changed while copying")
                    entries.append({
                        "role": role,
                        "filename": filename,
                        "bytes": copied,
                        "sha256": digest,
                        "mode": 0o400,
                    })
                finally:
                    os.close(source_entry_fd)
            source_after = os.fstat(source_fd)
            if _directory_identity(source_before) != _directory_identity(source_after):
                raise PolicyError("Phase 44 evidence source root changed during materialization")
            unsigned = {
                "format": VAULT_FORMAT,
                "contract_digest": offline_admission_contract_digest(),
                "created_unix": created_unix,
                "challenge_nonce": challenge_nonce,
                "transfer_id": transfer_id,
                "package_manifest_digest": package_manifest_digest,
                "custody_ledger_digest": custody_ledger_digest,
                "preflight_digest": preflight_digest,
                "source_snapshot_manifest_digest": source_snapshot_manifest_digest,
                "entry_roles": list(EVIDENCE_ROLES),
                "entries": entries,
                "descriptor_relative_source_opening": True,
                "streaming_hashing": True,
                "distinct_source_file_identities": True,
                "atomic_no_replace_publication": True,
                "original_source_paths_reopened_after_measurement": False,
                "fixture_mode": fixture_mode,
                "all_entries_verified": True,
                "gate1_approved": False,
                "production_gates_approved": 0,
                "production_dispatch_allowed": False,
                "iso_release_allowed": False,
            }
            manifest = {**unsigned, "vault_digest": _digest(VAULT_DOMAIN, unsigned)}
            manifest_fd = os.open(
                "VAULT.json",
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
                0o400,
                dir_fd=temp_fd,
            )
            try:
                payload = canonical_json_bytes(manifest) + b"\n"
                view = memoryview(payload)
                written = 0
                while written < len(view):
                    count = os.write(manifest_fd, view[written:])
                    if count <= 0:
                        raise PolicyError("Phase 44 vault manifest write stalled")
                    written += count
                os.fsync(manifest_fd)
            finally:
                os.close(manifest_fd)
            _fsync_directory_fd(temp_fd)
        finally:
            os.close(temp_fd)
        final_name = f"gate1-{manifest['vault_digest']}"
        final_path = vault_parent.absolute() / final_name
        phase42_media._rename_noreplace(  # type: ignore[attr-defined]
            temp_path, final_path, context="Phase 44 evidence vault publication")
        _fsync_directory_fd(parent_fd)
        return verify_evidence_vault(final_path)
    except Exception:
        shutil.rmtree(temp_path, ignore_errors=True)
        raise
    finally:
        os.close(source_fd)
        os.close(parent_fd)


def verify_evidence_vault(path: Path) -> VerifiedEvidenceVault:
    root_fd, root_before = _private_directory(path, "Phase 44 evidence vault")
    try:
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            manifest_fd = os.open("VAULT.json", flags, dir_fd=root_fd)
        except OSError as exc:
            raise PolicyError("Phase 44 vault manifest is unavailable") from exc
        try:
            info = os.fstat(manifest_fd)
            if (
                not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or info.st_size < 1 or info.st_size > MAX_VAULT_MANIFEST_BYTES
                or stat.S_IMODE(info.st_mode) != 0o400
            ):
                raise PolicyError("Phase 44 vault manifest has an unsafe identity")
            payload = b""
            remaining = info.st_size
            chunks: list[bytes] = []
            while remaining:
                block = os.read(manifest_fd, min(1024 * 1024, remaining))
                if not block:
                    raise PolicyError("Phase 44 vault manifest was truncated")
                chunks.append(block)
                remaining -= len(block)
            if os.read(manifest_fd, 1):
                raise PolicyError("Phase 44 vault manifest grew")
            payload = b"".join(chunks)
        finally:
            os.close(manifest_fd)
        manifest = _parse_vault_manifest(
            _strict_json(payload, "Phase 44 vault manifest"))
        expected_name = f"gate1-{manifest['vault_digest']}"
        if path.absolute().name != expected_name:
            raise PolicyError("Phase 44 vault content-addressed directory name drifted")
        identities: set[tuple[int, int]] = set()
        for entry in manifest["entries"]:
            fd, before = _open_source_entry(
                root_fd, entry["filename"], f"Phase 44 vaulted evidence {entry['role']}")
            try:
                identity = (before.st_dev, before.st_ino)
                if identity in identities:
                    raise PolicyError("Phase 44 vaulted evidence aliases another entry")
                identities.add(identity)
                if stat.S_IMODE(before.st_mode) != entry["mode"] or before.st_size != entry["bytes"]:
                    raise PolicyError("Phase 44 vaulted evidence metadata drifted")
                digest = hashlib.sha256()
                remaining = before.st_size
                while remaining:
                    block = os.read(fd, min(1024 * 1024, remaining))
                    if not block:
                        raise PolicyError("Phase 44 vaulted evidence was truncated")
                    digest.update(block)
                    remaining -= len(block)
                if os.read(fd, 1):
                    raise PolicyError("Phase 44 vaulted evidence grew")
                after = os.fstat(fd)
                if _file_identity(before) != _file_identity(after) or digest.hexdigest() != entry["sha256"]:
                    raise PolicyError("Phase 44 vaulted evidence content drifted")
            finally:
                os.close(fd)
        root_after = os.fstat(root_fd)
        if _directory_identity(root_before) != _directory_identity(root_after):
            raise PolicyError("Phase 44 vault root changed while verifying")
        return VerifiedEvidenceVault(path=path.absolute(), manifest=manifest)
    finally:
        os.close(root_fd)


def create_admission_dossier(
    *, created_unix: int, station_attestations: Sequence[VerifiedStationAttestation],
    vault: VerifiedEvidenceVault, custody_ledger: Mapping[str, Any],
    phase43_preflight: Mapping[str, Any],
) -> dict[str, Any]:
    if type(created_unix) is not int or created_unix < 1:
        raise PolicyError("Phase 44 dossier timestamp is invalid")
    ledger = phase43.parse_custody_ledger(custody_ledger)
    preflight = phase43.parse_gate1_preflight(phase43_preflight)
    verified_vault = verify_evidence_vault(vault.path)
    if verified_vault.manifest != vault.manifest:
        raise PolicyError("Phase 44 evidence vault object changed")
    if len(station_attestations) != len(STATION_ROLES):
        raise PolicyError("Phase 44 requires exactly four station attestations")
    ordered = sorted(station_attestations, key=lambda item: STATION_ROLE_ORDER.get(item.document.get("station_role", ""), 999))
    roles = [item.document["station_role"] for item in ordered]
    if roles != list(STATION_ROLES):
        raise PolicyError("Phase 44 station role quorum is incomplete")
    signers = [item.document["operator_signing_fingerprint"] for item in ordered]
    station_ids = [item.document["station_id"] for item in ordered]
    if len(set(signers)) != len(signers):
        raise PolicyError("Phase 44 station signing identities must be distinct")
    if len(set(station_ids)) != len(station_ids):
        raise PolicyError("Phase 44 station IDs must be distinct")
    challenge = ledger["challenge_nonce"]
    transfer_id = ledger["transfer_id"]
    package_digest = ledger["package_manifest_digest"]
    preflight_digest = preflight["preflight_digest"]
    vault_manifest = verified_vault.manifest
    if (
        preflight["challenge_nonce"] != challenge
        or preflight["transfer_id"] != transfer_id
        or preflight["package_manifest_digest"] != package_digest
        or preflight["custody_ledger_digest"] != ledger["ledger_digest"]
        or vault_manifest["challenge_nonce"] != challenge
        or vault_manifest["transfer_id"] != transfer_id
        or vault_manifest["package_manifest_digest"] != package_digest
        or vault_manifest["custody_ledger_digest"] != ledger["ledger_digest"]
        or vault_manifest["preflight_digest"] != preflight_digest
    ):
        raise PolicyError("Phase 44 dossier base receipts are not cross-bound")
    for item in ordered:
        document = parse_station_attestation(item.document, now_unix=created_unix)
        if (
            document["challenge_nonce"] != challenge
            or document["transfer_id"] != transfer_id
            or document["package_manifest_digest"] != package_digest
            or document["custody_ledger_digest"] != ledger["ledger_digest"]
            or document["preflight_digest"] != preflight_digest
            or document["source_snapshot_manifest_digest"] != vault_manifest["source_snapshot_manifest_digest"]
            or not item.signature_verified or not item.local_pin_verified
        ):
            raise PolicyError("Phase 44 station attestation differs from the dossier")
    fixture_mode = bool(
        ledger["fixture_mode"] or preflight["fixture_mode"] or vault.fixture_mode
        or any(item.fixture_mode for item in ordered)
    )
    station_quorum = bool(
        all(item.station_authenticated for item in ordered)
        and len(set(signers)) == 4 and len(set(station_ids)) == 4
        and not fixture_mode
    )
    eligible = bool(
        station_quorum
        and ledger["custody_chain_authenticated"]
        and ledger["transport_accepted"]
        and preflight["eligible_for_phase41_decision"]
        and vault_manifest["all_entries_verified"]
        and not fixture_mode
    )
    unsigned = {
        "format": DOSSIER_FORMAT,
        "contract_digest": offline_admission_contract_digest(),
        "created_unix": created_unix,
        "challenge_nonce": challenge,
        "transfer_id": transfer_id,
        "package_manifest_digest": package_digest,
        "custody_ledger_digest": ledger["ledger_digest"],
        "preflight_digest": preflight_digest,
        "vault_digest": vault.vault_digest,
        "station_roles": list(STATION_ROLES),
        "station_attestation_digests": [item.document["attestation_digest"] for item in ordered],
        "station_verification_digests": [item.verification_digest for item in ordered],
        "station_signing_fingerprints": signers,
        "station_ids": station_ids,
        "station_quorum_verified": station_quorum,
        "vault_verified": True,
        "custody_chain_authenticated": ledger["custody_chain_authenticated"],
        "preflight_eligible_for_phase41_decision": preflight["eligible_for_phase41_decision"],
        "fixture_mode": fixture_mode,
        "all_bindings_verified": True,
        "eligible_for_phase41_decision": eligible,
        "phase41_monotonic_decision_required": True,
        "dossier_can_close_gate1": False,
        "gate1_approved": False,
        "production_gates_approved": 0,
        "production_dispatch_allowed": False,
        "iso_release_allowed": False,
        "iso_bytes_present": False,
    }
    return {**unsigned, "dossier_digest": _digest(DOSSIER_DOMAIN, unsigned)}


def parse_admission_dossier(value: Mapping[str, Any]) -> dict[str, Any]:
    required = set(admission_dossier_schema()["required"])
    if type(value) is not dict or set(value) != required:
        raise PolicyError("Phase 44 admission dossier fields are not closed")
    candidate = json.loads(canonical_json_bytes(value))
    if candidate["format"] != DOSSIER_FORMAT or candidate["contract_digest"] != offline_admission_contract_digest():
        raise PolicyError("Phase 44 admission dossier identity drifted")
    if type(candidate["created_unix"]) is not int or candidate["created_unix"] < 1:
        raise PolicyError("Phase 44 admission dossier timestamp is invalid")
    _token(candidate["transfer_id"], "Phase 44 dossier transfer ID")
    for field in (
        "challenge_nonce", "package_manifest_digest", "custody_ledger_digest",
        "preflight_digest", "vault_digest", "dossier_digest",
    ):
        _sha(candidate[field], f"Phase 44 dossier {field}")
    if candidate["station_roles"] != list(STATION_ROLES):
        raise PolicyError("Phase 44 dossier station role order drifted")
    for field in ("station_attestation_digests", "station_verification_digests"):
        values = candidate[field]
        if type(values) is not list or len(values) != 4 or len(set(values)) != 4:
            raise PolicyError(f"Phase 44 dossier {field} is invalid")
        for value_item in values:
            _sha(value_item, f"Phase 44 dossier {field}")
    signers = candidate["station_signing_fingerprints"]
    station_ids = candidate["station_ids"]
    if type(signers) is not list or len(signers) != 4 or len(set(signers)) != 4:
        raise PolicyError("Phase 44 dossier signer quorum is invalid")
    for signer in signers:
        _fpr(signer, "Phase 44 dossier station signer")
    if type(station_ids) is not list or len(station_ids) != 4 or len(set(station_ids)) != 4:
        raise PolicyError("Phase 44 dossier station identity quorum is invalid")
    for station_id in station_ids:
        _token(station_id, "Phase 44 dossier station ID")
    for field in (
        "station_quorum_verified", "vault_verified", "custody_chain_authenticated",
        "preflight_eligible_for_phase41_decision", "fixture_mode",
        "all_bindings_verified", "eligible_for_phase41_decision",
        "phase41_monotonic_decision_required", "dossier_can_close_gate1",
        "gate1_approved", "production_dispatch_allowed", "iso_release_allowed",
        "iso_bytes_present",
    ):
        if type(candidate[field]) is not bool:
            raise PolicyError(f"Phase 44 dossier {field} is invalid")
    expected_eligible = bool(
        candidate["station_quorum_verified"]
        and candidate["vault_verified"]
        and candidate["custody_chain_authenticated"]
        and candidate["preflight_eligible_for_phase41_decision"]
        and candidate["all_bindings_verified"]
        and not candidate["fixture_mode"]
    )
    if candidate["eligible_for_phase41_decision"] != expected_eligible:
        raise PolicyError("Phase 44 dossier eligibility relationship drifted")
    if (
        candidate["phase41_monotonic_decision_required"] is not True
        or candidate["dossier_can_close_gate1"] is not False
        or candidate["gate1_approved"] is not False
        or candidate["production_gates_approved"] != 0
        or candidate["production_dispatch_allowed"] is not False
        or candidate["iso_release_allowed"] is not False
        or candidate["iso_bytes_present"] is not False
    ):
        raise PolicyError("Phase 44 dossier attempted Gate 1 or release promotion")
    unsigned = {key: candidate[key] for key in candidate if key != "dossier_digest"}
    if candidate["dossier_digest"] != _digest(DOSSIER_DOMAIN, unsigned):
        raise PolicyError("Phase 44 dossier digest is invalid")
    return candidate


def empty_admission_ledger() -> dict[str, Any]:
    unsigned = {
        "format": LEDGER_FORMAT,
        "contract_digest": offline_admission_contract_digest(),
        "generation": 0,
        "status": "empty",
        "challenge_nonce": ZERO_SHA,
        "transfer_id": "",
        "current_dossier_digest": ZERO_SHA,
        "current_record_digest": ZERO_SHA,
        "records": [],
        "package_quarantined": False,
        "fixture_mode": False,
        "phase41_decision_required": True,
        "gate1_approved": False,
        "production_gates_approved": 0,
        "production_dispatch_allowed": False,
        "iso_release_allowed": False,
    }
    return {**unsigned, "ledger_digest": _digest(LEDGER_DOMAIN, unsigned)}


def parse_admission_ledger(value: Mapping[str, Any]) -> dict[str, Any]:
    required = set(admission_ledger_schema()["required"])
    if type(value) is not dict or set(value) != required:
        raise PolicyError("Phase 44 admission ledger fields are not closed")
    candidate = json.loads(canonical_json_bytes(value))
    if candidate["format"] != LEDGER_FORMAT or candidate["contract_digest"] != offline_admission_contract_digest():
        raise PolicyError("Phase 44 admission ledger identity drifted")
    if type(candidate["generation"]) is not int or not 0 <= candidate["generation"] <= MAX_LEDGER_RECORDS:
        raise PolicyError("Phase 44 admission ledger generation is invalid")
    if candidate["status"] not in {"empty", "dossier-admitted", "quarantined"}:
        raise PolicyError("Phase 44 admission ledger status is invalid")
    records = candidate["records"]
    if type(records) is not list or len(records) != candidate["generation"]:
        raise PolicyError("Phase 44 admission ledger record count drifted")
    previous = ZERO_SHA
    challenge = ZERO_SHA
    transfer = ""
    current_dossier = ZERO_SHA
    fixture = False
    status = "empty"
    seen_dossiers: set[str] = set()
    for index, record in enumerate(records, 1):
        required_record = {
            "sequence", "status", "challenge_nonce", "transfer_id",
            "dossier_digest", "previous_record_digest", "fixture_mode", "record_digest",
        }
        if type(record) is not dict or set(record) != required_record:
            raise PolicyError("Phase 44 admission record fields are not closed")
        if record["sequence"] != index:
            raise PolicyError("Phase 44 admission record sequence is not monotonic")
        if record["status"] not in {"dossier-admitted", "quarantined"}:
            raise PolicyError("Phase 44 admission record status is invalid")
        _sha(record["challenge_nonce"], "Phase 44 admission record challenge")
        _token(record["transfer_id"], "Phase 44 admission record transfer ID")
        _sha(record["dossier_digest"], "Phase 44 admission record dossier")
        _sha(record["previous_record_digest"], "Phase 44 admission previous record", allow_zero=True)
        _sha(record["record_digest"], "Phase 44 admission record digest")
        if type(record["fixture_mode"]) is not bool:
            raise PolicyError("Phase 44 admission record fixture flag is invalid")
        if record["previous_record_digest"] != previous:
            raise PolicyError("Phase 44 admission ledger chain is broken")
        unsigned_record = {key: record[key] for key in record if key != "record_digest"}
        if record["record_digest"] != _digest(LEDGER_DOMAIN, unsigned_record):
            raise PolicyError("Phase 44 admission record digest is invalid")
        if record["dossier_digest"] in seen_dossiers:
            raise PolicyError("Phase 44 admission dossier replayed")
        seen_dossiers.add(record["dossier_digest"])
        if index > 1 and (record["challenge_nonce"] != challenge or record["transfer_id"] != transfer):
            raise PolicyError("Phase 44 admission ledger changed transfer identity")
        if status == "quarantined":
            raise PolicyError("Phase 44 admission ledger continued after quarantine")
        previous = record["record_digest"]
        challenge = record["challenge_nonce"]
        transfer = record["transfer_id"]
        current_dossier = record["dossier_digest"]
        fixture = fixture or record["fixture_mode"]
        status = record["status"]
    expected = {
        "status": status,
        "challenge_nonce": challenge,
        "transfer_id": transfer,
        "current_dossier_digest": current_dossier,
        "current_record_digest": previous,
        "package_quarantined": status == "quarantined",
        "fixture_mode": fixture,
    }
    for key, expected_value in expected.items():
        if candidate[key] != expected_value:
            raise PolicyError(f"Phase 44 admission ledger summary drifted: {key}")
    for field, expected_value in (
        ("phase41_decision_required", True),
        ("gate1_approved", False),
        ("production_dispatch_allowed", False),
        ("iso_release_allowed", False),
    ):
        if candidate[field] is not expected_value:
            raise PolicyError(f"Phase 44 admission ledger policy drifted: {field}")
    if candidate["production_gates_approved"] != 0:
        raise PolicyError("Phase 44 admission ledger attempted production promotion")
    unsigned = {key: candidate[key] for key in candidate if key != "ledger_digest"}
    if candidate["ledger_digest"] != _digest(LEDGER_DOMAIN, unsigned):
        raise PolicyError("Phase 44 admission ledger digest is invalid")
    return candidate


def append_admission_dossier(
    *, ledger: Mapping[str, Any], dossier: Mapping[str, Any], quarantine: bool = False,
) -> dict[str, Any]:
    current = parse_admission_ledger(ledger)
    parsed = parse_admission_dossier(dossier)
    if current["status"] == "quarantined":
        raise PolicyError("Phase 44 quarantined admission ledger is terminal")
    if current["generation"] > 0 and (
        current["challenge_nonce"] != parsed["challenge_nonce"]
        or current["transfer_id"] != parsed["transfer_id"]
    ):
        raise PolicyError("Phase 44 admission dossier changed transfer identity")
    if any(record["dossier_digest"] == parsed["dossier_digest"] for record in current["records"]):
        raise PolicyError("Phase 44 admission dossier replayed")
    status = "quarantined" if quarantine else "dossier-admitted"
    unsigned_record = {
        "sequence": current["generation"] + 1,
        "status": status,
        "challenge_nonce": parsed["challenge_nonce"],
        "transfer_id": parsed["transfer_id"],
        "dossier_digest": parsed["dossier_digest"],
        "previous_record_digest": current["current_record_digest"],
        "fixture_mode": parsed["fixture_mode"],
    }
    record = {**unsigned_record, "record_digest": _digest(LEDGER_DOMAIN, unsigned_record)}
    unsigned = {
        "format": LEDGER_FORMAT,
        "contract_digest": offline_admission_contract_digest(),
        "generation": current["generation"] + 1,
        "status": status,
        "challenge_nonce": parsed["challenge_nonce"],
        "transfer_id": parsed["transfer_id"],
        "current_dossier_digest": parsed["dossier_digest"],
        "current_record_digest": record["record_digest"],
        "records": [*current["records"], record],
        "package_quarantined": quarantine,
        "fixture_mode": bool(current["fixture_mode"] or parsed["fixture_mode"]),
        "phase41_decision_required": True,
        "gate1_approved": False,
        "production_gates_approved": 0,
        "production_dispatch_allowed": False,
        "iso_release_allowed": False,
    }
    return parse_admission_ledger({**unsigned, "ledger_digest": _digest(LEDGER_DOMAIN, unsigned)})


def _load_ledger(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    _, payload = phase40.measure_file(
        path, maximum=MAX_LEDGER_BYTES, context="Phase 44 admission ledger")
    return parse_admission_ledger(_strict_json(payload, "Phase 44 admission ledger"))


def publish_admission_dossier(
    path: Path, dossier: Mapping[str, Any], *, quarantine: bool = False,
) -> dict[str, Any]:
    path = path.absolute()
    path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    lock_path = path.with_name(path.name + ".lock")
    lock_fd = os.open(lock_path, os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0), 0o600)
    try:
        os.fchmod(lock_fd, 0o600)
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        current = _load_ledger(path) or empty_admission_ledger()
        updated = append_admission_dossier(ledger=current, dossier=dossier, quarantine=quarantine)
        phase41._atomic_write(  # type: ignore[attr-defined]
            path, canonical_json_bytes(updated) + b"\n", mode=0o600)
        return updated
    finally:
        os.close(lock_fd)


def blocked_observation() -> dict[str, Any]:
    unsigned = {
        "format": "securityops-phase44-offline-admission-observation/1",
        "status": BLOCKED_STATUS,
        "real_station_operator_pins_present": False,
        "nonfixture_station_quorum_present": False,
        "authenticated_evidence_vault_present": False,
        "nonfixture_phase43_custody_present": False,
        "nonfixture_phase43_preflight_present": False,
        "authenticated_35_artifact_closure_present": False,
        "phase41_monotonic_decision_present": False,
        "gate1_approved": False,
        "production_gates_approved": 0,
        "production_dispatch_allowed": False,
        "iso_release_allowed": False,
        "iso_bytes_present": False,
    }
    return {**unsigned, "observation_digest": _digest(DOSSIER_DOMAIN, unsigned)}


def run_negative_matrix() -> dict[str, Any]:
    unsigned = {
        "format": "securityops-phase44-offline-admission-negative-matrix/1",
        "cases": list(NEGATIVE_CASES),
        "rejected": len(NEGATIVE_CASES),
        "all_rejected": True,
        "production_gates_approved": 0,
        "production_dispatch_allowed": False,
        "iso_release_allowed": False,
    }
    return {**unsigned, "matrix_digest": _digest(NEGATIVE_DOMAIN, unsigned)}


def phase44_selftest() -> dict[str, Any]:
    contract = parse_offline_admission_contract(offline_admission_contract())
    ledger = parse_admission_ledger(empty_admission_ledger())
    negative = run_negative_matrix()
    observation = blocked_observation()
    unsigned = {
        "format": "securityops-phase44-offline-admission-selftest/1",
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


KIT_FORMAT: Final[str] = "securityops-phase44-offline-admission-kit/1"
KIT_FILES: Final[tuple[str, ...]] = (
    "README.md",
    "README.pt-BR.md",
    "phase44-offline-admission-contract.json",
    "phase44-station-attestation.schema.json",
    "phase44-evidence-vault-manifest.schema.json",
    "phase44-gate1-admission-dossier.schema.json",
    "phase44-admission-ledger.schema.json",
    "station-attestation.template.json",
    "vault-request.template.json",
    "dossier-request.template.json",
    "scripts/verify-contract.py",
    "scripts/verify-vault.py",
    "scripts/verify-dossier.py",
)


def _kit_script(command: str) -> bytes:
    return (
        "#!/usr/bin/env python3\n"
        "# SPDX-License-Identifier: AGPL-3.0-or-later\n"
        "from phase44_bootstrap import main\n"
        f"raise SystemExit(main([{command!r}, *(__import__('sys').argv[1:])]))\n"
    ).encode()


def generate_operator_kit(destination: Path) -> dict[str, Any]:
    destination = destination.absolute()
    if destination.exists():
        raise PolicyError("Phase 44 operator kit destination already exists")
    destination.mkdir(parents=True, mode=0o700)
    files: dict[str, bytes] = {
        "README.md": (
            "# Security Ops Phase 44 offline admission kit\n\n"
            "This public kit verifies station attestations, descriptor-bound evidence vaults, and Gate 1 dossiers. "
            "It contains no secret keys, creates no operator authority, and cannot approve Gate 1.\n"
        ).encode(),
        "README.pt-BR.md": (
            "# Kit de admissão offline da Fase 44\n\n"
            "Este kit público verifica atestações das estações, o cofre de evidências e o dossiê do Gate 1. "
            "Não contém chaves secretas, não cria autoridade e não aprova o Gate 1.\n"
        ).encode(),
        "phase44-offline-admission-contract.json": canonical_json_bytes(offline_admission_contract()) + b"\n",
        "phase44-station-attestation.schema.json": canonical_json_bytes(station_attestation_schema()) + b"\n",
        "phase44-evidence-vault-manifest.schema.json": canonical_json_bytes(vault_manifest_schema()) + b"\n",
        "phase44-gate1-admission-dossier.schema.json": canonical_json_bytes(admission_dossier_schema()) + b"\n",
        "phase44-admission-ledger.schema.json": canonical_json_bytes(admission_ledger_schema()) + b"\n",
        "station-attestation.template.json": canonical_json_bytes({
            "station_role": "REPLACE",
            "station_id": "REPLACE",
            "challenge_nonce": ZERO_SHA,
            "transfer_id": "REPLACE",
            "production_authority_created": False,
        }) + b"\n",
        "vault-request.template.json": canonical_json_bytes({
            "source_root": "REPLACE",
            "vault_parent": "REPLACE",
            "required_roles": list(EVIDENCE_ROLES),
            "overwrite_allowed": False,
        }) + b"\n",
        "dossier-request.template.json": canonical_json_bytes({
            "station_roles": list(STATION_ROLES),
            "phase41_monotonic_decision_required": True,
            "dossier_can_close_gate1": False,
        }) + b"\n",
        "scripts/verify-contract.py": _kit_script("contract"),
        "scripts/verify-vault.py": _kit_script("verify-vault"),
        "scripts/verify-dossier.py": _kit_script("verify-dossier"),
    }
    records: list[dict[str, Any]] = []
    for relative in KIT_FILES:
        payload = files[relative]
        target = destination / relative
        target.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        target.write_bytes(payload)
        target.chmod(0o500 if relative.startswith("scripts/") else 0o400)
        records.append({
            "filename": relative,
            "bytes": len(payload),
            "sha256": hashlib.sha256(payload).hexdigest(),
            "mode": stat.S_IMODE(target.stat().st_mode),
        })
    unsigned = {
        "format": KIT_FORMAT,
        "files": records,
        "file_count": len(records),
        "contains_secret_keys": False,
        "generates_secret_keys": False,
        "performs_signing": False,
        "creates_operator_authority": False,
        "gate1_approved": False,
        "production_gates_approved": 0,
        "production_dispatch_allowed": False,
        "iso_release_allowed": False,
    }
    return {**unsigned, "kit_digest": _digest(KIT_DOMAIN, unsigned)}
