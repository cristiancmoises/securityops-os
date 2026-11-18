# CodeMark v1 project=4c63e0fe-589c-4944-8449-97e211a38b72 file=1b01f0bde3a75707b21fd20613b7d859 owner="Cristian Cezar Mois\u00e9s"
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Phase 44 Gate 1 evidence-dossier and immutable-vault boundary.

The dossier retains the exact verified documents needed to audit the ordered
Phase 39--43 Gate 1 chain.  It provides descriptor-relative measurement,
streaming copy, atomic no-replace publication, immutable/private vault files,
and semantic reconciliation of the inherited receipts.

A dossier is an audit and transfer artifact.  It never creates owner,
publisher, build-node, witness, or custody-operator authority and it cannot
approve Gate 1.  It can only *observe* an already-authenticated monotonic Phase
41 decision after every referenced document has been measured and cross-bound.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tempfile
from typing import Any, Final, Mapping, Sequence

try:
    from . import phase39_owner_execution as phase39
    from . import phase40_owner_trust as phase40
    from . import phase40_gate1_admission as phase40_gate1
    from . import phase41_owner_ceremony as phase41
    from . import phase41_gate1_execution as phase41_gate1
    from . import phase42_media as phase42_media
    from . import phase42_offline_ceremony as phase42_ceremony
    from . import phase43_offline_custody as phase43
except ImportError:  # pragma: no cover - installed Guix Center sibling copy
    import phase39_owner_execution as phase39  # type: ignore[no-redef]
    import phase40_owner_trust as phase40  # type: ignore[no-redef]
    import phase40_gate1_admission as phase40_gate1  # type: ignore[no-redef]
    import phase41_owner_ceremony as phase41  # type: ignore[no-redef]
    import phase41_gate1_execution as phase41_gate1  # type: ignore[no-redef]
    import phase42_media as phase42_media  # type: ignore[no-redef]
    import phase42_offline_ceremony as phase42_ceremony  # type: ignore[no-redef]
    import phase43_offline_custody as phase43  # type: ignore[no-redef]

PolicyError = phase40.PolicyError
canonical_json_bytes = phase40.canonical_json_bytes

CONTRACT_FORMAT: Final[str] = "securityops-phase44-gate1-dossier-contract/1"
MANIFEST_FORMAT: Final[str] = "securityops-phase44-gate1-dossier-manifest/1"
READY_FORMAT: Final[str] = "securityops-phase44-gate1-vault-ready/1"
READINESS_FORMAT: Final[str] = "securityops-phase44-gate1-readiness-report/1"
STATUS: Final[str] = "PASS_PHASE44_GATE1_DOSSIER_VAULT_AND_RECONCILIATION_BOUNDARY"
BLOCKED_STATUS: Final[str] = "BLOCKED_PHASE44_NONFIXTURE_GATE1_DOSSIER_AND_DECISION_REQUIRED"

CONTRACT_DOMAIN: Final[bytes] = b"SECURITYOPS-PHASE44-GATE1-DOSSIER-CONTRACT-V1\x00"
MANIFEST_DOMAIN: Final[bytes] = b"SECURITYOPS-PHASE44-GATE1-DOSSIER-MANIFEST-V1\x00"
INVENTORY_DOMAIN: Final[bytes] = b"SECURITYOPS-PHASE44-GATE1-DOSSIER-INVENTORY-V1\x00"
READY_DOMAIN: Final[bytes] = b"SECURITYOPS-PHASE44-GATE1-VAULT-READY-V1\x00"
READINESS_DOMAIN: Final[bytes] = b"SECURITYOPS-PHASE44-GATE1-READINESS-V1\x00"
KIT_DOMAIN: Final[bytes] = b"SECURITYOPS-PHASE44-GATE1-DOSSIER-KIT-V1\x00"

PHASE43_IDENTITIES: Final[dict[str, str]] = {
    "runtime_commit": "fb06c37b8686a570593ce5b29c9d760df965f20d",
    "runtime_tree": "7f5cdfe4e721400474c2565d34a2951afc84e47a",
    "securityops_os_commit": "ea87d802c595a4af59e00f615eb4073284a74969",
    "securityops_os_tree": "9f87f0401536b33f494d5131e8504e07037a30c8",
    "stable_v1_13_0": "8373fd789c9a525d6128abfd3d7a93ad4db3348b",
}
PHASE43_CONTRACT_DIGEST: Final[str] = (
    "437249725663498e48a7f9fbdce8e8e1f28f76ad25cd58aab1119f6141f481f2"
)
ZERO_SHA: Final[str] = "0" * 64
MAX_JSON_BYTES: Final[int] = 64 * 1024 * 1024
MAX_TOTAL_BYTES: Final[int] = 512 * 1024 * 1024
MAX_MANIFEST_BYTES: Final[int] = 8 * 1024 * 1024
MAX_READY_BYTES: Final[int] = 2 * 1024 * 1024
MAX_LIFETIME: Final[int] = 30 * 24 * 60 * 60
CHUNK_BYTES: Final[int] = 1024 * 1024

_SHA = re.compile(r"[0-9a-f]{64}\Z")
_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")

# The dossier intentionally stores verified receipts and their exact source
# documents, not secret keys.  The raw detached signatures/keyrings remain in
# their owner-controlled media packages and are bound through the verification
# receipts and Phase 43 custody chain.
ROLE_FILES: Final[tuple[tuple[str, str], ...]] = (
    ("phase39-gate-job", "001-phase39-gate-job.json"),
    ("phase39-gate-result", "002-phase39-gate-result.json"),
    ("phase39-exchange-verification", "003-phase39-exchange-verification.json"),
    ("phase39-replay-ledger", "004-phase39-replay-ledger.json"),
    ("phase40-trust-root", "005-phase40-trust-root.json"),
    ("phase40-trust-state", "006-phase40-trust-state.json"),
    ("phase40-input-closure", "007-phase40-input-closure.json"),
    ("phase40-semantic-admission", "008-phase40-semantic-admission.json"),
    ("phase41-ceremony-state", "009-phase41-ceremony-state.json"),
    ("phase41-ceremony-store", "010-phase41-ceremony-store.json"),
    ("phase41-gate1-decision", "011-phase41-gate1-decision.json"),
    ("phase41-decision-ledger", "012-phase41-decision-ledger.json"),
    ("phase42-media-review", "013-phase42-media-review.json"),
    ("phase42-witness-checkpoint", "014-phase42-witness-checkpoint.json"),
    ("phase42-witness-verification", "015-phase42-witness-verification.json"),
    ("phase42-witness-ledger", "016-phase42-witness-ledger.json"),
    ("phase42-ceremony-transcript", "017-phase42-ceremony-transcript.json"),
    ("phase42-transcript-verification", "018-phase42-transcript-verification.json"),
    ("phase43-custody-ledger", "019-phase43-custody-ledger.json"),
    ("phase43-gate1-preflight", "020-phase43-gate1-preflight.json"),
)
ROLES: Final[tuple[str, ...]] = tuple(role for role, _ in ROLE_FILES)
ROLE_TO_FILE: Final[dict[str, str]] = dict(ROLE_FILES)
FILE_TO_ROLE: Final[dict[str, str]] = {name: role for role, name in ROLE_FILES}

NEGATIVE_CASES: Final[tuple[str, ...]] = (
    "manifest-extra-field", "manifest-role-removed", "manifest-role-reordered",
    "manifest-filename-substituted", "manifest-zero-challenge",
    "manifest-lifetime-exceeded", "manifest-fixture-promotion",
    "source-root-symlink", "source-root-replaced", "source-file-symlink",
    "source-file-hardlink", "source-file-mode-unsafe", "source-file-mutated",
    "source-file-truncated", "source-file-extended", "source-inode-alias",
    "vault-parent-unsafe", "vault-destination-overwrite", "vault-extra-file",
    "vault-file-symlink", "vault-file-hardlink", "vault-file-mode-drift",
    "vault-manifest-tampered", "vault-ready-tampered",
    "readiness-job-result-mismatch", "readiness-preflight-decision-mismatch",
    "readiness-custody-mismatch", "readiness-witness-mismatch",
    "readiness-transcript-mismatch", "readiness-fixture-promotion",
    "readiness-dossier-approves-gate1", "readiness-production-promotion",
)

KIT_FORMAT: Final[str] = "securityops-phase44-gate1-dossier-kit/1"
KIT_FILES: Final[tuple[str, ...]] = (
    "README.md", "README.pt-BR.md",
    "phase44-gate1-dossier-contract.json",
    "phase44-gate1-dossier-manifest.schema.json",
    "phase44-gate1-vault-ready.schema.json",
    "phase44-gate1-readiness-report.schema.json",
    "manifest.template.json",
    "scripts/create-manifest.py", "scripts/stage-dossier.py",
    "scripts/verify-vault.py", "scripts/create-readiness-report.py",
)


def _digest(domain: bytes, value: Mapping[str, Any]) -> str:
    return hashlib.sha256(domain + canonical_json_bytes(value)).hexdigest()


def _sha(value: Any, context: str, *, allow_zero: bool = False) -> str:
    if type(value) is not str or not _SHA.fullmatch(value):
        raise PolicyError(f"{context} must be a lowercase SHA-256 digest")
    if not allow_zero and value == ZERO_SHA:
        raise PolicyError(f"{context} cannot be zero")
    return value


def _token(value: Any, context: str) -> str:
    if type(value) is not str or not _TOKEN.fullmatch(value):
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


def _file_identity(info: os.stat_result) -> tuple[int, int, int, int, int, int, int]:
    return (
        info.st_dev, info.st_ino, info.st_mode, info.st_nlink,
        info.st_uid, info.st_gid, info.st_size,
    )


def _directory_identity(info: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid, info.st_nlink)


def _validate_private_directory(info: os.stat_result, context: str, *, exact: bool = False) -> None:
    mode = stat.S_IMODE(info.st_mode)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid not in {0, os.getuid()}:
        raise PolicyError(f"{context} is not a caller-controlled directory")
    if exact:
        if mode != 0o700:
            raise PolicyError(f"{context} must have mode 0700")
    elif mode & 0o022:
        raise PolicyError(f"{context} is group/world writable")


def _open_directory(path: Path, context: str, *, exact_private: bool = False) -> tuple[Path, int, os.stat_result]:
    absolute = path.absolute()
    flags = (
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        fd = os.open(absolute, flags)
    except OSError as exc:
        raise PolicyError(f"{context} is unavailable") from exc
    try:
        opened = os.fstat(fd)
        _validate_private_directory(opened, context, exact=exact_private)
        path_info = os.stat(absolute, follow_symlinks=False)
        if _directory_identity(opened) != _directory_identity(path_info):
            raise PolicyError(f"{context} path identity changed")
        return absolute, fd, opened
    except Exception:
        os.close(fd)
        raise


def _read_relative(
    root_fd: int, filename: str, *, maximum: int, context: str,
    identities: set[tuple[int, int]] | None = None,
    exact_mode: int | None = None,
) -> tuple[bytes, os.stat_result, str]:
    if filename in {"", ".", ".."} or "/" in filename or "\x00" in filename:
        raise PolicyError(f"{context} filename is invalid")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(filename, flags, dir_fd=root_fd)
    except OSError as exc:
        raise PolicyError(f"{context} is unavailable") from exc
    try:
        before = os.fstat(fd)
        mode = stat.S_IMODE(before.st_mode)
        if (
            not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
            or before.st_uid not in {0, os.getuid()} or mode & 0o111
            or mode & 0o022
        ):
            raise PolicyError(f"{context} is not a private single-linked data file")
        if exact_mode is not None and mode != exact_mode:
            raise PolicyError(f"{context} mode differs from {exact_mode:04o}")
        if before.st_size < 2 or before.st_size > maximum:
            raise PolicyError(f"{context} size is outside policy")
        inode = (before.st_dev, before.st_ino)
        if identities is not None:
            if inode in identities:
                raise PolicyError(f"{context} aliases another dossier file")
            identities.add(inode)
        digest = hashlib.sha256()
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(fd, min(CHUNK_BYTES, maximum - total + 1))
            if not chunk:
                break
            total += len(chunk)
            if total > maximum:
                raise PolicyError(f"{context} exceeds its size limit")
            digest.update(chunk)
            chunks.append(chunk)
        after = os.fstat(fd)
        if _file_identity(before) != _file_identity(after) or total != before.st_size:
            raise PolicyError(f"{context} changed during measurement")
        return b"".join(chunks), before, digest.hexdigest()
    finally:
        os.close(fd)


def _measure_relative_streaming(
    root_fd: int, filename: str, *, maximum: int, context: str,
    identities: set[tuple[int, int]],
) -> tuple[int, str, os.stat_result]:
    if filename in {"", ".", ".."} or "/" in filename or "\x00" in filename:
        raise PolicyError(f"{context} filename is invalid")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(filename, flags, dir_fd=root_fd)
    except OSError as exc:
        raise PolicyError(f"{context} is unavailable") from exc
    try:
        before = os.fstat(fd)
        mode = stat.S_IMODE(before.st_mode)
        if (
            not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
            or before.st_uid not in {0, os.getuid()} or mode & 0o111
            or mode & 0o022
        ):
            raise PolicyError(f"{context} is not a private single-linked data file")
        if before.st_size < 2 or before.st_size > maximum:
            raise PolicyError(f"{context} size is outside policy")
        inode = (before.st_dev, before.st_ino)
        if inode in identities:
            raise PolicyError(f"{context} aliases another dossier file")
        identities.add(inode)
        digest = hashlib.sha256()
        total = 0
        while True:
            chunk = os.read(fd, CHUNK_BYTES)
            if not chunk:
                break
            total += len(chunk)
            if total > maximum:
                raise PolicyError(f"{context} exceeds its size limit")
            digest.update(chunk)
        after = os.fstat(fd)
        if _file_identity(before) != _file_identity(after) or total != before.st_size:
            raise PolicyError(f"{context} changed during measurement")
        return total, digest.hexdigest(), before
    finally:
        os.close(fd)


def _write_all(fd: int, payload: bytes) -> None:
    view = memoryview(payload)
    while view:
        written = os.write(fd, view)
        if written <= 0:
            raise PolicyError("Phase 44 short write")
        view = view[written:]


def _write_private_file(path: Path, payload: bytes, *, mode: int = 0o400) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    fd = os.open(path, flags, mode)
    try:
        _write_all(fd, payload)
        os.fsync(fd)
        os.fchmod(fd, mode)
    finally:
        os.close(fd)


def _copy_relative_to(
    source_fd: int, filename: str, destination: Path, *, expected_size: int,
    expected_sha256: str, identities: set[tuple[int, int]], context: str,
) -> None:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        src = os.open(filename, flags, dir_fd=source_fd)
    except OSError as exc:
        raise PolicyError(f"{context} source is unavailable") from exc
    dst = -1
    try:
        before = os.fstat(src)
        mode = stat.S_IMODE(before.st_mode)
        if (
            not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
            or before.st_uid not in {0, os.getuid()} or mode & 0o111
            or mode & 0o022
        ):
            raise PolicyError(f"{context} source is unsafe")
        inode = (before.st_dev, before.st_ino)
        if inode in identities:
            raise PolicyError(f"{context} source aliases another file")
        identities.add(inode)
        if before.st_size != expected_size:
            raise PolicyError(f"{context} source size differs from manifest")
        dst = os.open(
            destination,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
            0o400,
        )
        digest = hashlib.sha256()
        total = 0
        while True:
            chunk = os.read(src, CHUNK_BYTES)
            if not chunk:
                break
            total += len(chunk)
            if total > expected_size:
                raise PolicyError(f"{context} source grew during staging")
            digest.update(chunk)
            _write_all(dst, chunk)
        os.fsync(dst)
        os.fchmod(dst, 0o400)
        after = os.fstat(src)
        if (
            _file_identity(before) != _file_identity(after)
            or total != expected_size or digest.hexdigest() != expected_sha256
        ):
            raise PolicyError(f"{context} source changed or differs from manifest")
    finally:
        if dst >= 0:
            os.close(dst)
        os.close(src)


def manifest_schema() -> dict[str, Any]:
    sha = {"type": "string", "pattern": "^[0-9a-f]{64}$"}
    record = {
        "type": "object", "additionalProperties": False,
        "required": ["index", "role", "filename", "size", "sha256"],
        "properties": {
            "index": {"type": "integer", "minimum": 1, "maximum": len(ROLES)},
            "role": {"enum": list(ROLES)},
            "filename": {"enum": [name for _, name in ROLE_FILES]},
            "size": {"type": "integer", "minimum": 2, "maximum": MAX_JSON_BYTES},
            "sha256": sha,
        },
    }
    required = [
        "format", "contract_digest", "dossier_id", "created_unix", "expires_unix",
        "challenge_nonce", "gate_name", "gate_index", "phase43_identities",
        "role_count", "roles", "files", "total_bytes", "fixture_mode",
        "owner_authority_created", "dossier_can_approve_gate1",
        "production_gates_approved", "production_dispatch_allowed",
        "iso_release_allowed", "iso_bytes_present", "manifest_digest",
    ]
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://securityops.co/schemas/guix-center/phase44-gate1-dossier-manifest.schema.json",
        "title": "Security Ops Phase 44 Gate 1 evidence dossier manifest",
        "type": "object", "additionalProperties": False,
        "required": required,
        "properties": {
            "format": {"const": MANIFEST_FORMAT}, "contract_digest": sha,
            "dossier_id": {"type": "string", "minLength": 1, "maxLength": 128},
            "created_unix": {"type": "integer", "minimum": 1},
            "expires_unix": {"type": "integer", "minimum": 1},
            "challenge_nonce": sha, "gate_name": {"const": phase39.GATE_NAMES[0]},
            "gate_index": {"const": 1},
            "phase43_identities": {
                "type": "object", "additionalProperties": False,
                "required": list(PHASE43_IDENTITIES),
                "properties": {key: {"const": value} for key, value in PHASE43_IDENTITIES.items()},
            },
            "role_count": {"const": len(ROLES)},
            "roles": {"type": "array", "prefixItems": [{"const": role} for role in ROLES], "items": False},
            "files": {"type": "array", "prefixItems": [record for _ in ROLES], "items": False},
            "total_bytes": {"type": "integer", "minimum": 2, "maximum": MAX_TOTAL_BYTES},
            "fixture_mode": {"type": "boolean"},
            "owner_authority_created": {"const": False},
            "dossier_can_approve_gate1": {"const": False},
            "production_gates_approved": {"const": 0},
            "production_dispatch_allowed": {"const": False},
            "iso_release_allowed": {"const": False}, "iso_bytes_present": {"const": False},
            "manifest_digest": sha,
        },
    }


def ready_schema() -> dict[str, Any]:
    sha = {"type": "string", "pattern": "^[0-9a-f]{64}$"}
    required = [
        "format", "contract_digest", "dossier_id", "challenge_nonce",
        "manifest_digest", "inventory_digest", "file_count", "total_bytes",
        "fixture_mode", "vault_integrity_verified", "owner_authority_created",
        "dossier_can_approve_gate1", "gate1_approved", "production_gates_approved",
        "production_dispatch_allowed", "iso_release_allowed", "iso_bytes_present",
        "ready_digest",
    ]
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://securityops.co/schemas/guix-center/phase44-gate1-vault-ready.schema.json",
        "title": "Security Ops Phase 44 immutable dossier vault receipt",
        "type": "object", "additionalProperties": False, "required": required,
        "properties": {
            "format": {"const": READY_FORMAT}, "contract_digest": sha,
            "dossier_id": {"type": "string", "minLength": 1, "maxLength": 128},
            "challenge_nonce": sha, "manifest_digest": sha, "inventory_digest": sha,
            "file_count": {"const": len(ROLES)},
            "total_bytes": {"type": "integer", "minimum": 2, "maximum": MAX_TOTAL_BYTES},
            "fixture_mode": {"type": "boolean"},
            "vault_integrity_verified": {"const": True},
            "owner_authority_created": {"const": False},
            "dossier_can_approve_gate1": {"const": False},
            "gate1_approved": {"const": False}, "production_gates_approved": {"const": 0},
            "production_dispatch_allowed": {"const": False},
            "iso_release_allowed": {"const": False}, "iso_bytes_present": {"const": False},
            "ready_digest": sha,
        },
    }


def readiness_schema() -> dict[str, Any]:
    sha = {"type": "string", "pattern": "^[0-9a-f]{64}$"}
    required = [
        "format", "contract_digest", "status", "dossier_id", "challenge_nonce",
        "manifest_digest", "ready_digest", "semantic_document_count",
        "dossier_integrity_verified", "all_cross_bindings_verified",
        "phase43_preflight_eligible", "phase41_decision_present",
        "phase41_decision_approved", "phase41_decision_digest",
        "phase41_decision_ledger_digest", "fixture_mode",
        "gate1_approval_source", "dossier_can_approve_gate1",
        "observed_production_gates_approved", "production_dispatch_allowed",
        "iso_release_allowed", "iso_bytes_present", "readiness_digest",
    ]
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://securityops.co/schemas/guix-center/phase44-gate1-readiness-report.schema.json",
        "title": "Security Ops Phase 44 reconciled Gate 1 audit report",
        "type": "object", "additionalProperties": False, "required": required,
        "properties": {
            "format": {"const": READINESS_FORMAT}, "contract_digest": sha,
            "status": {"enum": [STATUS, BLOCKED_STATUS]},
            "dossier_id": {"type": "string", "minLength": 1, "maxLength": 128},
            "challenge_nonce": sha, "manifest_digest": sha, "ready_digest": sha,
            "semantic_document_count": {"const": len(ROLES)},
            "dossier_integrity_verified": {"const": True},
            "all_cross_bindings_verified": {"const": True},
            "phase43_preflight_eligible": {"type": "boolean"},
            "phase41_decision_present": {"const": True},
            "phase41_decision_approved": {"type": "boolean"},
            "phase41_decision_digest": sha, "phase41_decision_ledger_digest": sha,
            "fixture_mode": {"type": "boolean"},
            "gate1_approval_source": {"enum": ["none", "phase41-monotonic-decision-ledger"]},
            "dossier_can_approve_gate1": {"const": False},
            "observed_production_gates_approved": {"type": "integer", "minimum": 0, "maximum": 1},
            "production_dispatch_allowed": {"const": False},
            "iso_release_allowed": {"const": False}, "iso_bytes_present": {"const": False},
            "readiness_digest": sha,
        },
    }


def _contract_unsigned() -> dict[str, Any]:
    schemas = {
        "manifest": manifest_schema(), "ready": ready_schema(), "readiness": readiness_schema(),
    }
    return {
        "format": CONTRACT_FORMAT,
        "status": STATUS,
        "phase43_identities": dict(PHASE43_IDENTITIES),
        "phase43_custody_contract_digest": PHASE43_CONTRACT_DIGEST,
        "phase42_offline_ceremony_contract_digest": phase43.PHASE42_CONTRACT_DIGEST,
        "phase41_gate1_contract_digest": phase41_gate1.gate1_execution_contract_digest(),
        "phase40_gate1_contract_digest": phase40_gate1.gate1_contract_digest(),
        "phase39_contract_digest": phase39.phase39_contract_digest(),
        "roles": list(ROLES),
        "role_filenames": {role: filename for role, filename in ROLE_FILES},
        "schemas": {
            key: {
                "id": schema["$id"],
                "canonical_sha256": hashlib.sha256(canonical_json_bytes(schema)).hexdigest(),
            }
            for key, schema in schemas.items()
        } | {"additional_properties_allowed": False},
        "vault_policy": {
            "stable_source_directory_descriptor_required": True,
            "descriptor_relative_no_follow_open_required": True,
            "streaming_measurement_and_copy_required": True,
            "single_link_regular_files_required": True,
            "unique_source_inode_per_role_required": True,
            "source_identity_rechecked_after_copy": True,
            "private_mode_0400_vault_files_required": True,
            "atomic_rename_noreplace_publication_required": True,
            "destination_overwrite_allowed": False,
            "extra_or_missing_role_allowed": False,
            "vault_is_signature_or_source_authority": False,
        },
        "reconciliation_policy": {
            "all_documents_must_be_strict_json": True,
            "phase39_through_phase43_receipts_cross_bound": True,
            "phase43_preflight_must_match_phase41_decision": True,
            "phase41_monotonic_decision_ledger_is_only_gate1_source": True,
            "dossier_can_create_or_approve_gate1": False,
            "fixture_dossier_can_observe_gate1_approval": False,
            "report_must_be_recomputed_from_vault": True,
        },
        "network_fetch_allowed": False,
        "production_gates_approved": 0,
        "production_dispatch_allowed": False,
        "iso_release_allowed": False,
        "execution_status": BLOCKED_STATUS,
    }


def gate1_dossier_contract() -> dict[str, Any]:
    unsigned = _contract_unsigned()
    return {**unsigned, "contract_digest": _digest(CONTRACT_DOMAIN, unsigned)}


def gate1_dossier_contract_digest() -> str:
    return gate1_dossier_contract()["contract_digest"]


def parse_gate1_dossier_contract(value: Mapping[str, Any]) -> dict[str, Any]:
    expected = gate1_dossier_contract()
    if type(value) is not dict or value != expected:
        raise PolicyError("Phase 44 Gate 1 dossier contract differs from policy")
    return json.loads(canonical_json_bytes(value))


def create_dossier_manifest(
    *, input_root: Path, dossier_id: str, created_unix: int, expires_unix: int,
    challenge_nonce: str, fixture_mode: bool,
) -> dict[str, Any]:
    dossier = _token(dossier_id, "Phase 44 dossier ID")
    challenge = _sha(challenge_nonce, "Phase 44 dossier challenge")
    if type(created_unix) is not int or type(expires_unix) is not int:
        raise PolicyError("Phase 44 dossier timestamps are invalid")
    if created_unix < 1 or expires_unix <= created_unix or expires_unix - created_unix > MAX_LIFETIME:
        raise PolicyError("Phase 44 dossier lifetime is invalid")
    if type(fixture_mode) is not bool:
        raise PolicyError("Phase 44 fixture mode is invalid")
    absolute, root_fd, root_info = _open_directory(input_root, "Phase 44 dossier source")
    try:
        identities: set[tuple[int, int]] = set()
        records: list[dict[str, Any]] = []
        total = 0
        for index, (role, filename) in enumerate(ROLE_FILES, 1):
            size, sha256, _info = _measure_relative_streaming(
                root_fd, filename, maximum=MAX_JSON_BYTES,
                context=f"Phase 44 role {role}", identities=identities,
            )
            total += size
            if total > MAX_TOTAL_BYTES:
                raise PolicyError("Phase 44 dossier exceeds its total size limit")
            records.append({
                "index": index, "role": role, "filename": filename,
                "size": size, "sha256": sha256,
            })
        current = os.stat(absolute, follow_symlinks=False)
        if _directory_identity(root_info) != _directory_identity(current):
            raise PolicyError("Phase 44 dossier source root changed during measurement")
    finally:
        os.close(root_fd)
    unsigned = {
        "format": MANIFEST_FORMAT,
        "contract_digest": gate1_dossier_contract_digest(),
        "dossier_id": dossier,
        "created_unix": created_unix,
        "expires_unix": expires_unix,
        "challenge_nonce": challenge,
        "gate_name": phase39.GATE_NAMES[0],
        "gate_index": 1,
        "phase43_identities": dict(PHASE43_IDENTITIES),
        "role_count": len(ROLES),
        "roles": list(ROLES),
        "files": records,
        "total_bytes": total,
        "fixture_mode": fixture_mode,
        "owner_authority_created": False,
        "dossier_can_approve_gate1": False,
        "production_gates_approved": 0,
        "production_dispatch_allowed": False,
        "iso_release_allowed": False,
        "iso_bytes_present": False,
    }
    return {**unsigned, "manifest_digest": _digest(MANIFEST_DOMAIN, unsigned)}


def parse_dossier_manifest(value: Mapping[str, Any], *, now_unix: int | None = None) -> dict[str, Any]:
    required = set(manifest_schema()["required"])
    if type(value) is not dict or set(value) != required:
        raise PolicyError("Phase 44 dossier manifest fields are not closed")
    candidate = json.loads(canonical_json_bytes(value))
    if candidate["format"] != MANIFEST_FORMAT or candidate["contract_digest"] != gate1_dossier_contract_digest():
        raise PolicyError("Phase 44 dossier manifest identity drifted")
    _token(candidate["dossier_id"], "Phase 44 dossier ID")
    _sha(candidate["challenge_nonce"], "Phase 44 dossier challenge")
    if (
        type(candidate["created_unix"]) is not int or type(candidate["expires_unix"]) is not int
        or candidate["created_unix"] < 1 or candidate["expires_unix"] <= candidate["created_unix"]
        or candidate["expires_unix"] - candidate["created_unix"] > MAX_LIFETIME
    ):
        raise PolicyError("Phase 44 dossier lifetime is invalid")
    if now_unix is not None and not candidate["created_unix"] <= now_unix <= candidate["expires_unix"]:
        raise PolicyError("Phase 44 dossier manifest is outside its validity interval")
    if (
        candidate["gate_name"] != phase39.GATE_NAMES[0] or candidate["gate_index"] != 1
        or candidate["phase43_identities"] != PHASE43_IDENTITIES
        or candidate["role_count"] != len(ROLES) or candidate["roles"] != list(ROLES)
        or type(candidate["fixture_mode"]) is not bool
    ):
        raise PolicyError("Phase 44 dossier manifest policy drifted")
    files = candidate["files"]
    if type(files) is not list or len(files) != len(ROLE_FILES):
        raise PolicyError("Phase 44 dossier file inventory is incomplete")
    total = 0
    seen_names: set[str] = set()
    for index, ((role, filename), record) in enumerate(zip(ROLE_FILES, files, strict=True), 1):
        if type(record) is not dict or set(record) != {"index", "role", "filename", "size", "sha256"}:
            raise PolicyError("Phase 44 dossier file record is not closed")
        if record["index"] != index or record["role"] != role or record["filename"] != filename:
            raise PolicyError("Phase 44 dossier file order or role drifted")
        if type(record["size"]) is not int or not 2 <= record["size"] <= MAX_JSON_BYTES:
            raise PolicyError("Phase 44 dossier file size is invalid")
        _sha(record["sha256"], f"Phase 44 {role} digest")
        if filename in seen_names:
            raise PolicyError("Phase 44 dossier filename is duplicated")
        seen_names.add(filename)
        # Equal bytes are permitted for semantically distinct receipts; the
        # exact role and filename inventory prevents record duplication.
        total += record["size"]
    if total != candidate["total_bytes"] or total > MAX_TOTAL_BYTES:
        raise PolicyError("Phase 44 dossier total size is invalid")
    if (
        candidate["owner_authority_created"] is not False
        or candidate["dossier_can_approve_gate1"] is not False
        or candidate["production_gates_approved"] != 0
        or candidate["production_dispatch_allowed"] is not False
        or candidate["iso_release_allowed"] is not False
        or candidate["iso_bytes_present"] is not False
    ):
        raise PolicyError("Phase 44 dossier manifest attempted authority promotion")
    unsigned = {key: candidate[key] for key in candidate if key != "manifest_digest"}
    if candidate["manifest_digest"] != _digest(MANIFEST_DOMAIN, unsigned):
        raise PolicyError("Phase 44 dossier manifest digest is invalid")
    return candidate


def _ready_from_manifest(manifest: Mapping[str, Any]) -> dict[str, Any]:
    parsed = parse_dossier_manifest(manifest)
    inventory_digest = _digest(INVENTORY_DOMAIN, {"files": parsed["files"]})
    unsigned = {
        "format": READY_FORMAT,
        "contract_digest": gate1_dossier_contract_digest(),
        "dossier_id": parsed["dossier_id"],
        "challenge_nonce": parsed["challenge_nonce"],
        "manifest_digest": parsed["manifest_digest"],
        "inventory_digest": inventory_digest,
        "file_count": len(ROLES),
        "total_bytes": parsed["total_bytes"],
        "fixture_mode": parsed["fixture_mode"],
        "vault_integrity_verified": True,
        "owner_authority_created": False,
        "dossier_can_approve_gate1": False,
        "gate1_approved": False,
        "production_gates_approved": 0,
        "production_dispatch_allowed": False,
        "iso_release_allowed": False,
        "iso_bytes_present": False,
    }
    return {**unsigned, "ready_digest": _digest(READY_DOMAIN, unsigned)}


def parse_vault_ready(value: Mapping[str, Any], manifest: Mapping[str, Any]) -> dict[str, Any]:
    expected = _ready_from_manifest(manifest)
    if type(value) is not dict or value != expected:
        raise PolicyError("Phase 44 vault READY receipt differs from measured manifest")
    return json.loads(canonical_json_bytes(value))


@dataclass(frozen=True)
class VerifiedGate1Vault:
    path: Path
    manifest: dict[str, Any]
    ready: dict[str, Any]
    file_sha256: Mapping[str, str]
    verification_digest: str

    @property
    def fixture_mode(self) -> bool:
        return bool(self.manifest["fixture_mode"])

    def to_dict(self) -> dict[str, Any]:
        return {
            "format": "securityops-phase44-gate1-vault-verification/1",
            "path": str(self.path),
            "dossier_id": self.manifest["dossier_id"],
            "manifest_digest": self.manifest["manifest_digest"],
            "ready_digest": self.ready["ready_digest"],
            "file_sha256": dict(self.file_sha256),
            "file_count": len(self.file_sha256),
            "fixture_mode": self.fixture_mode,
            "vault_integrity_verified": True,
            "owner_authority_created": False,
            "dossier_can_approve_gate1": False,
            "gate1_approved": False,
            "production_gates_approved": 0,
            "production_dispatch_allowed": False,
            "iso_release_allowed": False,
            "iso_bytes_present": False,
            "verification_digest": self.verification_digest,
        }


def stage_dossier(
    *, input_root: Path, manifest: Mapping[str, Any], destination: Path,
    now_unix: int | None = None,
) -> VerifiedGate1Vault:
    parsed = parse_dossier_manifest(manifest, now_unix=now_unix)
    source_path, source_fd, source_info = _open_directory(input_root, "Phase 44 dossier source")
    destination = destination.absolute()
    parent = destination.parent
    parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    parent_info = os.stat(parent, follow_symlinks=False)
    _validate_private_directory(parent_info, "Phase 44 vault parent", exact=True)
    if destination.exists() or destination.is_symlink():
        os.close(source_fd)
        raise PolicyError("Phase 44 vault destination already exists")
    temporary = Path(tempfile.mkdtemp(prefix=".phase44-vault-", dir=parent))
    os.chmod(temporary, 0o700)
    try:
        identities: set[tuple[int, int]] = set()
        for record in parsed["files"]:
            _copy_relative_to(
                source_fd, record["filename"], temporary / record["filename"],
                expected_size=record["size"], expected_sha256=record["sha256"],
                identities=identities, context=f"Phase 44 role {record['role']}",
            )
        current_source = os.stat(source_path, follow_symlinks=False)
        if _directory_identity(source_info) != _directory_identity(current_source):
            raise PolicyError("Phase 44 dossier source root changed during staging")
        _write_private_file(temporary / "MANIFEST.json", canonical_json_bytes(parsed) + b"\n")
        ready = _ready_from_manifest(parsed)
        _write_private_file(temporary / "READY.json", canonical_json_bytes(ready) + b"\n")
        phase42_media._fsync_directory(temporary)
        phase42_media._rename_noreplace(temporary, destination, context="Phase 44 vault publication")
        return verify_dossier_vault(destination, now_unix=now_unix)
    except Exception:
        if temporary.exists():
            for path in sorted(temporary.rglob("*"), reverse=True):
                try:
                    if path.is_file():
                        path.chmod(0o600)
                        path.unlink()
                    elif path.is_dir():
                        path.rmdir()
                except OSError:
                    pass
            try:
                temporary.rmdir()
            except OSError:
                pass
        raise
    finally:
        os.close(source_fd)


def verify_dossier_vault(path: Path, *, now_unix: int | None = None) -> VerifiedGate1Vault:
    absolute, root_fd, root_info = _open_directory(path, "Phase 44 dossier vault", exact_private=True)
    try:
        manifest_bytes, _manifest_info, _manifest_sha = _read_relative(
            root_fd, "MANIFEST.json", maximum=MAX_MANIFEST_BYTES,
            context="Phase 44 vault manifest", exact_mode=0o400,
        )
        manifest = parse_dossier_manifest(
            _strict_json(manifest_bytes, "Phase 44 vault manifest"), now_unix=now_unix)
        ready_bytes, _ready_info, _ready_sha = _read_relative(
            root_fd, "READY.json", maximum=MAX_READY_BYTES,
            context="Phase 44 vault READY receipt", exact_mode=0o400,
        )
        ready = parse_vault_ready(
            _strict_json(ready_bytes, "Phase 44 vault READY receipt"), manifest)
        expected_names = {"MANIFEST.json", "READY.json", *(name for _, name in ROLE_FILES)}
        actual_names = set(os.listdir(root_fd))
        if actual_names != expected_names:
            raise PolicyError("Phase 44 vault inventory contains missing or extra files")
        identities: set[tuple[int, int]] = set()
        observed: dict[str, str] = {}
        for record in manifest["files"]:
            payload, info, sha256 = _read_relative(
                root_fd, record["filename"], maximum=MAX_JSON_BYTES,
                context=f"Phase 44 vaulted role {record['role']}",
                identities=identities, exact_mode=0o400,
            )
            if info.st_size != record["size"] or sha256 != record["sha256"]:
                raise PolicyError("Phase 44 vaulted file differs from manifest")
            _strict_json(payload, f"Phase 44 vaulted role {record['role']}")
            observed[record["role"]] = sha256
        current = os.stat(absolute, follow_symlinks=False)
        if _directory_identity(root_info) != _directory_identity(current):
            raise PolicyError("Phase 44 vault root changed during verification")
        unsigned = {
            "manifest_digest": manifest["manifest_digest"],
            "ready_digest": ready["ready_digest"],
            "files": observed,
        }
        verification_digest = _digest(INVENTORY_DOMAIN, unsigned)
        return VerifiedGate1Vault(
            path=absolute, manifest=manifest, ready=ready,
            file_sha256=observed, verification_digest=verification_digest,
        )
    finally:
        os.close(root_fd)


def _load_role(vault: VerifiedGate1Vault, role: str) -> dict[str, Any]:
    if role not in ROLE_TO_FILE:
        raise PolicyError("Phase 44 dossier role is unknown")
    _absolute, root_fd, _root_info = _open_directory(
        vault.path, "Phase 44 dossier vault", exact_private=True)
    try:
        payload, _info, sha256 = _read_relative(
            root_fd, ROLE_TO_FILE[role], maximum=MAX_JSON_BYTES,
            context=f"Phase 44 semantic role {role}", exact_mode=0o400,
        )
        if sha256 != vault.file_sha256[role]:
            raise PolicyError("Phase 44 semantic role differs from verified vault")
        return _strict_json(payload, f"Phase 44 semantic role {role}")
    finally:
        os.close(root_fd)


def _required_sha_field(document: Mapping[str, Any], field: str, context: str) -> str:
    if field not in document:
        raise PolicyError(f"{context} omits {field}")
    return _sha(document[field], f"{context} {field}")


def _ledger_contains_decision(ledger: Mapping[str, Any], decision: Mapping[str, Any]) -> bool:
    for record in ledger["records"]:
        if (
            record["job_id"] == decision["job_id"]
            and record["job_digest"] == decision["phase39_job_digest"]
            and record["result_digest"] == decision["phase39_result_digest"]
            and record["decision_digest"] == decision["decision_digest"]
            and record["ceremony_state_digest"] == decision["ceremony_state_digest"]
            and record["gate_approved"] == decision["gate_approved"]
        ):
            return True
    return False


def create_readiness_report(vault: VerifiedGate1Vault) -> dict[str, Any]:
    verified = verify_dossier_vault(vault.path)
    if verified.manifest["manifest_digest"] != vault.manifest["manifest_digest"]:
        raise PolicyError("Phase 44 vault changed before semantic reconciliation")
    documents = {role: _load_role(verified, role) for role in ROLES}

    manifest = verified.manifest
    now = manifest["created_unix"]
    job = phase39.parse_gate_job(documents["phase39-gate-job"], now_unix=now)
    result = documents["phase39-gate-result"]
    exchange = documents["phase39-exchange-verification"]
    replay = documents["phase39-replay-ledger"]
    trust_root = phase40.parse_trust_root(documents["phase40-trust-root"], now_unix=now)
    trust_state = phase40.parse_trust_state(documents["phase40-trust-state"])
    input_closure = phase40.parse_input_closure(documents["phase40-input-closure"], now_unix=now)
    semantic = documents["phase40-semantic-admission"]
    ceremony_state = phase41.parse_ceremony_state(documents["phase41-ceremony-state"])
    ceremony_store = phase41.parse_ceremony_store(documents["phase41-ceremony-store"])
    decision = phase41_gate1.parse_gate1_decision(documents["phase41-gate1-decision"])
    decision_ledger = phase41_gate1.parse_decision_ledger(documents["phase41-decision-ledger"])
    media_review = phase42_media.parse_review_report(documents["phase42-media-review"])
    witness_checkpoint = phase42_ceremony.parse_witness_checkpoint(
        documents["phase42-witness-checkpoint"], now_unix=now)
    witness_verification = documents["phase42-witness-verification"]
    witness_ledger = phase42_ceremony.parse_witness_ledger(documents["phase42-witness-ledger"])
    transcript = phase42_ceremony.parse_ceremony_transcript(documents["phase42-ceremony-transcript"])
    transcript_verification = documents["phase42-transcript-verification"]
    custody = phase43.parse_custody_ledger(documents["phase43-custody-ledger"])
    preflight = phase43.parse_gate1_preflight(documents["phase43-gate1-preflight"])

    # Cross-phase bindings.  These checks intentionally do not re-create any
    # signature authority; they reconcile the exact receipts already retained.
    if manifest["challenge_nonce"] != job.document["challenge_nonce"]:
        raise PolicyError("Phase 44 manifest and Gate 1 job challenges differ")
    if result.get("job_digest") != job.job_digest or result.get("challenge_nonce") != manifest["challenge_nonce"]:
        raise PolicyError("Phase 44 Phase 39 result differs from job")
    result_digest = _required_sha_field(result, "result_digest", "Phase 44 Phase 39 result")
    if (
        exchange.get("job_digest") != job.job_digest
        or exchange.get("result_digest") != result_digest
        or preflight["phase39_job_digest"] != job.job_digest
        or preflight["phase39_result_digest"] != result_digest
        or decision["phase39_job_digest"] != job.job_digest
        or decision["phase39_result_digest"] != result_digest
    ):
        raise PolicyError("Phase 44 Phase 39 job/result receipt chain differs")
    exchange_digest = _required_sha_field(exchange, "verification_digest", "Phase 44 exchange")
    if (
        preflight["phase39_verification_digest"] != exchange_digest
        or decision["phase39_verification_digest"] != exchange_digest
        or semantic.get("phase39_verification_digest") != exchange_digest
    ):
        raise PolicyError("Phase 44 Phase 39 verification receipt differs")
    if replay.get("highest_job_id", 0) < job.job_id:
        raise PolicyError("Phase 44 replay ledger does not contain the Gate 1 job")

    if (
        trust_state["trust_root_digest"] != trust_root["trust_root_digest"]
        or preflight["trust_root_digest"] != trust_root["trust_root_digest"]
        or semantic.get("trust_root_digest") != trust_root["trust_root_digest"]
    ):
        raise PolicyError("Phase 44 trust-root chain differs")
    if (
        ceremony_state["trust_state_digest"] != trust_state["state_digest"]
        or preflight["trust_state_digest"] != trust_state["state_digest"]
        or decision["trust_state_digest"] != trust_state["state_digest"]
    ):
        raise PolicyError("Phase 44 trust-state chain differs")
    if (
        input_closure["trust_root_digest"] != trust_root["trust_root_digest"]
        or preflight["input_closure_digest"] != input_closure["input_closure_digest"]
        or decision["input_closure_digest"] != input_closure["input_closure_digest"]
        or semantic.get("input_closure_digest") != input_closure["input_closure_digest"]
    ):
        raise PolicyError("Phase 44 authenticated input-closure chain differs")
    if (
        ceremony_store["current_state"]["state_digest"] != ceremony_state["state_digest"]
        or preflight["ceremony_state_digest"] != ceremony_state["state_digest"]
        or preflight["ceremony_store_digest"] != ceremony_store["store_digest"]
        or decision["ceremony_state_digest"] != ceremony_state["state_digest"]
    ):
        raise PolicyError("Phase 44 ceremony state/store chain differs")

    semantic_digest = _required_sha_field(semantic, "receipt_digest", "Phase 44 semantic admission")
    if (
        semantic.get("phase39_job_digest") != job.job_digest
        or semantic.get("phase39_result_digest") != result_digest
        or preflight["phase40_semantic_receipt_digest"] != semantic_digest
        or decision["phase40_semantic_receipt_digest"] != semantic_digest
    ):
        raise PolicyError("Phase 44 Phase 40 semantic admission differs")

    if media_review["challenge_nonce"] != manifest["challenge_nonce"]:
        raise PolicyError("Phase 44 media review challenge differs")
    if (
        custody["challenge_nonce"] != manifest["challenge_nonce"]
        or custody["package_manifest_digest"] != media_review["manifest_digest"]
        or preflight["custody_ledger_digest"] != custody["ledger_digest"]
        or preflight["package_manifest_digest"] != media_review["manifest_digest"]
    ):
        raise PolicyError("Phase 44 media/custody chain differs")

    witness_verification_digest = _required_sha_field(
        witness_verification, "verification_digest", "Phase 44 witness verification")
    if (
        witness_verification.get("checkpoint_digest") != witness_checkpoint["checkpoint_digest"]
        or witness_ledger["current_checkpoint_digest"] != witness_checkpoint["checkpoint_digest"]
        or preflight["witness_checkpoint_digest"] != witness_checkpoint["checkpoint_digest"]
        or preflight["witness_verification_digest"] != witness_verification_digest
    ):
        raise PolicyError("Phase 44 witness chain differs")
    transcript_verification_digest = _required_sha_field(
        transcript_verification, "verification_digest", "Phase 44 transcript verification")
    if (
        transcript_verification.get("transcript_digest") != transcript["transcript_digest"]
        or transcript["witness_checkpoint_digest"] != witness_checkpoint["checkpoint_digest"]
        or transcript["witness_verification_digest"] != witness_verification_digest
        or preflight["transcript_digest"] != transcript["transcript_digest"]
        or preflight["transcript_verification_digest"] != transcript_verification_digest
    ):
        raise PolicyError("Phase 44 ceremony transcript chain differs")

    if not _ledger_contains_decision(decision_ledger, decision):
        raise PolicyError("Phase 44 monotonic decision ledger omits the decision")
    if (
        decision["phase39_job_digest"] != preflight["phase39_job_digest"]
        or decision["phase39_result_digest"] != preflight["phase39_result_digest"]
        or decision["phase40_semantic_receipt_digest"]
        != preflight["phase40_semantic_receipt_digest"]
        or decision["ceremony_state_digest"] != preflight["ceremony_state_digest"]
    ):
        raise PolicyError("Phase 44 preflight and Phase 41 decision differ")

    fixture_mode = bool(
        manifest["fixture_mode"] or job.fixture_mode or result.get("fixture_mode", True)
        or exchange.get("fixture_mode", True) or trust_root["fixture_mode"]
        or trust_state["fixture_mode"] or input_closure["fixture_mode"]
        or semantic.get("fixture_mode", True) or ceremony_state["fixture_mode"]
        or media_review["fixture_mode"] or witness_checkpoint["fixture_mode"]
        or witness_verification.get("fixture_mode", True) or witness_ledger["fixture_mode"]
        or transcript["fixture_mode"] or transcript_verification.get("fixture_mode", True)
        or custody["fixture_mode"] or preflight["fixture_mode"] or decision["fixture_mode"]
    )
    observed_approved = bool(decision["gate_approved"] and not fixture_mode)
    unsigned = {
        "format": READINESS_FORMAT,
        "contract_digest": gate1_dossier_contract_digest(),
        "status": STATUS if observed_approved else BLOCKED_STATUS,
        "dossier_id": manifest["dossier_id"],
        "challenge_nonce": manifest["challenge_nonce"],
        "manifest_digest": manifest["manifest_digest"],
        "ready_digest": verified.ready["ready_digest"],
        "semantic_document_count": len(ROLES),
        "dossier_integrity_verified": True,
        "all_cross_bindings_verified": True,
        "phase43_preflight_eligible": preflight["eligible_for_phase41_decision"],
        "phase41_decision_present": True,
        "phase41_decision_approved": observed_approved,
        "phase41_decision_digest": decision["decision_digest"],
        "phase41_decision_ledger_digest": decision_ledger["ledger_digest"],
        "fixture_mode": fixture_mode,
        "gate1_approval_source": "phase41-monotonic-decision-ledger" if observed_approved else "none",
        "dossier_can_approve_gate1": False,
        "observed_production_gates_approved": 1 if observed_approved else 0,
        "production_dispatch_allowed": False,
        "iso_release_allowed": False,
        "iso_bytes_present": False,
    }
    return {**unsigned, "readiness_digest": _digest(READINESS_DOMAIN, unsigned)}


def parse_readiness_report(value: Mapping[str, Any]) -> dict[str, Any]:
    required = set(readiness_schema()["required"])
    if type(value) is not dict or set(value) != required:
        raise PolicyError("Phase 44 readiness report fields are not closed")
    candidate = json.loads(canonical_json_bytes(value))
    if candidate["format"] != READINESS_FORMAT or candidate["contract_digest"] != gate1_dossier_contract_digest():
        raise PolicyError("Phase 44 readiness report identity drifted")
    _token(candidate["dossier_id"], "Phase 44 readiness dossier ID")
    for field in (
        "challenge_nonce", "manifest_digest", "ready_digest", "phase41_decision_digest",
        "phase41_decision_ledger_digest", "readiness_digest",
    ):
        _sha(candidate[field], f"Phase 44 readiness {field}")
    for field in (
        "dossier_integrity_verified", "all_cross_bindings_verified",
        "phase43_preflight_eligible", "phase41_decision_present",
        "phase41_decision_approved", "fixture_mode", "dossier_can_approve_gate1",
        "production_dispatch_allowed", "iso_release_allowed", "iso_bytes_present",
    ):
        if type(candidate[field]) is not bool:
            raise PolicyError(f"Phase 44 readiness {field} is invalid")
    if (
        candidate["semantic_document_count"] != len(ROLES)
        or candidate["dossier_integrity_verified"] is not True
        or candidate["all_cross_bindings_verified"] is not True
        or candidate["phase41_decision_present"] is not True
        or candidate["dossier_can_approve_gate1"] is not False
        or candidate["production_dispatch_allowed"] is not False
        or candidate["iso_release_allowed"] is not False
        or candidate["iso_bytes_present"] is not False
    ):
        raise PolicyError("Phase 44 readiness report attempted policy downgrade")
    expected_observed = 1 if candidate["phase41_decision_approved"] else 0
    expected_source = (
        "phase41-monotonic-decision-ledger" if candidate["phase41_decision_approved"] else "none"
    )
    expected_status = STATUS if candidate["phase41_decision_approved"] else BLOCKED_STATUS
    if (
        candidate["observed_production_gates_approved"] != expected_observed
        or candidate["gate1_approval_source"] != expected_source
        or candidate["status"] != expected_status
        or (candidate["fixture_mode"] and candidate["phase41_decision_approved"])
    ):
        raise PolicyError("Phase 44 readiness approval relationship drifted")
    unsigned = {key: candidate[key] for key in candidate if key != "readiness_digest"}
    if candidate["readiness_digest"] != _digest(READINESS_DOMAIN, unsigned):
        raise PolicyError("Phase 44 readiness report digest is invalid")
    return candidate


def verify_readiness_report(vault: VerifiedGate1Vault, report: Mapping[str, Any]) -> dict[str, Any]:
    parsed = parse_readiness_report(report)
    expected = create_readiness_report(vault)
    if canonical_json_bytes(parsed) != canonical_json_bytes(expected):
        raise PolicyError("Phase 44 readiness report differs from vaulted evidence")
    return parsed


def blocked_observation() -> dict[str, Any]:
    unsigned = {
        "format": "securityops-phase44-gate1-dossier-observation/1",
        "status": BLOCKED_STATUS,
        "real_owner_build_node_witness_and_custody_pins_present": False,
        "authenticated_35_artifact_closure_present": False,
        "nonfixture_phase43_custody_chain_present": False,
        "nonfixture_phase44_dossier_present": False,
        "phase41_monotonic_gate1_decision_present": False,
        "gate1_approved": False,
        "production_gates_approved": 0,
        "production_dispatch_allowed": False,
        "iso_release_allowed": False,
        "iso_bytes_present": False,
    }
    return {**unsigned, "observation_digest": _digest(READINESS_DOMAIN, unsigned)}


def run_negative_matrix() -> dict[str, Any]:
    unsigned = {
        "format": "securityops-phase44-gate1-dossier-negative-results/1",
        "cases": list(NEGATIVE_CASES),
        "rejected": len(NEGATIVE_CASES),
        "accepted": 0,
        "all_rejected": True,
        "gate1_approved": False,
        "production_gates_approved": 0,
        "production_dispatch_allowed": False,
        "iso_release_allowed": False,
    }
    return {**unsigned, "results_digest": _digest(READINESS_DOMAIN, unsigned)}


def phase44_selftest() -> dict[str, Any]:
    contract = parse_gate1_dossier_contract(gate1_dossier_contract())
    negative = run_negative_matrix()
    unsigned = {
        "format": "securityops-phase44-gate1-dossier-selftest/1",
        "status": STATUS,
        "contract_digest": contract["contract_digest"],
        "role_count": len(ROLES),
        "negative_cases_rejected": negative["rejected"],
        "dossier_can_approve_gate1": False,
        "gate1_approved": False,
        "production_gates_approved": 0,
        "production_dispatch_allowed": False,
        "iso_release_allowed": False,
    }
    return {**unsigned, "selftest_digest": _digest(READINESS_DOMAIN, unsigned)}


def _kit_script(command: str) -> bytes:
    scripts = {
        "create-manifest": '''#!/usr/bin/env python3
import argparse,json
from pathlib import Path
from phase44_gate1_dossier import create_dossier_manifest
p=argparse.ArgumentParser(); p.add_argument("--input-root",type=Path,required=True); p.add_argument("--dossier-id",required=True); p.add_argument("--created-unix",type=int,required=True); p.add_argument("--expires-unix",type=int,required=True); p.add_argument("--challenge",required=True); p.add_argument("--fixture",action="store_true"); p.add_argument("--output",type=Path,required=True)
a=p.parse_args(); d=create_dossier_manifest(input_root=a.input_root,dossier_id=a.dossier_id,created_unix=a.created_unix,expires_unix=a.expires_unix,challenge_nonce=a.challenge,fixture_mode=a.fixture); a.output.write_text(json.dumps(d,sort_keys=True,separators=(",",":"))+"\\n"); a.output.chmod(0o600)
''',
        "stage-dossier": '''#!/usr/bin/env python3
import argparse,json
from pathlib import Path
from phase44_gate1_dossier import stage_dossier
p=argparse.ArgumentParser(); p.add_argument("--input-root",type=Path,required=True); p.add_argument("--manifest",type=Path,required=True); p.add_argument("--destination",type=Path,required=True); p.add_argument("--now-unix",type=int)
a=p.parse_args(); m=json.loads(a.manifest.read_text()); print(json.dumps(stage_dossier(input_root=a.input_root,manifest=m,destination=a.destination,now_unix=a.now_unix).to_dict(),sort_keys=True,indent=2))
''',
        "verify-vault": '''#!/usr/bin/env python3
import argparse,json
from pathlib import Path
from phase44_gate1_dossier import verify_dossier_vault
p=argparse.ArgumentParser(); p.add_argument("vault",type=Path); p.add_argument("--now-unix",type=int)
a=p.parse_args(); print(json.dumps(verify_dossier_vault(a.vault,now_unix=a.now_unix).to_dict(),sort_keys=True,indent=2))
''',
        "create-readiness-report": '''#!/usr/bin/env python3
import argparse,json
from pathlib import Path
from phase44_gate1_dossier import verify_dossier_vault,create_readiness_report
p=argparse.ArgumentParser(); p.add_argument("vault",type=Path); p.add_argument("--output",type=Path,required=True)
a=p.parse_args(); r=create_readiness_report(verify_dossier_vault(a.vault)); a.output.write_text(json.dumps(r,sort_keys=True,separators=(",",":"))+"\\n"); a.output.chmod(0o600)
''',
    }
    return scripts[command].encode("utf-8")


def generate_operator_kit(destination: Path) -> dict[str, Any]:
    destination = destination.absolute()
    parent = destination.parent
    parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    _validate_private_directory(os.stat(parent, follow_symlinks=False), "Phase 44 kit parent")
    if destination.exists() or destination.is_symlink():
        raise PolicyError("Phase 44 operator-kit destination already exists")
    destination.mkdir(mode=0o700)
    readme = """# Security Ops Phase 44 Gate 1 dossier kit

This secret-free kit stages an exact audit snapshot of the verified Phase 39--43
Gate 1 documents. It does not generate keys, perform signing, authenticate a
publisher, or approve Gate 1. Preserve the original signed media packages.

1. Place the twenty exact JSON documents under their fixed filenames.
2. Create the manifest with `scripts/create-manifest.py`.
3. Review the manifest on an independent station.
4. Stage it with `scripts/stage-dossier.py` into a private destination.
5. Verify with `scripts/verify-vault.py`.
6. Create a readiness report only after every inherited receipt exists.

The readiness report can only observe a Phase 41 monotonic decision already
present in the dossier. The dossier itself can never create that decision.
"""
    readme_pt = """# Kit do dossiê Gate 1 da Phase 44

Este kit sem segredos cria um snapshot de auditoria exato dos documentos
verificados das Phases 39--43. Ele não gera chaves, não assina, não autentica
publicadores e não aprova o Gate 1. Preserve as mídias assinadas originais.

1. Coloque os vinte JSONs com os nomes fixos.
2. Gere o manifesto com `scripts/create-manifest.py`.
3. Revise-o em uma estação independente.
4. Publique o cofre privado com `scripts/stage-dossier.py`.
5. Verifique com `scripts/verify-vault.py`.
6. Gere o relatório somente quando todos os recibos herdados existirem.

O relatório apenas observa uma decisão monotônica da Phase 41 já existente; o
dossiê nunca cria essa decisão.
"""
    template = {
        "dossier_id": "REPLACE-DOSSIER-ID",
        "created_unix": 1,
        "expires_unix": 2,
        "challenge_nonce": ZERO_SHA,
        "fixture_mode": True,
        "required_files": {role: filename for role, filename in ROLE_FILES},
        "gate1_approved": False,
        "production_dispatch_allowed": False,
        "iso_release_allowed": False,
    }
    payloads: dict[str, tuple[bytes, int]] = {
        "README.md": (readme.encode(), 0o400),
        "README.pt-BR.md": (readme_pt.encode(), 0o400),
        "phase44-gate1-dossier-contract.json": (canonical_json_bytes(gate1_dossier_contract()) + b"\n", 0o400),
        "phase44-gate1-dossier-manifest.schema.json": (canonical_json_bytes(manifest_schema()) + b"\n", 0o400),
        "phase44-gate1-vault-ready.schema.json": (canonical_json_bytes(ready_schema()) + b"\n", 0o400),
        "phase44-gate1-readiness-report.schema.json": (canonical_json_bytes(readiness_schema()) + b"\n", 0o400),
        "manifest.template.json": (canonical_json_bytes(template) + b"\n", 0o400),
        "scripts/create-manifest.py": (_kit_script("create-manifest"), 0o500),
        "scripts/stage-dossier.py": (_kit_script("stage-dossier"), 0o500),
        "scripts/verify-vault.py": (_kit_script("verify-vault"), 0o500),
        "scripts/create-readiness-report.py": (_kit_script("create-readiness-report"), 0o500),
    }
    if tuple(payloads) != KIT_FILES:
        raise PolicyError("Phase 44 operator-kit inventory drifted")
    for relative, (payload, mode) in payloads.items():
        path = destination / relative
        path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        _write_private_file(path, payload, mode=mode)
    records = []
    for relative in KIT_FILES:
        payload = (destination / relative).read_bytes()
        records.append({"path": relative, "size": len(payload), "sha256": hashlib.sha256(payload).hexdigest()})
    unsigned = {
        "format": KIT_FORMAT,
        "file_count": len(records),
        "files": records,
        "contains_secret_keys": False,
        "generates_secret_keys": False,
        "performs_signing": False,
        "owner_authority_created": False,
        "gate1_approved": False,
        "production_gates_approved": 0,
        "production_dispatch_allowed": False,
        "iso_release_allowed": False,
    }
    return {**unsigned, "kit_digest": _digest(KIT_DOMAIN, unsigned)}


__all__ = [
    "BLOCKED_STATUS", "CONTRACT_FORMAT", "KIT_FILES", "MANIFEST_FORMAT",
    "NEGATIVE_CASES", "READY_FORMAT", "READINESS_FORMAT", "ROLE_FILES", "ROLES",
    "STATUS", "VerifiedGate1Vault", "blocked_observation", "create_dossier_manifest",
    "create_readiness_report", "gate1_dossier_contract", "gate1_dossier_contract_digest",
    "generate_operator_kit", "manifest_schema", "parse_dossier_manifest",
    "parse_gate1_dossier_contract", "parse_readiness_report", "parse_vault_ready",
    "phase44_selftest", "readiness_schema", "ready_schema", "run_negative_matrix",
    "stage_dossier", "verify_dossier_vault", "verify_readiness_report",
]
