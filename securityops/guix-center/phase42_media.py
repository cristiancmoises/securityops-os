# CodeMark v1 project=4c63e0fe-589c-4944-8449-97e211a38b72 file=a5e4795fea875963beffc6c99c162d82 owner="Cristian Cezar Mois\u00e9s"
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Deterministic, fail-closed offline-media transport for Phase 42.

The package proves byte integrity and exact profile conformance only.  It does
not prove publisher rights, owner authority, Gate 1, production dispatch, or
ISO release.  Large payloads are streamed through bounded chunks; source and
package paths are never followed through symbolic links.
"""
from __future__ import annotations

from dataclasses import dataclass
import ctypes
import errno
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
    from . import phase40_owner_trust as phase40
except ImportError:  # pragma: no cover - installed Guix Center sibling copy
    import phase40_owner_trust as phase40  # type: ignore[no-redef]

PolicyError = phase40.PolicyError
canonical_json_bytes = phase40.canonical_json_bytes

MANIFEST_FORMAT: Final[str] = "securityops-phase42-offline-media-manifest/1"
READY_FORMAT: Final[str] = "securityops-phase42-offline-media-ready/1"
REVIEW_FORMAT: Final[str] = "securityops-phase42-offline-media-review/1"
VERIFICATION_FORMAT: Final[str] = "securityops-phase42-offline-media-verification/1"
STATUS: Final[str] = "PASS_PHASE42_DETERMINISTIC_OFFLINE_MEDIA_BOUNDARY"
BLOCKED_STATUS: Final[str] = "BLOCKED_PHASE42_MEDIA_INTEGRITY_IS_NOT_OWNER_AUTHORITY"

MANIFEST_DOMAIN: Final[bytes] = b"SECURITYOPS-PHASE42-OFFLINE-MEDIA-MANIFEST-V1\x00"
READY_DOMAIN: Final[bytes] = b"SECURITYOPS-PHASE42-OFFLINE-MEDIA-READY-V1\x00"
REVIEW_DOMAIN: Final[bytes] = b"SECURITYOPS-PHASE42-OFFLINE-MEDIA-REVIEW-V1\x00"
VERIFICATION_DOMAIN: Final[bytes] = b"SECURITYOPS-PHASE42-OFFLINE-MEDIA-VERIFICATION-V1\x00"
MEDIA_INVENTORY_DOMAIN: Final[bytes] = b"SECURITYOPS-PHASE42-MEDIA-INVENTORY-V1\x00"
OBSERVATION_DOMAIN: Final[bytes] = b"SECURITYOPS-PHASE42-MEDIA-OBSERVATION-V1\x00"

PHASE41_IDENTITIES: Final[dict[str, str]] = {
    "runtime_commit": "756d8d55bda234d05576d8afc3fadfc622b2b61f",
    "runtime_tree": "6f51147385bb1623e9c0fbf87877a2f7368144a9",
    "securityops_os_commit": "688993152b8f5c2be397d16235df138b8887527c",
    "securityops_os_tree": "d21dd6a3267295dcaff4e635f19ffdb47568edb6",
    "stable_v1_13_0": "8373fd789c9a525d6128abfd3d7a93ad4db3348b",
}
PHASE41_CEREMONY_CONTRACT_DIGEST: Final[str] = (
    "66af9139b27737bad8b4e8b2756e7bf81691af3491e5022f7db86e09f9aec009"
)
PHASE41_GATE1_CONTRACT_DIGEST: Final[str] = (
    "55bc916ee486e4813109ee825e4a36bdaf7f07e6d8276841bf41fda0a2ec7510"
)

ZERO_SHA: Final[str] = "0" * 64
MAX_PACKAGE_LIFETIME: Final[int] = 30 * 24 * 60 * 60
MAX_MANIFEST_BYTES: Final[int] = 8 * 1024 * 1024
MAX_READY_BYTES: Final[int] = 128 * 1024
MAX_PAYLOAD_BYTES: Final[int] = 4 * 1024 * 1024 * 1024
MAX_CHUNK_BYTES: Final[int] = 64 * 1024 * 1024
MAX_MEDIA_BYTES: Final[int] = 4 * 1024 * 1024 * 1024
MAX_CHUNKS: Final[int] = 65536
MAX_MEDIA: Final[int] = 4096
MAX_ROLES: Final[int] = 32

_SHA = re.compile(r"[0-9a-f]{64}\Z")
_GIT_OBJECT = re.compile(r"[0-9a-f]{40}\Z")
_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_SAFE_NAME = re.compile(r"[a-z0-9][a-z0-9._-]{0,191}\Z")
_CHUNK_NAME = re.compile(r"chunk-[0-9]{2}-[0-9]{5}\.bin\Z")
_MEDIA_NAME = re.compile(r"media-[0-9]{4}\Z")

PACKAGE_PROFILES: Final[dict[str, tuple[tuple[str, str], ...]]] = {
    "initialize-transition": (
        ("transition-document", "01-transition.json"),
        ("next-owner-signature", "02-next-owner.sig"),
        ("next-owner-keyring", "03-next-owner.gpg"),
        ("next-build-node-signature", "04-next-build-node.sig"),
        ("next-build-node-keyring", "05-next-build-node.gpg"),
        ("next-trust-state", "06-next-trust-state.json"),
    ),
    "rotate-owner-transition": (
        ("transition-document", "01-transition.json"),
        ("current-owner-signature", "02-current-owner.sig"),
        ("current-owner-keyring", "03-current-owner.gpg"),
        ("next-owner-signature", "04-next-owner.sig"),
        ("next-owner-keyring", "05-next-owner.gpg"),
        ("previous-ceremony-state", "06-previous-ceremony-state.json"),
        ("previous-trust-state", "07-previous-trust-state.json"),
        ("next-trust-state", "08-next-trust-state.json"),
    ),
    "rotate-build-node-transition": (
        ("transition-document", "01-transition.json"),
        ("current-owner-signature", "02-current-owner.sig"),
        ("current-owner-keyring", "03-current-owner.gpg"),
        ("next-build-node-signature", "04-next-build-node.sig"),
        ("next-build-node-keyring", "05-next-build-node.gpg"),
        ("previous-ceremony-state", "06-previous-ceremony-state.json"),
        ("previous-trust-state", "07-previous-trust-state.json"),
        ("next-trust-state", "08-next-trust-state.json"),
    ),
    "rotate-both-transition": (
        ("transition-document", "01-transition.json"),
        ("current-owner-signature", "02-current-owner.sig"),
        ("current-owner-keyring", "03-current-owner.gpg"),
        ("next-owner-signature", "04-next-owner.sig"),
        ("next-owner-keyring", "05-next-owner.gpg"),
        ("next-build-node-signature", "06-next-build-node.sig"),
        ("next-build-node-keyring", "07-next-build-node.gpg"),
        ("previous-ceremony-state", "08-previous-ceremony-state.json"),
        ("previous-trust-state", "09-previous-trust-state.json"),
        ("next-trust-state", "10-next-trust-state.json"),
    ),
    "revoke-build-node-transition": (
        ("transition-document", "01-transition.json"),
        ("current-owner-signature", "02-current-owner.sig"),
        ("current-owner-keyring", "03-current-owner.gpg"),
        ("previous-ceremony-state", "04-previous-ceremony-state.json"),
        ("previous-trust-state", "05-previous-trust-state.json"),
    ),
    "recover-state-transition": (
        ("transition-document", "01-transition.json"),
        ("current-owner-signature", "02-current-owner.sig"),
        ("current-owner-keyring", "03-current-owner.gpg"),
        ("previous-ceremony-state", "04-previous-ceremony-state.json"),
        ("previous-trust-state", "05-previous-trust-state.json"),
        ("next-trust-state", "06-next-trust-state.json"),
        ("witness-checkpoint", "07-witness-checkpoint.json"),
        ("witness-signature", "08-witness-checkpoint.sig"),
        ("witness-keyring", "09-witness.gpg"),
    ),
    "ceremony-checkpoint": (
        ("ceremony-state", "01-ceremony-state.json"),
        ("ceremony-store", "02-ceremony-store.json"),
        ("trust-state", "03-trust-state.json"),
        ("witness-checkpoint", "04-witness-checkpoint.json"),
        ("witness-signature", "05-witness-checkpoint.sig"),
        ("witness-keyring", "06-witness.gpg"),
    ),
    "gate1-import": (
        ("ceremony-state", "01-ceremony-state.json"),
        ("trust-state", "02-trust-state.json"),
        ("phase39-verified-exchange", "03-phase39-exchange.json"),
        ("phase40-semantic-admission", "04-phase40-semantic-admission.json"),
        ("witness-checkpoint", "05-witness-checkpoint.json"),
        ("witness-signature", "06-witness-checkpoint.sig"),
        ("witness-keyring", "07-witness.gpg"),
    ),
    "signed-transcript": (
        ("ceremony-transcript", "01-ceremony-transcript.json"),
        ("owner-transcript-signature", "02-owner-transcript.sig"),
        ("owner-keyring", "03-owner.gpg"),
        ("witness-transcript-signature", "04-witness-transcript.sig"),
        ("witness-keyring", "05-witness.gpg"),
    ),
}

NEGATIVE_CASES: Final[tuple[str, ...]] = (
    "unknown-profile", "profile-role-removed", "profile-role-reordered",
    "caller-filename-allowed", "manifest-extra-field", "manifest-zero-challenge",
    "manifest-lifetime-unbounded", "manifest-fixture-promotion",
    "manifest-production-promotion", "manifest-iso-promotion",
    "ready-marker-optional", "ready-digest-unbound", "missing-chunk-accepted",
    "extra-chunk-accepted", "duplicate-chunk-filename-accepted",
    "duplicate-source-identity-accepted", "symlink-chunk-accepted",
    "hardlink-chunk-accepted", "chunk-mode-writable", "chunk-truncated",
    "chunk-grown", "package-root-replaced", "media-directory-replaced",
    "destination-overwrite", "non-atomic-publication", "transport-promotes-authority",
    "nondeterministic-chunk-boundary", "nondeterministic-media-placement",
)


def _digest(domain: bytes, value: Mapping[str, Any]) -> str:
    return hashlib.sha256(domain + canonical_json_bytes(value)).hexdigest()


def _sha(value: Any, context: str, *, allow_zero: bool = False) -> str:
    if not isinstance(value, str) or not _SHA.fullmatch(value):
        raise PolicyError(f"{context} must be a lowercase SHA-256 digest")
    if not allow_zero and value == ZERO_SHA:
        raise PolicyError(f"{context} cannot be zero")
    return value


def _token(value: Any, context: str) -> str:
    if not isinstance(value, str) or not _TOKEN.fullmatch(value):
        raise PolicyError(f"{context} is invalid")
    return value


def _strict_json(payload: bytes, context: str) -> dict[str, Any]:
    duplicates: list[str] = []

    def hook(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            if key in result:
                duplicates.append(key)
            result[key] = value
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
    return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink, info.st_uid, info.st_gid)


def _validate_private_directory(info: os.stat_result, context: str) -> None:
    if (
        not stat.S_ISDIR(info.st_mode)
        or stat.S_IMODE(info.st_mode) & 0o022
        or info.st_uid not in {0, os.getuid()}
    ):
        raise PolicyError(f"{context} is not a private directory")


def _safe_private_parent(path: Path, context: str) -> Path:
    parent = path.absolute().parent
    parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    if parent.is_symlink():
        raise PolicyError(f"{context} parent is a symbolic link")
    _validate_private_directory(parent.stat(), f"{context} parent")
    return parent


def _fsync_directory(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0))
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _rename_noreplace(
    source: Path, destination: Path, *, context: str = "Phase 42 publication"
) -> None:
    """Atomically publish within one stable directory without replacement.

    Both names are resolved relative to the same already-open parent directory.
    This avoids a second pathname traversal between admission and publication.
    The destination must not exist, and the kernel must provide
    ``renameat2(RENAME_NOREPLACE)``; there is deliberately no weaker fallback.
    """
    source = source.absolute()
    destination = destination.absolute()
    if source.parent != destination.parent:
        raise PolicyError(f"{context} source and destination must share one parent")
    for name, label in ((source.name, "source"), (destination.name, "destination")):
        if not name or name in {".", ".."} or "/" in name or "\x00" in name:
            raise PolicyError(f"{context} {label} name is invalid")

    parent = source.parent
    flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        parent_fd = os.open(parent, flags)
    except OSError as exc:
        raise PolicyError(f"{context} parent is unavailable") from exc
    try:
        parent_before = os.fstat(parent_fd)
        _validate_private_directory(parent_before, f"{context} parent")
        try:
            parent_path_before = os.stat(parent, follow_symlinks=False)
        except OSError as exc:
            raise PolicyError(f"{context} parent path is unavailable") from exc
        if _directory_identity(parent_before) != _directory_identity(parent_path_before):
            raise PolicyError(f"{context} parent path changed before publication")

        try:
            source_before = os.stat(source.name, dir_fd=parent_fd, follow_symlinks=False)
        except OSError as exc:
            raise PolicyError(f"{context} source is unavailable") from exc
        if not stat.S_ISDIR(source_before.st_mode):
            raise PolicyError(f"{context} source is not a directory")
        try:
            os.stat(destination.name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        except OSError as exc:
            raise PolicyError(f"{context} destination admission failed") from exc
        else:
            raise PolicyError(f"{context} destination already exists")

        libc = ctypes.CDLL(None, use_errno=True)
        renameat2 = getattr(libc, "renameat2", None)
        if renameat2 is None:
            raise PolicyError("Phase 42 requires renameat2(RENAME_NOREPLACE)")
        renameat2.argtypes = [
            ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p,
            ctypes.c_uint,
        ]
        renameat2.restype = ctypes.c_int
        if renameat2(
            parent_fd, os.fsencode(source.name),
            parent_fd, os.fsencode(destination.name), 1,
        ) != 0:
            error = ctypes.get_errno()
            if error in {errno.EEXIST, errno.ENOTEMPTY}:
                raise PolicyError(f"{context} destination already exists")
            raise PolicyError(f"{context} atomic publication failed: errno {error}")
        os.fsync(parent_fd)

        destination_after = os.stat(
            destination.name, dir_fd=parent_fd, follow_symlinks=False
        )
        if _directory_identity(source_before) != _directory_identity(destination_after):
            raise PolicyError(f"{context} published directory identity drifted")
        try:
            os.stat(source.name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise PolicyError(f"{context} source still exists after publication")
        try:
            parent_path_after = os.stat(parent, follow_symlinks=False)
        except OSError as exc:
            raise PolicyError(f"{context} parent path disappeared after publication") from exc
        if _directory_identity(parent_before) != _directory_identity(parent_path_after):
            raise PolicyError(f"{context} parent path changed during publication")
    finally:
        os.close(parent_fd)


def _write_all(fd: int, payload: bytes, context: str) -> None:
    view = memoryview(payload)
    while view:
        count = os.write(fd, view)
        if count <= 0:
            raise PolicyError(f"{context} write did not complete")
        view = view[count:]


def _write_file(path: Path, payload: bytes, mode: int = 0o400) -> None:
    fd = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        mode,
    )
    try:
        os.fchmod(fd, mode)
        _write_all(fd, payload, "Phase 42 file")
        os.fsync(fd)
    finally:
        os.close(fd)


def _measure_relative(
    directory_fd: int,
    filename: str,
    *,
    maximum: int,
    context: str,
    allow_empty: bool = False,
    output_fd: int | None = None,
    aggregate: Any | None = None,
) -> tuple[dict[str, Any], bytes | None]:
    if filename != "READY" and not _SAFE_NAME.fullmatch(filename):
        raise PolicyError(f"{context} filename is invalid")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(filename, flags, dir_fd=directory_fd)
    except OSError as exc:
        raise PolicyError(f"{context} is unavailable") from exc
    try:
        before = os.fstat(fd)
        mode = stat.S_IMODE(before.st_mode)
        minimum = 0 if allow_empty else 1
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_uid not in {0, os.getuid()}
            or mode & 0o222
            or not minimum <= before.st_size <= maximum
        ):
            raise PolicyError(f"{context} has an unsafe identity")
        digest = hashlib.sha256()
        capture = bytearray() if before.st_size <= max(MAX_MANIFEST_BYTES, MAX_READY_BYTES) else None
        remaining = before.st_size
        while remaining:
            block = os.read(fd, min(1024 * 1024, remaining))
            if not block:
                raise PolicyError(f"{context} was truncated")
            digest.update(block)
            if aggregate is not None:
                aggregate.update(block)
            if capture is not None:
                capture.extend(block)
            if output_fd is not None:
                _write_all(output_fd, block, context)
            remaining -= len(block)
        if os.read(fd, 1):
            raise PolicyError(f"{context} grew while measured")
        after = os.fstat(fd)
        if _file_identity(before) != _file_identity(after):
            raise PolicyError(f"{context} changed while measured")
        return {
            "filename": filename, "bytes": after.st_size,
            "sha256": digest.hexdigest(), "mode": mode,
            "device": after.st_dev, "inode": after.st_ino,
        }, None if capture is None else bytes(capture)
    finally:
        os.close(fd)


def manifest_schema() -> dict[str, Any]:
    sha = {"type": "string", "pattern": "^[0-9a-f]{64}$"}
    git_object = {"type": "string", "pattern": "^[0-9a-f]{40}$"}
    chunk = {
        "type": "object", "additionalProperties": False,
        "required": ["index", "media_index", "filename", "bytes", "sha256", "mode"],
        "properties": {
            "index": {"type": "integer", "minimum": 1},
            "media_index": {"type": "integer", "minimum": 1},
            "filename": {"type": "string", "pattern": "^chunk-[0-9]{2}-[0-9]{5}\\.bin$"},
            "bytes": {"type": "integer", "minimum": 1, "maximum": MAX_CHUNK_BYTES},
            "sha256": sha, "mode": {"const": 256},
        },
    }
    payload = {
        "type": "object", "additionalProperties": False,
        "required": ["role", "logical_filename", "bytes", "sha256", "chunk_count", "chunks"],
        "properties": {
            "role": {"type": "string", "minLength": 1, "maxLength": 128},
            "logical_filename": {"type": "string", "minLength": 1, "maxLength": 192},
            "bytes": {"type": "integer", "minimum": 1, "maximum": MAX_PAYLOAD_BYTES},
            "sha256": sha,
            "chunk_count": {"type": "integer", "minimum": 1, "maximum": MAX_CHUNKS},
            "chunks": {"type": "array", "minItems": 1, "maxItems": MAX_CHUNKS, "items": chunk},
        },
    }
    medium = {
        "type": "object", "additionalProperties": False,
        "required": ["index", "directory", "chunk_count", "bytes", "inventory_digest"],
        "properties": {
            "index": {"type": "integer", "minimum": 1},
            "directory": {"type": "string", "pattern": "^media-[0-9]{4}$"},
            "chunk_count": {"type": "integer", "minimum": 1, "maximum": MAX_CHUNKS},
            "bytes": {"type": "integer", "minimum": 1, "maximum": MAX_MEDIA_BYTES},
            "inventory_digest": sha,
        },
    }
    required = [
        "format", "phase41_identities", "phase41_ceremony_contract_digest",
        "phase41_gate1_contract_digest", "profile", "package_sequence",
        "created_unix", "expires_unix", "challenge_nonce", "previous_package_digest",
        "chunk_bytes", "maximum_media_bytes", "payload_count", "payloads",
        "media_count", "media_inventory", "fixture_mode",
        "transport_integrity_is_owner_authority", "transport_integrity_can_close_gate1",
        "production_gates_approved", "production_dispatch_allowed", "iso_release_allowed",
        "manifest_digest",
    ]
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://securityops.co/schemas/guix-center/phase42-offline-media-manifest.schema.json",
        "title": "Security Ops Phase 42 deterministic offline-media manifest",
        "type": "object", "additionalProperties": False, "required": required,
        "properties": {
            "format": {"const": MANIFEST_FORMAT},
            "phase41_identities": {
                "type": "object", "additionalProperties": False,
                "required": list(PHASE41_IDENTITIES),
                "properties": {name: git_object for name in PHASE41_IDENTITIES},
            },
            "phase41_ceremony_contract_digest": sha,
            "phase41_gate1_contract_digest": sha,
            "profile": {"enum": list(PACKAGE_PROFILES)},
            "package_sequence": {"type": "integer", "minimum": 1},
            "created_unix": {"type": "integer", "minimum": 1},
            "expires_unix": {"type": "integer", "minimum": 1},
            "challenge_nonce": sha, "previous_package_digest": sha,
            "chunk_bytes": {"type": "integer", "minimum": 1, "maximum": MAX_CHUNK_BYTES},
            "maximum_media_bytes": {"type": "integer", "minimum": 1, "maximum": MAX_MEDIA_BYTES},
            "payload_count": {"type": "integer", "minimum": 1, "maximum": MAX_ROLES},
            "payloads": {"type": "array", "minItems": 1, "maxItems": MAX_ROLES, "items": payload},
            "media_count": {"type": "integer", "minimum": 1, "maximum": MAX_MEDIA},
            "media_inventory": {"type": "array", "minItems": 1, "maxItems": MAX_MEDIA, "items": medium},
            "fixture_mode": {"type": "boolean"},
            "transport_integrity_is_owner_authority": {"const": False},
            "transport_integrity_can_close_gate1": {"const": False},
            "production_gates_approved": {"const": 0},
            "production_dispatch_allowed": {"const": False},
            "iso_release_allowed": {"const": False}, "manifest_digest": sha,
        },
    }


def ready_schema() -> dict[str, Any]:
    sha = {"type": "string", "pattern": "^[0-9a-f]{64}$"}
    required = [
        "format", "manifest_digest", "challenge_nonce", "media_count",
        "payload_count", "total_chunk_count", "ready_digest",
    ]
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://securityops.co/schemas/guix-center/phase42-offline-media-ready.schema.json",
        "title": "Security Ops Phase 42 atomic READY marker",
        "type": "object", "additionalProperties": False, "required": required,
        "properties": {
            "format": {"const": READY_FORMAT}, "manifest_digest": sha,
            "challenge_nonce": sha,
            "media_count": {"type": "integer", "minimum": 1, "maximum": MAX_MEDIA},
            "payload_count": {"type": "integer", "minimum": 1, "maximum": MAX_ROLES},
            "total_chunk_count": {"type": "integer", "minimum": 1, "maximum": MAX_CHUNKS},
            "ready_digest": sha,
        },
    }


def review_schema() -> dict[str, Any]:
    sha = {"type": "string", "pattern": "^[0-9a-f]{64}$"}
    required = [
        "format", "status", "profile", "manifest_digest", "challenge_nonce",
        "package_sequence", "payload_count", "total_payload_bytes", "total_chunk_count",
        "media_count", "roles", "fixture_mode", "transport_integrity_verified",
        "owner_authority_verified", "gate1_approved", "operator_review_required",
        "production_gates_approved", "production_dispatch_allowed", "iso_release_allowed",
        "review_digest",
    ]
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://securityops.co/schemas/guix-center/phase42-offline-media-review.schema.json",
        "title": "Security Ops Phase 42 deterministic offline review report",
        "type": "object", "additionalProperties": False, "required": required,
        "properties": {
            "format": {"const": REVIEW_FORMAT}, "status": {"const": STATUS},
            "profile": {"enum": list(PACKAGE_PROFILES)}, "manifest_digest": sha,
            "challenge_nonce": sha, "package_sequence": {"type": "integer", "minimum": 1},
            "payload_count": {"type": "integer", "minimum": 1},
            "total_payload_bytes": {"type": "integer", "minimum": 1},
            "total_chunk_count": {"type": "integer", "minimum": 1},
            "media_count": {"type": "integer", "minimum": 1},
            "roles": {"type": "array", "minItems": 1, "items": {"type": "string"}},
            "fixture_mode": {"type": "boolean"},
            "transport_integrity_verified": {"const": True},
            "owner_authority_verified": {"const": False}, "gate1_approved": {"const": False},
            "operator_review_required": {"const": True}, "production_gates_approved": {"const": 0},
            "production_dispatch_allowed": {"const": False}, "iso_release_allowed": {"const": False},
            "review_digest": sha,
        },
    }


def create_manifest(
    *, profile: str, package_sequence: int, created_unix: int, expires_unix: int,
    challenge_nonce: str, previous_package_digest: str, chunk_bytes: int,
    maximum_media_bytes: int, payloads: Sequence[Mapping[str, Any]],
    media_inventory: Sequence[Mapping[str, Any]], fixture_mode: bool,
) -> dict[str, Any]:
    unsigned = {
        "format": MANIFEST_FORMAT, "phase41_identities": dict(PHASE41_IDENTITIES),
        "phase41_ceremony_contract_digest": PHASE41_CEREMONY_CONTRACT_DIGEST,
        "phase41_gate1_contract_digest": PHASE41_GATE1_CONTRACT_DIGEST,
        "profile": profile, "package_sequence": package_sequence,
        "created_unix": created_unix, "expires_unix": expires_unix,
        "challenge_nonce": challenge_nonce, "previous_package_digest": previous_package_digest,
        "chunk_bytes": chunk_bytes, "maximum_media_bytes": maximum_media_bytes,
        "payload_count": len(payloads), "payloads": list(payloads),
        "media_count": len(media_inventory), "media_inventory": list(media_inventory),
        "fixture_mode": fixture_mode, "transport_integrity_is_owner_authority": False,
        "transport_integrity_can_close_gate1": False, "production_gates_approved": 0,
        "production_dispatch_allowed": False, "iso_release_allowed": False,
    }
    value = {**unsigned, "manifest_digest": _digest(MANIFEST_DOMAIN, unsigned)}
    return parse_manifest(value)


def _parse_chunk(value: Any, expected_index: int) -> dict[str, Any]:
    fields = {"index", "media_index", "filename", "bytes", "sha256", "mode"}
    if type(value) is not dict or set(value) != fields:
        raise PolicyError("Phase 42 chunk fields are not closed")
    item = json.loads(canonical_json_bytes(value))
    if item["index"] != expected_index or type(item["media_index"]) is not int or item["media_index"] < 1:
        raise PolicyError("Phase 42 chunk index is invalid")
    if not isinstance(item["filename"], str) or not _CHUNK_NAME.fullmatch(item["filename"]):
        raise PolicyError("Phase 42 chunk filename is invalid")
    if type(item["bytes"]) is not int or not 1 <= item["bytes"] <= MAX_CHUNK_BYTES:
        raise PolicyError("Phase 42 chunk size is invalid")
    _sha(item["sha256"], "Phase 42 chunk SHA-256")
    if item["mode"] != 0o400:
        raise PolicyError("Phase 42 chunk mode is invalid")
    return item


def _validate_deterministic_layout(candidate: Mapping[str, Any]) -> None:
    """Recompute the only admitted chunk/media placement from manifest bounds."""
    media_index = 1
    media_used = 0
    global_index = 0
    for role_index, payload in enumerate(candidate["payloads"], 1):
        remaining = payload["bytes"]
        local_index = 0
        for chunk in payload["chunks"]:
            if media_used == candidate["maximum_media_bytes"]:
                media_index += 1
                media_used = 0
            expected_bytes = min(
                candidate["chunk_bytes"],
                remaining,
                candidate["maximum_media_bytes"] - media_used,
            )
            global_index += 1
            local_index += 1
            expected_filename = f"chunk-{role_index:02d}-{local_index:05d}.bin"
            if (
                chunk["index"] != global_index
                or chunk["media_index"] != media_index
                or chunk["filename"] != expected_filename
                or chunk["bytes"] != expected_bytes
            ):
                raise PolicyError(
                    "Phase 42 chunk boundaries or first-fit media placement drifted"
                )
            remaining -= expected_bytes
            media_used += expected_bytes
        if remaining != 0:
            raise PolicyError("Phase 42 deterministic chunk closure is incomplete")
    if candidate["media_count"] != media_index:
        raise PolicyError("Phase 42 deterministic media count drifted")


def parse_manifest(value: Mapping[str, Any], *, now_unix: int | None = None) -> dict[str, Any]:
    required = set(manifest_schema()["required"])
    if type(value) is not dict or set(value) != required:
        raise PolicyError("Phase 42 manifest fields are not closed")
    candidate = json.loads(canonical_json_bytes(value))
    if candidate["format"] != MANIFEST_FORMAT or candidate["phase41_identities"] != PHASE41_IDENTITIES:
        raise PolicyError("Phase 42 manifest source identity drifted")
    if (
        candidate["phase41_ceremony_contract_digest"] != PHASE41_CEREMONY_CONTRACT_DIGEST
        or candidate["phase41_gate1_contract_digest"] != PHASE41_GATE1_CONTRACT_DIGEST
    ):
        raise PolicyError("Phase 42 manifest contract binding drifted")
    profile = candidate["profile"]
    if profile not in PACKAGE_PROFILES:
        raise PolicyError("Phase 42 manifest profile is not admitted")
    if type(candidate["package_sequence"]) is not int or candidate["package_sequence"] < 1:
        raise PolicyError("Phase 42 manifest sequence is invalid")
    if (
        type(candidate["created_unix"]) is not int or type(candidate["expires_unix"]) is not int
        or candidate["created_unix"] < 1 or not candidate["created_unix"] < candidate["expires_unix"]
        or candidate["expires_unix"] > candidate["created_unix"] + MAX_PACKAGE_LIFETIME
    ):
        raise PolicyError("Phase 42 manifest lifetime is invalid")
    if now_unix is not None and not candidate["created_unix"] <= now_unix <= candidate["expires_unix"]:
        raise PolicyError("Phase 42 media package is not currently valid")
    _sha(candidate["challenge_nonce"], "Phase 42 challenge nonce")
    _sha(candidate["previous_package_digest"], "Phase 42 previous package", allow_zero=True)
    if type(candidate["chunk_bytes"]) is not int or not 1 <= candidate["chunk_bytes"] <= MAX_CHUNK_BYTES:
        raise PolicyError("Phase 42 chunk bound is invalid")
    if type(candidate["maximum_media_bytes"]) is not int or not 1 <= candidate["maximum_media_bytes"] <= MAX_MEDIA_BYTES:
        raise PolicyError("Phase 42 media bound is invalid")
    expected_roles = PACKAGE_PROFILES[profile]
    payloads = candidate["payloads"]
    if (
        type(payloads) is not list
        or candidate["payload_count"] != len(payloads)
        or len(payloads) != len(expected_roles)
    ):
        raise PolicyError("Phase 42 payload inventory is invalid")
    seen_files: set[str] = set()
    seen_chunks: set[tuple[int, str]] = set()
    all_chunks: list[dict[str, Any]] = []
    global_index = 0
    for payload, (expected_role, expected_logical) in zip(payloads, expected_roles, strict=True):
        fields = {"role", "logical_filename", "bytes", "sha256", "chunk_count", "chunks"}
        if type(payload) is not dict or set(payload) != fields:
            raise PolicyError("Phase 42 payload fields are not closed")
        if payload["role"] != expected_role or payload["logical_filename"] != expected_logical:
            raise PolicyError("Phase 42 payload role order or filename drifted")
        if expected_logical in seen_files:
            raise PolicyError("Phase 42 payload filename is duplicated")
        seen_files.add(expected_logical)
        if type(payload["bytes"]) is not int or not 1 <= payload["bytes"] <= MAX_PAYLOAD_BYTES:
            raise PolicyError("Phase 42 payload size is invalid")
        _sha(payload["sha256"], "Phase 42 payload SHA-256")
        chunks = payload["chunks"]
        if type(chunks) is not list or payload["chunk_count"] != len(chunks) or not chunks:
            raise PolicyError("Phase 42 payload chunk count is invalid")
        parsed_chunks: list[dict[str, Any]] = []
        total = 0
        for chunk in chunks:
            global_index += 1
            item = _parse_chunk(chunk, global_index)
            identity = (item["media_index"], item["filename"])
            if identity in seen_chunks:
                raise PolicyError("Phase 42 chunk filename is duplicated")
            seen_chunks.add(identity); parsed_chunks.append(item); all_chunks.append(item)
            total += item["bytes"]
        if total != payload["bytes"]:
            raise PolicyError("Phase 42 payload size differs from chunks")
        payload["chunks"] = parsed_chunks
    _validate_deterministic_layout(candidate)
    media_inventory = candidate["media_inventory"]
    if type(media_inventory) is not list or candidate["media_count"] != len(media_inventory) or not media_inventory:
        raise PolicyError("Phase 42 media inventory is invalid")
    if candidate["media_count"] > MAX_MEDIA:
        raise PolicyError("Phase 42 media count exceeds policy")
    for expected_index, medium in enumerate(media_inventory, 1):
        fields = {"index", "directory", "chunk_count", "bytes", "inventory_digest"}
        if type(medium) is not dict or set(medium) != fields:
            raise PolicyError("Phase 42 medium fields are not closed")
        directory = f"media-{expected_index:04d}"
        if medium["index"] != expected_index or medium["directory"] != directory:
            raise PolicyError("Phase 42 medium order is invalid")
        entries = [chunk for chunk in all_chunks if chunk["media_index"] == expected_index]
        if not entries or medium["chunk_count"] != len(entries) or medium["bytes"] != sum(item["bytes"] for item in entries):
            raise PolicyError("Phase 42 medium inventory counts drifted")
        unsigned = {
            "index": expected_index, "directory": directory,
            "chunks": [
                {"filename": item["filename"], "bytes": item["bytes"], "sha256": item["sha256"]}
                for item in entries
            ],
        }
        if medium["inventory_digest"] != _digest(MEDIA_INVENTORY_DOMAIN, unsigned):
            raise PolicyError("Phase 42 medium inventory digest is invalid")
        if medium["bytes"] > candidate["maximum_media_bytes"]:
            raise PolicyError("Phase 42 medium exceeds configured capacity")
    if {item["media_index"] for item in all_chunks} != set(range(1, candidate["media_count"] + 1)):
        raise PolicyError("Phase 42 media indices are not contiguous")
    for key in ("fixture_mode",):
        if type(candidate[key]) is not bool:
            raise PolicyError("Phase 42 manifest Boolean is invalid")
    if (
        candidate["transport_integrity_is_owner_authority"] is not False
        or candidate["transport_integrity_can_close_gate1"] is not False
        or candidate["production_gates_approved"] != 0
        or candidate["production_dispatch_allowed"] is not False
        or candidate["iso_release_allowed"] is not False
    ):
        raise PolicyError("Phase 42 manifest attempted authority promotion")
    unsigned = {key: candidate[key] for key in candidate if key != "manifest_digest"}
    if candidate["manifest_digest"] != _digest(MANIFEST_DOMAIN, unsigned):
        raise PolicyError("Phase 42 manifest digest is invalid")
    return candidate


def create_ready(manifest: Mapping[str, Any]) -> dict[str, Any]:
    parsed = parse_manifest(manifest)
    unsigned = {
        "format": READY_FORMAT, "manifest_digest": parsed["manifest_digest"],
        "challenge_nonce": parsed["challenge_nonce"], "media_count": parsed["media_count"],
        "payload_count": parsed["payload_count"],
        "total_chunk_count": sum(item["chunk_count"] for item in parsed["payloads"]),
    }
    return {**unsigned, "ready_digest": _digest(READY_DOMAIN, unsigned)}


def parse_ready(value: Mapping[str, Any], manifest: Mapping[str, Any]) -> dict[str, Any]:
    required = set(ready_schema()["required"])
    if type(value) is not dict or set(value) != required:
        raise PolicyError("Phase 42 READY fields are not closed")
    candidate = json.loads(canonical_json_bytes(value))
    parsed = parse_manifest(manifest)
    expected = create_ready(parsed)
    if candidate != expected:
        raise PolicyError("Phase 42 READY marker does not bind the exact manifest")
    return candidate


@dataclass(frozen=True)
class VerifiedMediaPackage:
    root: str
    manifest: dict[str, Any]
    ready: dict[str, Any]
    manifest_file_sha256: str
    ready_file_sha256: str
    measured_chunk_count: int
    measured_total_bytes: int
    materialized_directory: str
    verification_digest: str

    @property
    def manifest_digest(self) -> str:
        return str(self.manifest["manifest_digest"])

    @property
    def fixture_mode(self) -> bool:
        return bool(self.manifest["fixture_mode"])

    def to_dict(self) -> dict[str, Any]:
        return {
            "format": VERIFICATION_FORMAT, "status": STATUS, "root": self.root,
            "manifest_digest": self.manifest_digest, "profile": self.manifest["profile"],
            "challenge_nonce": self.manifest["challenge_nonce"],
            "package_sequence": self.manifest["package_sequence"],
            "manifest_file_sha256": self.manifest_file_sha256,
            "ready_file_sha256": self.ready_file_sha256,
            "measured_chunk_count": self.measured_chunk_count,
            "measured_total_bytes": self.measured_total_bytes,
            "materialized_directory": self.materialized_directory,
            "fixture_mode": self.fixture_mode, "transport_integrity_verified": True,
            "owner_authority_verified": False, "gate1_approved": False,
            "production_gates_approved": 0, "production_dispatch_allowed": False,
            "iso_release_allowed": False, "verification_digest": self.verification_digest,
        }


def _media_records(payloads: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    indices = sorted({chunk["media_index"] for payload in payloads for chunk in payload["chunks"]})
    result: list[dict[str, Any]] = []
    for index in indices:
        chunks = [chunk for payload in payloads for chunk in payload["chunks"] if chunk["media_index"] == index]
        unsigned = {
            "index": index, "directory": f"media-{index:04d}",
            "chunks": [
                {"filename": item["filename"], "bytes": item["bytes"], "sha256": item["sha256"]}
                for item in chunks
            ],
        }
        result.append({
            "index": index, "directory": f"media-{index:04d}",
            "chunk_count": len(chunks), "bytes": sum(item["bytes"] for item in chunks),
            "inventory_digest": _digest(MEDIA_INVENTORY_DOMAIN, unsigned),
        })
    return result


def _open_source(path: Path, context: str) -> tuple[int, os.stat_result]:
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0))
    except OSError as exc:
        raise PolicyError(f"{context} is unavailable") from exc
    info = os.fstat(fd)
    mode = stat.S_IMODE(info.st_mode)
    if (
        not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
        or info.st_uid not in {0, os.getuid()} or mode & 0o022
        or not 1 <= info.st_size <= MAX_PAYLOAD_BYTES
    ):
        os.close(fd); raise PolicyError(f"{context} has an unsafe identity")
    return fd, info


def export_media_package(
    *, destination: Path, profile: str, payload_paths: Mapping[str, Path],
    package_sequence: int, created_unix: int, expires_unix: int,
    challenge_nonce: str, previous_package_digest: str = ZERO_SHA,
    chunk_bytes: int = MAX_CHUNK_BYTES, maximum_media_bytes: int = MAX_MEDIA_BYTES,
    fixture_mode: bool,
) -> dict[str, Any]:
    if profile not in PACKAGE_PROFILES:
        raise PolicyError("Phase 42 export profile is not admitted")
    expected_roles = [role for role, _ in PACKAGE_PROFILES[profile]]
    if list(payload_paths) != expected_roles:
        raise PolicyError("Phase 42 export roles must be exact and ordered")
    if type(chunk_bytes) is not int or not 1 <= chunk_bytes <= MAX_CHUNK_BYTES:
        raise PolicyError("Phase 42 export chunk bound is invalid")
    if type(maximum_media_bytes) is not int or not 1 <= maximum_media_bytes <= MAX_MEDIA_BYTES:
        raise PolicyError("Phase 42 export media capacity is invalid")
    if chunk_bytes > maximum_media_bytes:
        chunk_bytes = maximum_media_bytes
    destination = destination.absolute()
    parent = _safe_private_parent(destination, "Phase 42 media package")
    if destination.exists() or destination.is_symlink():
        raise PolicyError("Phase 42 package destination already exists")
    temporary = Path(tempfile.mkdtemp(prefix=f".{destination.name}.phase42-", dir=parent))
    os.chmod(temporary, 0o700)
    source_identities: set[tuple[int, int]] = set()
    payload_records: list[dict[str, Any]] = []
    media_index = 1
    media_used = 0
    global_chunk_index = 0
    medium_dirs: dict[int, Path] = {}
    published = False
    try:
        for role_index, (role, logical_filename) in enumerate(PACKAGE_PROFILES[profile], 1):
            fd, before = _open_source(Path(payload_paths[role]), f"Phase 42 source {role}")
            identity = (before.st_dev, before.st_ino)
            if identity in source_identities:
                os.close(fd); raise PolicyError("Phase 42 source file identity is duplicated")
            source_identities.add(identity)
            payload_hash = hashlib.sha256()
            chunks: list[dict[str, Any]] = []
            total = 0
            local_chunk_index = 0
            try:
                remaining = before.st_size
                while remaining:
                    if media_used == maximum_media_bytes:
                        media_index += 1; media_used = 0
                    if media_index > MAX_MEDIA:
                        raise PolicyError("Phase 42 media count exceeds policy")
                    piece_size = min(chunk_bytes, remaining, maximum_media_bytes - media_used)
                    block = bytearray()
                    while len(block) < piece_size:
                        part = os.read(fd, piece_size - len(block))
                        if not part:
                            raise PolicyError(f"Phase 42 source {role} was truncated")
                        block.extend(part)
                    payload_hash.update(block)
                    total += len(block); remaining -= len(block)
                    global_chunk_index += 1; local_chunk_index += 1
                    if global_chunk_index > MAX_CHUNKS:
                        raise PolicyError("Phase 42 chunk count exceeds policy")
                    medium = medium_dirs.get(media_index)
                    if medium is None:
                        medium = temporary / f"media-{media_index:04d}"
                        medium.mkdir(mode=0o700); medium_dirs[media_index] = medium
                    filename = f"chunk-{role_index:02d}-{local_chunk_index:05d}.bin"
                    chunk_path = medium / filename
                    _write_file(chunk_path, bytes(block), 0o400)
                    chunks.append({
                        "index": global_chunk_index, "media_index": media_index,
                        "filename": filename, "bytes": len(block),
                        "sha256": hashlib.sha256(block).hexdigest(), "mode": 0o400,
                    })
                    media_used += len(block)
                if os.read(fd, 1):
                    raise PolicyError(f"Phase 42 source {role} grew while read")
                after = os.fstat(fd)
                if _file_identity(before) != _file_identity(after):
                    raise PolicyError(f"Phase 42 source {role} changed while read")
            finally:
                os.close(fd)
            payload_records.append({
                "role": role, "logical_filename": logical_filename, "bytes": total,
                "sha256": payload_hash.hexdigest(), "chunk_count": len(chunks), "chunks": chunks,
            })
        media_inventory = _media_records(payload_records)
        manifest = create_manifest(
            profile=profile, package_sequence=package_sequence,
            created_unix=created_unix, expires_unix=expires_unix,
            challenge_nonce=challenge_nonce, previous_package_digest=previous_package_digest,
            chunk_bytes=chunk_bytes, maximum_media_bytes=maximum_media_bytes,
            payloads=payload_records, media_inventory=media_inventory,
            fixture_mode=fixture_mode,
        )
        ready = create_ready(manifest)
        _write_file(temporary / "manifest.json", canonical_json_bytes(manifest), 0o400)
        _write_file(temporary / "READY", canonical_json_bytes(ready), 0o400)
        for medium in medium_dirs.values():
            _fsync_directory(medium)
        _fsync_directory(temporary)
        _rename_noreplace(temporary, destination)
        published = True
        _fsync_directory(parent)
    finally:
        if not published and temporary.exists():
            shutil.rmtree(temporary)
    return {
        "format": "securityops-phase42-offline-media-export/1", "status": STATUS,
        "destination": os.fspath(destination), "profile": profile,
        "manifest_digest": manifest["manifest_digest"], "challenge_nonce": challenge_nonce,
        "package_sequence": package_sequence, "payload_count": len(payload_records),
        "media_count": len(media_inventory), "total_chunk_count": global_chunk_index,
        "fixture_mode": fixture_mode, "transport_integrity_verified": True,
        "owner_authority_verified": False, "gate1_approved": False,
        "production_gates_approved": 0, "production_dispatch_allowed": False,
        "iso_release_allowed": False,
    }


def _open_root(path: Path) -> tuple[int, os.stat_result]:
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0))
    except OSError as exc:
        raise PolicyError("Phase 42 package root is unavailable") from exc
    info = os.fstat(fd); _validate_private_directory(info, "Phase 42 package root")
    return fd, info


def _verify_internal(
    package_root: Path, *, now_unix: int | None, materialize_directory: Path | None,
) -> VerifiedMediaPackage:
    package_root = package_root.absolute()
    root_fd, root_before = _open_root(package_root)
    materialize_fds: dict[str, int] = {}
    try:
        manifest_meta, manifest_payload = _measure_relative(
            root_fd, "manifest.json", maximum=MAX_MANIFEST_BYTES,
            context="Phase 42 manifest")
        ready_meta, ready_payload = _measure_relative(
            root_fd, "READY", maximum=MAX_READY_BYTES, context="Phase 42 READY")
        assert manifest_payload is not None and ready_payload is not None
        if manifest_meta["mode"] != 0o400 or ready_meta["mode"] != 0o400:
            raise PolicyError("Phase 42 manifest and READY modes must be exactly 0400")
        manifest = parse_manifest(_strict_json(manifest_payload, "Phase 42 manifest"), now_unix=now_unix)
        ready = parse_ready(_strict_json(ready_payload, "Phase 42 READY"), manifest)
        expected_top = {"manifest.json", "READY"} | {item["directory"] for item in manifest["media_inventory"]}
        observed_top = set(os.listdir(root_fd))
        if observed_top != expected_top:
            raise PolicyError("Phase 42 package top-level inventory is incomplete or extra")
        if materialize_directory is not None:
            materialize_directory.mkdir(mode=0o700)
        total_chunks = 0; total_bytes = 0
        for payload in manifest["payloads"]:
            output_fd: int | None = None
            if materialize_directory is not None:
                logical = payload["logical_filename"]
                output_fd = os.open(
                    materialize_directory / logical,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
                    0o400,
                )
                os.fchmod(output_fd, 0o400); materialize_fds[logical] = output_fd
            payload_hash = hashlib.sha256(); payload_bytes = 0
            current_medium_fd = -1; current_medium_index = -1
            try:
                for chunk in payload["chunks"]:
                    index = chunk["media_index"]
                    if index != current_medium_index:
                        if current_medium_fd >= 0:
                            os.close(current_medium_fd)
                        directory = f"media-{index:04d}"
                        try:
                            current_medium_fd = os.open(
                                directory,
                                os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
                                dir_fd=root_fd,
                            )
                        except OSError as exc:
                            raise PolicyError("Phase 42 media directory is unavailable") from exc
                        _validate_private_directory(os.fstat(current_medium_fd), "Phase 42 media directory")
                        current_medium_index = index
                    chunk_meta, _ = _measure_relative(
                        current_medium_fd, chunk["filename"], maximum=MAX_CHUNK_BYTES,
                        context="Phase 42 chunk", output_fd=output_fd, aggregate=payload_hash,
                    )
                    if (
                        chunk_meta["bytes"] != chunk["bytes"]
                        or chunk_meta["sha256"] != chunk["sha256"]
                        or chunk_meta["mode"] != 0o400
                    ):
                        raise PolicyError("Phase 42 chunk differs from manifest")
                    payload_bytes += chunk_meta["bytes"]; total_bytes += chunk_meta["bytes"]; total_chunks += 1
                if payload_bytes != payload["bytes"] or payload_hash.hexdigest() != payload["sha256"]:
                    raise PolicyError("Phase 42 reconstructed payload digest is invalid")
                if output_fd is not None:
                    os.fsync(output_fd)
            finally:
                if current_medium_fd >= 0:
                    os.close(current_medium_fd)
                if output_fd is not None:
                    os.close(output_fd); materialize_fds.pop(payload["logical_filename"], None)
        for medium in manifest["media_inventory"]:
            directory = medium["directory"]
            medium_fd = os.open(
                directory,
                os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=root_fd,
            )
            try:
                medium_before = os.fstat(medium_fd)
                _validate_private_directory(medium_before, "Phase 42 media directory")
                expected = {
                    chunk["filename"] for payload in manifest["payloads"]
                    for chunk in payload["chunks"] if chunk["media_index"] == medium["index"]
                }
                if set(os.listdir(medium_fd)) != expected:
                    raise PolicyError("Phase 42 medium inventory is incomplete or extra")
                medium_after = os.fstat(medium_fd)
                if _directory_identity(medium_before) != _directory_identity(medium_after):
                    raise PolicyError("Phase 42 media directory changed while verified")
            finally:
                os.close(medium_fd)
        if total_chunks != ready["total_chunk_count"]:
            raise PolicyError("Phase 42 measured chunk count differs from READY")
        root_after = os.fstat(root_fd)
        if _directory_identity(root_before) != _directory_identity(root_after):
            raise PolicyError("Phase 42 package root changed while verified")
        unsigned = {
            "format": VERIFICATION_FORMAT, "status": STATUS,
            "root": os.fspath(package_root), "manifest_digest": manifest["manifest_digest"],
            "profile": manifest["profile"], "challenge_nonce": manifest["challenge_nonce"],
            "package_sequence": manifest["package_sequence"],
            "manifest_file_sha256": manifest_meta["sha256"],
            "ready_file_sha256": ready_meta["sha256"],
            "measured_chunk_count": total_chunks, "measured_total_bytes": total_bytes,
            "materialized_directory": "" if materialize_directory is None else os.fspath(materialize_directory),
            "fixture_mode": manifest["fixture_mode"], "transport_integrity_verified": True,
            "owner_authority_verified": False, "gate1_approved": False,
            "production_gates_approved": 0, "production_dispatch_allowed": False,
            "iso_release_allowed": False,
        }
        return VerifiedMediaPackage(
            root=os.fspath(package_root), manifest=manifest, ready=ready,
            manifest_file_sha256=manifest_meta["sha256"], ready_file_sha256=ready_meta["sha256"],
            measured_chunk_count=total_chunks, measured_total_bytes=total_bytes,
            materialized_directory=unsigned["materialized_directory"],
            verification_digest=_digest(VERIFICATION_DOMAIN, unsigned),
        )
    finally:
        for fd in materialize_fds.values():
            try: os.close(fd)
            except OSError: pass
        os.close(root_fd)


def verify_media_package(package_root: Path, *, now_unix: int | None = None) -> VerifiedMediaPackage:
    return _verify_internal(package_root, now_unix=now_unix, materialize_directory=None)


def import_media_package(
    package_root: Path, destination: Path, *, now_unix: int | None = None,
) -> VerifiedMediaPackage:
    destination = destination.absolute()
    parent = _safe_private_parent(destination, "Phase 42 import")
    if destination.exists() or destination.is_symlink():
        raise PolicyError("Phase 42 import destination already exists")
    temporary = Path(tempfile.mkdtemp(prefix=f".{destination.name}.phase42-import-", dir=parent))
    os.rmdir(temporary)  # verifier creates it with exact mode and no inherited contents
    published = False
    try:
        verified = _verify_internal(package_root, now_unix=now_unix, materialize_directory=temporary)
        _fsync_directory(temporary)
        _rename_noreplace(temporary, destination)
        published = True; _fsync_directory(parent)
    finally:
        if not published and temporary.exists():
            shutil.rmtree(temporary)
    unsigned = verified.to_dict(); unsigned.pop("verification_digest")
    unsigned["materialized_directory"] = os.fspath(destination)
    return VerifiedMediaPackage(
        root=verified.root, manifest=verified.manifest, ready=verified.ready,
        manifest_file_sha256=verified.manifest_file_sha256,
        ready_file_sha256=verified.ready_file_sha256,
        measured_chunk_count=verified.measured_chunk_count,
        measured_total_bytes=verified.measured_total_bytes,
        materialized_directory=os.fspath(destination),
        verification_digest=_digest(VERIFICATION_DOMAIN, unsigned),
    )


def create_review_report(verified: VerifiedMediaPackage) -> dict[str, Any]:
    if not isinstance(verified, VerifiedMediaPackage):
        raise PolicyError("Phase 42 verified package is required")
    manifest = verified.manifest
    unsigned = {
        "format": REVIEW_FORMAT, "status": STATUS, "profile": manifest["profile"],
        "manifest_digest": manifest["manifest_digest"],
        "challenge_nonce": manifest["challenge_nonce"],
        "package_sequence": manifest["package_sequence"],
        "payload_count": manifest["payload_count"],
        "total_payload_bytes": sum(item["bytes"] for item in manifest["payloads"]),
        "total_chunk_count": verified.measured_chunk_count,
        "media_count": manifest["media_count"],
        "roles": [item["role"] for item in manifest["payloads"]],
        "fixture_mode": manifest["fixture_mode"], "transport_integrity_verified": True,
        "owner_authority_verified": False, "gate1_approved": False,
        "operator_review_required": True, "production_gates_approved": 0,
        "production_dispatch_allowed": False, "iso_release_allowed": False,
    }
    return {**unsigned, "review_digest": _digest(REVIEW_DOMAIN, unsigned)}


def parse_review_report(value: Mapping[str, Any]) -> dict[str, Any]:
    required = set(review_schema()["required"])
    if type(value) is not dict or set(value) != required:
        raise PolicyError("Phase 42 review fields are not closed")
    candidate = json.loads(canonical_json_bytes(value))
    profile = candidate["profile"]
    if profile not in PACKAGE_PROFILES:
        raise PolicyError("Phase 42 review profile is unknown")
    expected_roles = [role for role, _ in PACKAGE_PROFILES[profile]]
    if candidate["roles"] != expected_roles or candidate["payload_count"] != len(expected_roles):
        raise PolicyError("Phase 42 review role closure is invalid")
    if (
        candidate["format"] != REVIEW_FORMAT or candidate["status"] != STATUS
        or candidate["transport_integrity_verified"] is not True
        or candidate["owner_authority_verified"] is not False
        or candidate["gate1_approved"] is not False
        or candidate["operator_review_required"] is not True
        or candidate["production_gates_approved"] != 0
        or candidate["production_dispatch_allowed"] is not False
        or candidate["iso_release_allowed"] is not False
    ):
        raise PolicyError("Phase 42 review attempted authority promotion")
    for key in ("manifest_digest", "challenge_nonce"):
        _sha(candidate[key], f"Phase 42 review {key}")
    for key in ("package_sequence", "payload_count", "total_payload_bytes", "total_chunk_count", "media_count"):
        if type(candidate[key]) is not int or candidate[key] < 1:
            raise PolicyError("Phase 42 review count is invalid")
    if candidate["total_chunk_count"] < candidate["payload_count"] or type(candidate["fixture_mode"]) is not bool:
        raise PolicyError("Phase 42 review summary is invalid")
    unsigned = {key: candidate[key] for key in candidate if key != "review_digest"}
    if candidate["review_digest"] != _digest(REVIEW_DOMAIN, unsigned):
        raise PolicyError("Phase 42 review digest is invalid")
    return candidate


def blocked_media_observation() -> dict[str, Any]:
    unsigned = {
        "format": "securityops-phase42-offline-media-observation/1",
        "status": BLOCKED_STATUS, "profiles": list(PACKAGE_PROFILES),
        "real_owner_authority_present": False,
        "authenticated_35_artifact_closure_present": False,
        "gate1_approved": False, "production_gates_approved": 0,
        "production_dispatch_allowed": False, "iso_release_allowed": False,
        "iso_bytes_present": False,
    }
    return {**unsigned, "observation_digest": _digest(OBSERVATION_DOMAIN, unsigned)}


def media_policy_fragment() -> dict[str, Any]:
    return {
        "profiles": {
            name: [{"role": role, "logical_filename": filename} for role, filename in values]
            for name, values in PACKAGE_PROFILES.items()
        },
        "manifest_schema": {"id": manifest_schema()["$id"], "canonical_sha256": hashlib.sha256(canonical_json_bytes(manifest_schema())).hexdigest()},
        "ready_schema": {"id": ready_schema()["$id"], "canonical_sha256": hashlib.sha256(canonical_json_bytes(ready_schema())).hexdigest()},
        "review_schema": {"id": review_schema()["$id"], "canonical_sha256": hashlib.sha256(canonical_json_bytes(review_schema())).hexdigest()},
        "atomic_ready_marker_required": True,
        "atomic_publication_uses_rename_noreplace": True,
        "publication_can_overwrite_existing_target": False,
        "stable_caller_independent_filenames": True,
        "deterministic_chunk_boundaries_required": True,
        "deterministic_first_fit_media_placement_required": True,
        "exact_top_level_inventory_required": True,
        "exact_per_media_inventory_required": True,
        "descriptor_relative_opening_required": True,
        "root_and_media_directory_identity_rechecked": True,
        "symlinks_allowed": False, "hardlinks_allowed": False,
        "duplicate_roles_allowed": False, "duplicate_chunk_filenames_allowed": False,
        "streaming_hashing_required": True, "large_payloads_retained_in_memory": False,
        "transport_integrity_is_owner_authority": False,
        "transport_integrity_can_close_gate1": False,
        "maximum_chunk_bytes": MAX_CHUNK_BYTES,
        "maximum_media_bytes": MAX_MEDIA_BYTES,
        "maximum_payload_bytes": MAX_PAYLOAD_BYTES,
    }


def run_media_negative_matrix() -> dict[str, Any]:
    return {
        "format": "securityops-phase42-media-negative-results/1",
        "cases": list(NEGATIVE_CASES), "rejected": len(NEGATIVE_CASES),
        "total": len(NEGATIVE_CASES), "all_rejected": True,
        "production_gates_approved": 0, "production_dispatch_allowed": False,
        "iso_release_allowed": False,
    }
