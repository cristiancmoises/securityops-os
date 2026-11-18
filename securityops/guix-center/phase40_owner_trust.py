# CodeMark v1 project=4c63e0fe-589c-4944-8449-97e211a38b72 file=6f5adb8c056c5bbcbb05a68a000df8d9 owner="Cristian Cezar Mois\u00e9s"
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Phase 40 owner trust-root and authenticated input-closure bootstrap.

Phase 39 can verify dual-signed production-gate exchanges, but it deliberately
requires a locally pinned owner fingerprint.  This module defines the missing
operator-controlled trust bootstrap without manufacturing owner authority:

* owner and build-node verification keyrings are measured through descriptors;
* key packets are inspected from kernel-sealed memfd objects;
* secret-key packets, weak signing algorithms, duplicate keys, and role reuse
  are rejected;
* an owner-signed trust-root document binds both verification keyrings;
* an owner-signed exact input inventory binds the inherited Rust/Evelin/Esquema
  closure and the Guix/Guile/Qt/PySide/Guix-Center closure;
* generated signing requests never contain or invoke secret keys;
* fixture keys and transport-only input inventories can never close Gate 1.

This is an executable trust and staging boundary.  It is not evidence that the
real owner ceremony, publisher admission, Guix build, KVM execution, or ISO
construction happened.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import errno
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import shutil
import signal
import stat
import subprocess
import tempfile
import time
from typing import Any, Final, Mapping, Sequence

try:
    from . import phase39_owner_execution as phase39
except ImportError:  # pragma: no cover - installed Guix Center copy
    import phase39_owner_execution as phase39  # type: ignore[no-redef]

PolicyError = phase39.PolicyError
canonical_json_bytes = phase39.canonical_json_bytes

CONTRACT_FORMAT: Final[str] = "securityops-phase40-owner-trust-bootstrap-contract/1"
TRUST_ROOT_FORMAT: Final[str] = "securityops-phase40-owner-trust-root/1"
TRUST_ROOT_VERIFICATION_FORMAT: Final[str] = (
    "securityops-phase40-owner-trust-root-verification/1"
)
TRUST_STATE_FORMAT: Final[str] = "securityops-phase40-owner-trust-state/1"
INPUT_CLOSURE_FORMAT: Final[str] = (
    "securityops-phase40-owner-authenticated-input-closure/1"
)
INPUT_CLOSURE_VERIFICATION_FORMAT: Final[str] = (
    "securityops-phase40-owner-input-closure-verification/1"
)
SIGNING_REQUEST_FORMAT: Final[str] = (
    "securityops-phase40-gate1-signing-request/1"
)
KIT_FORMAT: Final[str] = "securityops-phase40-owner-bootstrap-kit/1"
STATUS: Final[str] = (
    "PASS_PHASE40_OWNER_TRUST_BOOTSTRAP_AND_AUTHENTICATED_INPUT_BOUNDARY"
)
BLOCKED_STATUS: Final[str] = (
    "BLOCKED_PHASE40_REAL_OWNER_TRUST_AND_AUTHENTICATED_INPUTS_REQUIRED"
)

CONTRACT_DOMAIN: Final[bytes] = b"SECURITYOPS-PHASE40-OWNER-TRUST-CONTRACT-V1\x00"
TRUST_ROOT_DOMAIN: Final[bytes] = b"SECURITYOPS-PHASE40-OWNER-TRUST-ROOT-V1\x00"
TRUST_VERIFICATION_DOMAIN: Final[bytes] = (
    b"SECURITYOPS-PHASE40-OWNER-TRUST-VERIFICATION-V1\x00"
)
TRUST_STATE_DOMAIN: Final[bytes] = b"SECURITYOPS-PHASE40-OWNER-TRUST-STATE-V1\x00"
INPUT_CLOSURE_DOMAIN: Final[bytes] = (
    b"SECURITYOPS-PHASE40-OWNER-INPUT-CLOSURE-V1\x00"
)
INPUT_VERIFICATION_DOMAIN: Final[bytes] = (
    b"SECURITYOPS-PHASE40-OWNER-INPUT-VERIFICATION-V1\x00"
)
SIGNING_REQUEST_DOMAIN: Final[bytes] = (
    b"SECURITYOPS-PHASE40-GATE1-SIGNING-REQUEST-V1\x00"
)
KIT_DOMAIN: Final[bytes] = b"SECURITYOPS-PHASE40-OWNER-BOOTSTRAP-KIT-V1\x00"

PHASE39_IDENTITIES: Final[dict[str, str]] = {
    "runtime_commit": "a1c3790d8178f68159744f5f1909c1681c27d4ab",
    "runtime_tree": "e179dfc99c7e4c5b819fed519612fa8ca1779e2a",
    "securityops_os_commit": "1898592523deffdc883656eaa6b9bfbaf9d09dd4",
    "securityops_os_tree": "46624c0155848f2b339f9a6979c8168016c0073b",
    "stable_v1_13_0": "8373fd789c9a525d6128abfd3d7a93ad4db3348b",
}
PHASE39_CONTRACT_DIGEST: Final[str] = (
    "b5e8d916288a713d036cba96fdaa77a595fb5c44e001ca6c03e33f55e5b7ee5f"
)
PHASE38_CONTRACT_DIGEST: Final[str] = (
    "16e17c2afa9f588ea3474a91eb180d4c4273282f55f8dfb82ac52b0cf9255dac"
)
RUST_ARCHIVE_NAME: Final[str] = "rust-1.85.1-x86_64-unknown-linux-gnu.tar.xz"
RUST_ARCHIVE_SHA256: Final[str] = (
    "912c76f602f5f630138fca2388b2688c2c1aabcf823d71890b2b9155f743792e"
)
RUST_RELEASE_FINGERPRINT: Final[str] = (
    "108F66205EAEB0AAA8DD5E1C85AB96E6FA1BE5FE"
)

_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_FINGERPRINT = re.compile(r"[0-9A-F]{40}\Z")
_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_FILENAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,191}\Z")
_BUILD_NODE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_STORE_ITEM = re.compile(r"[0-9a-z]{32}-[^/\x00]+\Z")

MAX_TRUST_ROOT_BYTES: Final[int] = 2 * 1024 * 1024
MAX_INPUT_MANIFEST_BYTES: Final[int] = 8 * 1024 * 1024
MAX_SIGNATURE_BYTES: Final[int] = 128 * 1024
MAX_KEYRING_BYTES: Final[int] = 8 * 1024 * 1024
MAX_ARTIFACT_BYTES: Final[int] = 4 * 1024 * 1024 * 1024
MAX_TRUST_ROOT_LIFETIME: Final[int] = 366 * 24 * 60 * 60
MAX_MANIFEST_LIFETIME: Final[int] = 30 * 24 * 60 * 60
MIN_KEY_VALIDITY_AFTER_ROOT: Final[int] = 24 * 60 * 60
NODE_PIN_FILE: Final[str] = "/etc/securityops/phase40-owner-pins.json"
NODE_INPUT_ROOT: Final[str] = "/input/phase40"
NODE_EVIDENCE_ROOT: Final[str] = "/evidence"

INHERITED_ARTIFACT_ROLES: Final[tuple[str, ...]] = (
    "rust-archive",
    "rust-detached-signature",
    "rust-minimal-release-keyring",
    "evelin-source-bundle",
    "evelin-signed-source-manifest",
    "evelin-source-manifest-signature",
    "evelin-minimal-publisher-keyring",
    "evelin-source-license-inventory",
    "evelin-dependency-license-inventory",
    "evelin-contribution-rights-evidence",
    "evelin-commercial-authority-evidence",
    "esquema-source-bundle",
    "esquema-signed-source-manifest",
    "esquema-source-manifest-signature",
    "esquema-minimal-publisher-keyring",
    "esquema-source-license-inventory",
    "esquema-dependency-license-inventory",
    "esquema-contribution-rights-evidence",
    "esquema-governance-authority-evidence",
)

GUIX_QT_ARTIFACT_ROLES: Final[tuple[str, ...]] = (
    "guix-source-bundle",
    "guix-signed-source-manifest",
    "guix-source-manifest-signature",
    "guix-minimal-publisher-keyring",
    "guix-channel-lock",
    "guix-channel-lock-signature",
    "guix-channel-authority-keyring",
    "guix-store-closure-manifest",
    "guix-store-closure-signature",
    "guix-store-result-keyring",
    "qt6-pyside6-closure-manifest",
    "qt6-pyside6-closure-signature",
    "guix-center-source-bundle",
    "guix-center-source-manifest",
    "guix-center-source-manifest-signature",
    "guix-center-owner-keyring",
)

ARTIFACT_ROLES: Final[tuple[str, ...]] = (
    INHERITED_ARTIFACT_ROLES + GUIX_QT_ARTIFACT_ROLES
)

STAGED_FILENAMES: Final[dict[str, str]] = {
    "rust-archive": RUST_ARCHIVE_NAME,
    "rust-detached-signature": RUST_ARCHIVE_NAME + ".asc",
    "rust-minimal-release-keyring": "rust-release-keyring.gpg",
    "evelin-source-bundle": "evelin-canonical.bundle",
    "evelin-signed-source-manifest": "evelin-source-manifest.json",
    "evelin-source-manifest-signature": "evelin-source-manifest.json.asc",
    "evelin-minimal-publisher-keyring": "evelin-publisher-keyring.gpg",
    "evelin-source-license-inventory": "evelin-source-licenses.json",
    "evelin-dependency-license-inventory": "evelin-dependency-licenses.json",
    "evelin-contribution-rights-evidence": "evelin-contribution-rights.json",
    "evelin-commercial-authority-evidence": "evelin-commercial-authority.json",
    "esquema-source-bundle": "esquema-canonical.bundle",
    "esquema-signed-source-manifest": "esquema-source-manifest.json",
    "esquema-source-manifest-signature": "esquema-source-manifest.json.asc",
    "esquema-minimal-publisher-keyring": "esquema-publisher-keyring.gpg",
    "esquema-source-license-inventory": "esquema-source-licenses.json",
    "esquema-dependency-license-inventory": "esquema-dependency-licenses.json",
    "esquema-contribution-rights-evidence": "esquema-contribution-rights.json",
    "esquema-governance-authority-evidence": "esquema-governance-authority.json",
    "guix-source-bundle": "guix-canonical.bundle",
    "guix-signed-source-manifest": "guix-source-manifest.json",
    "guix-source-manifest-signature": "guix-source-manifest.json.asc",
    "guix-minimal-publisher-keyring": "guix-publisher-keyring.gpg",
    "guix-channel-lock": "channels.lock.scm",
    "guix-channel-lock-signature": "channels.lock.scm.asc",
    "guix-channel-authority-keyring": "guix-channel-authority-keyring.gpg",
    "guix-store-closure-manifest": "guix-qt-store-closure.json",
    "guix-store-closure-signature": "guix-qt-store-closure.json.asc",
    "guix-store-result-keyring": "guix-build-result-keyring.gpg",
    "qt6-pyside6-closure-manifest": "qt6-pyside6-closure.json",
    "qt6-pyside6-closure-signature": "qt6-pyside6-closure.json.asc",
    "guix-center-source-bundle": "securityops-guix-center.bundle",
    "guix-center-source-manifest": "securityops-guix-center-source.json",
    "guix-center-source-manifest-signature": (
        "securityops-guix-center-source.json.asc"
    ),
    "guix-center-owner-keyring": "securityops-owner-keyring.gpg",
}

KEYRING_ROLES: Final[frozenset[str]] = frozenset(
    role for role in ARTIFACT_ROLES if role.endswith("keyring")
)
SIGNATURE_ROLES: Final[frozenset[str]] = frozenset(
    role for role in ARTIFACT_ROLES if role.endswith("signature")
)
BUNDLE_ROLES: Final[frozenset[str]] = frozenset(
    role for role in ARTIFACT_ROLES if role.endswith("bundle")
)

ROLE_LIMITS: Final[dict[str, int]] = {}
for _role in ARTIFACT_ROLES:
    if _role in BUNDLE_ROLES or _role == "rust-archive":
        ROLE_LIMITS[_role] = MAX_ARTIFACT_BYTES
    elif _role in KEYRING_ROLES:
        ROLE_LIMITS[_role] = MAX_KEYRING_BYTES
    elif _role in SIGNATURE_ROLES:
        ROLE_LIMITS[_role] = MAX_SIGNATURE_BYTES
    elif "closure" in _role:
        ROLE_LIMITS[_role] = 512 * 1024 * 1024
    else:
        ROLE_LIMITS[_role] = 64 * 1024 * 1024

PUBLISHER_ADMISSION_RECEIPT_ROLES: Final[tuple[str, ...]] = (
    "rust-release-signature-admission",
    "canonical-evelin-source-and-rights-admission",
    "official-esquema-source-and-rights-admission",
    "canonical-guix-source-and-channel-admission",
    "guix-store-closure-authentication",
    "guix-center-source-admission",
)

KIT_FILES: Final[tuple[str, ...]] = (
    "README.md",
    "README.pt-BR.md",
    "phase40-owner-trust-contract.json",
    "phase40-owner-trust-root.schema.json",
    "phase40-owner-trust-state.schema.json",
    "phase40-owner-input-closure.schema.json",
    "trust-root.template.json",
    "input-closure.template.json",
    "gate1-signing-request.template.json",
    "scripts/inspect-verification-keyring.py",
    "scripts/verify-owner-bootstrap.py",
    "scripts/create-gate1-job.py",
)

NEGATIVE_CASES: Final[tuple[str, ...]] = (
    "extra-contract-field",
    "phase39-contract-drift",
    "phase39-runtime-identity-drift",
    "owner-build-node-key-reuse-enabled",
    "secret-key-packets-allowed",
    "weak-signing-key-allowed",
    "ambient-gnupg-configuration-allowed",
    "original-path-signature-verification-enabled",
    "owner-fingerprint-pin-optional",
    "owner-keyring-digest-pin-optional",
    "node-fingerprint-pin-optional",
    "node-keyring-digest-pin-optional",
    "input-role-removed",
    "input-role-reordered",
    "guix-role-removed",
    "input-root-not-descriptor-bound",
    "input-root-mutation-not-rejected",
    "large-artifact-payload-retention-enabled",
    "rust-archive-unpinned",
    "fixture-trust-promoted",
    "transport-promoted-to-publisher-admission",
    "owner-inventory-promoted-to-gate1",
    "gate1-without-admission-receipts",
    "network-fetch-enabled",
    "secret-key-generation-enabled",
    "production-promotion",
    "iso-promotion",
)


@dataclass(frozen=True)
class MeasuredFile:
    path: str
    filename: str
    sha256: str
    bytes: int
    mode: int
    uid: int
    gid: int
    device: int
    inode: int

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class KeyIdentity:
    primary_fingerprint: str
    signing_fingerprint: str
    signing_algorithm: str
    signing_bits: int
    signing_curve: str
    signing_created_unix: int
    signing_expires_unix: int
    public_key_count: int
    public_subkey_count: int
    signing_capability_verified: bool
    secret_packets_present: bool
    keyring: MeasuredFile

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["keyring"] = self.keyring.to_dict()
        return value


@dataclass(frozen=True)
class VerifiedTrustRoot:
    document: Mapping[str, Any]
    trust_root_digest: str
    owner_identity: KeyIdentity
    build_node_identity: KeyIdentity
    signature_verified: bool
    local_owner_pin_verified: bool
    local_build_node_pin_verified: bool
    key_separation_verified: bool
    fixture_mode: bool
    owner_authenticated: bool
    verification_digest: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "format": TRUST_ROOT_VERIFICATION_FORMAT,
            "trust_root_digest": self.trust_root_digest,
            "owner_identity": self.owner_identity.to_dict(),
            "build_node_identity": self.build_node_identity.to_dict(),
            "signature_verified": self.signature_verified,
            "local_owner_pin_verified": self.local_owner_pin_verified,
            "local_build_node_pin_verified": self.local_build_node_pin_verified,
            "key_separation_verified": self.key_separation_verified,
            "fixture_mode": self.fixture_mode,
            "owner_authenticated": self.owner_authenticated,
            "production_gate_approved": False,
            "production_dispatch_allowed": False,
            "iso_release_allowed": False,
            "verification_digest": self.verification_digest,
        }


@dataclass(frozen=True)
class InputArtifact:
    role: str
    staged_filename: str
    sha256: str
    bytes: int
    mode: int
    device: int
    inode: int

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class VerifiedInputClosure:
    document: Mapping[str, Any]
    input_closure_digest: str
    trust_root_digest: str
    artifacts: tuple[InputArtifact, ...]
    owner_signature_verified: bool
    exact_inventory_verified: bool
    all_regular_single_link: bool
    all_distinct_file_identities: bool
    exact_rust_archive_bound: bool
    owner_inventory_authenticated: bool
    publisher_admission_receipts_verified: bool
    fixture_mode: bool
    ready_for_gate1_job: bool
    verification_digest: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "format": INPUT_CLOSURE_VERIFICATION_FORMAT,
            "input_closure_digest": self.input_closure_digest,
            "trust_root_digest": self.trust_root_digest,
            "artifacts": [item.to_dict() for item in self.artifacts],
            "artifact_count": len(self.artifacts),
            "owner_signature_verified": self.owner_signature_verified,
            "exact_inventory_verified": self.exact_inventory_verified,
            "all_regular_single_link": self.all_regular_single_link,
            "all_distinct_file_identities": self.all_distinct_file_identities,
            "exact_rust_archive_bound": self.exact_rust_archive_bound,
            "owner_inventory_authenticated": self.owner_inventory_authenticated,
            "publisher_admission_receipts_verified": (
                self.publisher_admission_receipts_verified
            ),
            "fixture_mode": self.fixture_mode,
            "ready_for_gate1_job": self.ready_for_gate1_job,
            "production_gate_approved": False,
            "production_dispatch_allowed": False,
            "iso_release_allowed": False,
            "verification_digest": self.verification_digest,
        }


def _digest(domain: bytes, value: Mapping[str, Any]) -> str:
    return hashlib.sha256(domain + canonical_json_bytes(value)).hexdigest()


def _sha256(value: Any, context: str) -> str:
    if type(value) is not str or not _HEX64.fullmatch(value):
        raise PolicyError(f"{context} must be a lowercase SHA-256 digest")
    return value


def _fingerprint(value: Any, context: str) -> str:
    if type(value) is not str or not _FINGERPRINT.fullmatch(value):
        raise PolicyError(f"{context} must be an uppercase 40-hex fingerprint")
    return value


def _token(value: Any, context: str) -> str:
    if type(value) is not str or not _TOKEN.fullmatch(value):
        raise PolicyError(f"{context} is not a safe token")
    return value


def _strict_json(payload: bytes, context: str) -> dict[str, Any]:
    if not payload or len(payload) > MAX_INPUT_MANIFEST_BYTES:
        raise PolicyError(f"{context} has an invalid byte length")

    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            if key in result:
                raise PolicyError(f"{context} contains a duplicate JSON key")
            result[key] = value
        return result

    try:
        parsed = json.loads(payload.decode("utf-8", errors="strict"),
                            object_pairs_hook=pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PolicyError(f"{context} is not strict UTF-8 JSON") from exc
    if type(parsed) is not dict:
        raise PolicyError(f"{context} must be a JSON object")
    if canonical_json_bytes(parsed) != payload:
        raise PolicyError(f"{context} is not canonical JSON")
    return parsed


def _file_identity(info: os.stat_result) -> tuple[int, ...]:
    return (
        info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
        info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns,
    )


def _measure_open_file(
    fd: int, *, display_path: str, filename: str, maximum: int,
    context: str, allow_empty: bool, capture_payload: bool,
) -> tuple[MeasuredFile, bytes | None]:
    """Measure one already-open file without reopening its pathname.

    Large authenticated bundles may be several GiB.  Callers that only need
    identity, size, and SHA-256 must set ``capture_payload=False`` so the
    measurement remains bounded independently of artifact size.
    """
    before = os.fstat(fd)
    mode = stat.S_IMODE(before.st_mode)
    if (not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_size > maximum
            or (not allow_empty and before.st_size == 0)
            or mode & 0o022
            or mode & 0o7000
            or before.st_uid not in {0, os.getuid()}):
        raise PolicyError(f"{context} has an unsafe file identity")
    remaining = before.st_size
    chunks: list[bytes] | None = [] if capture_payload else None
    digest = hashlib.sha256()
    while remaining:
        block = os.read(fd, min(1024 * 1024, remaining))
        if not block:
            raise PolicyError(f"{context} was truncated while measuring")
        if chunks is not None:
            chunks.append(block)
        digest.update(block)
        remaining -= len(block)
    if os.read(fd, 1):
        raise PolicyError(f"{context} grew while measuring")
    after = os.fstat(fd)
    if _file_identity(before) != _file_identity(after):
        raise PolicyError(f"{context} changed while measuring")
    measured = MeasuredFile(
        path=display_path,
        filename=filename,
        sha256=digest.hexdigest(),
        bytes=after.st_size,
        mode=mode,
        uid=after.st_uid,
        gid=after.st_gid,
        device=after.st_dev,
        inode=after.st_ino,
    )
    payload = b"".join(chunks) if chunks is not None else None
    return measured, payload


def measure_file(path: Path, *, maximum: int, context: str,
                 allow_empty: bool = False) -> tuple[MeasuredFile, bytes]:
    """Measure a small file and return its exact descriptor-read bytes."""
    candidate = path.absolute()
    flags = (os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
             | getattr(os, "O_NOFOLLOW", 0))
    try:
        fd = os.open(candidate, flags)
    except OSError as exc:
        raise PolicyError(f"{context} cannot be opened safely") from exc
    try:
        measured, payload = _measure_open_file(
            fd, display_path=os.fspath(candidate), filename=candidate.name,
            maximum=maximum, context=context, allow_empty=allow_empty,
            capture_payload=True,
        )
        assert payload is not None
        return measured, payload
    finally:
        os.close(fd)


def measure_file_streaming(
    path: Path, *, maximum: int, context: str, allow_empty: bool = False,
) -> MeasuredFile:
    """Measure a potentially large file without retaining its payload."""
    candidate = path.absolute()
    flags = (os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
             | getattr(os, "O_NOFOLLOW", 0))
    try:
        fd = os.open(candidate, flags)
    except OSError as exc:
        raise PolicyError(f"{context} cannot be opened safely") from exc
    try:
        measured, payload = _measure_open_file(
            fd, display_path=os.fspath(candidate), filename=candidate.name,
            maximum=maximum, context=context, allow_empty=allow_empty,
            capture_payload=False,
        )
        if payload is not None:
            raise AssertionError("streaming measurement unexpectedly retained payload")
        return measured
    finally:
        os.close(fd)


def _directory_identity(info: os.stat_result) -> tuple[int, ...]:
    return (
        info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
        info.st_nlink, info.st_mtime_ns, info.st_ctime_ns,
    )

def _sealed_memfd(name: str, payload: bytes) -> int:
    if not hasattr(os, "memfd_create"):
        raise PolicyError("Phase 40 requires Linux memfd_create")
    flags = getattr(os, "MFD_CLOEXEC", 0) | getattr(os, "MFD_ALLOW_SEALING", 0)
    fd = os.memfd_create(name, flags)
    try:
        view = memoryview(payload)
        written = 0
        while written < len(view):
            count = os.write(fd, view[written:])
            if count <= 0:
                raise PolicyError("Phase 40 memfd write did not complete")
            written += count
        os.lseek(fd, 0, os.SEEK_SET)
        seals = (
            getattr(fcntl, "F_SEAL_SEAL", 0x0001)
            | getattr(fcntl, "F_SEAL_SHRINK", 0x0002)
            | getattr(fcntl, "F_SEAL_GROW", 0x0004)
            | getattr(fcntl, "F_SEAL_WRITE", 0x0008)
        )
        fcntl.fcntl(fd, getattr(fcntl, "F_ADD_SEALS", 1033), seals)
        observed = fcntl.fcntl(fd, getattr(fcntl, "F_GET_SEALS", 1034))
        if observed & seals != seals:
            raise PolicyError("Phase 40 memfd did not receive all required seals")
        return fd
    except Exception:
        os.close(fd)
        raise


def _open_executable(path: str | Path, *, context: str,
                     fixture_mode: bool, required: str) -> tuple[int, str]:
    candidate = Path(path)
    if not candidate.is_absolute() or candidate.is_symlink():
        raise PolicyError(f"{context} must be an absolute non-symbolic executable")
    if not fixture_mode and candidate != Path(required):
        raise PolicyError(f"non-fixture {context} requires {required}")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(candidate, flags)
    except OSError as exc:
        raise PolicyError(f"{context} cannot be opened safely") from exc
    try:
        info = os.fstat(fd)
        mode = stat.S_IMODE(info.st_mode)
        if (not stat.S_ISREG(info.st_mode)
                or mode & 0o022
                or mode & 0o7000
                or not mode & 0o111
                or info.st_uid not in {0, os.getuid()}):
            raise PolicyError(f"{context} has an unsafe executable identity")
        return fd, f"/proc/self/fd/{fd}"
    except Exception:
        os.close(fd)
        raise


def _run_gpg(payload: bytes, *, gpg_executable: str | Path,
             fixture_mode: bool, list_packets: bool) -> subprocess.CompletedProcess[bytes]:
    gpg_fd, gpg = _open_executable(
        gpg_executable, context="Phase 40 keyring inspector",
        fixture_mode=fixture_mode, required="/usr/bin/gpg")
    fd = _sealed_memfd("phase40-keyring", payload)
    try:
        with tempfile.TemporaryDirectory(prefix="phase40-gnupg-") as raw:
            home = Path(raw)
            home.chmod(0o700)
            if list_packets:
                argv = [
                    gpg, "--no-options", "--batch", "--no-tty",
                    "--homedir", os.fspath(home), "--list-packets",
                    f"/proc/self/fd/{fd}",
                ]
            else:
                argv = [
                    gpg, "--no-options", "--batch", "--no-tty",
                    "--homedir", os.fspath(home), "--with-colons",
                    "--fixed-list-mode", "--import-options", "show-only",
                    "--dry-run", "--import", f"/proc/self/fd/{fd}",
                ]
            completed = subprocess.run(
                argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, close_fds=True,
                pass_fds=(gpg_fd, fd),
                check=False, timeout=30,
                env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
            )
            if completed.returncode != 0:
                raise PolicyError("Phase 40 keyring inspection failed")
            return completed
    except subprocess.SubprocessError as exc:
        raise PolicyError("Phase 40 keyring inspection did not complete") from exc
    finally:
        os.close(fd)
        os.close(gpg_fd)


def _key_records(colons: str) -> tuple[list[dict[str, Any]], str]:
    records: list[dict[str, Any]] = []
    pending: dict[str, Any] | None = None
    primary = ""
    for raw in colons.splitlines():
        fields = raw.split(":")
        kind = fields[0] if fields else ""
        if kind in {"sec", "ssb"}:
            raise PolicyError("Phase 40 verification keyring contains secret records")
        if kind in {"pub", "sub"}:
            if pending is not None and not pending.get("fingerprint"):
                raise PolicyError("Phase 40 keyring record lacks a fingerprint")
            validity = fields[1] if len(fields) > 1 else ""
            if validity.lower() in {"r", "e", "d", "i"}:
                raise PolicyError("Phase 40 keyring contains an unusable key")
            try:
                bits = int(fields[2] or "0")
                algorithm = int(fields[3] or "0")
                created = int(fields[5] or "0")
                expires = int(fields[6] or "0")
            except (ValueError, IndexError) as exc:
                raise PolicyError("Phase 40 keyring numeric field is invalid") from exc
            capabilities = fields[11] if len(fields) > 11 else ""
            curve = fields[16] if len(fields) > 16 else ""
            pending = {
                "kind": kind,
                "fingerprint": "",
                "bits": bits,
                "algorithm": algorithm,
                "created": created,
                "expires": expires,
                "capabilities": capabilities,
                "curve": curve,
            }
            records.append(pending)
        elif kind == "fpr" and pending is not None and not pending["fingerprint"]:
            fingerprint = fields[9].upper() if len(fields) > 9 else ""
            _fingerprint(fingerprint, "Phase 40 key fingerprint")
            pending["fingerprint"] = fingerprint
            if pending["kind"] == "pub" and not primary:
                primary = fingerprint
    if pending is not None and not pending.get("fingerprint"):
        raise PolicyError("Phase 40 keyring record lacks a fingerprint")
    if not records or not primary:
        raise PolicyError("Phase 40 keyring has no public primary key")
    return records, primary


def _inspect_verification_keyring_payload(
    *, measured: MeasuredFile, payload: bytes,
    expected_primary_fingerprint: str,
    expected_signing_fingerprint: str, valid_through_unix: int,
    gpg_executable: str | Path, fixture_mode: bool,
) -> KeyIdentity:
    """Inspect the exact keyring bytes already measured by the caller.

    This helper is the authoritative path for trust-root verification.  It
    never reopens the original keyring pathname after descriptor measurement.
    """
    if not isinstance(measured, MeasuredFile):
        raise PolicyError("Phase 40 measured keyring identity is invalid")
    if type(payload) is not bytes or len(payload) != measured.bytes:
        raise PolicyError("Phase 40 measured keyring bytes are inconsistent")
    if hashlib.sha256(payload).hexdigest() != measured.sha256:
        raise PolicyError("Phase 40 measured keyring digest is inconsistent")
    expected_primary = _fingerprint(
        expected_primary_fingerprint, "Phase 40 expected primary fingerprint")
    expected_signing = _fingerprint(
        expected_signing_fingerprint, "Phase 40 expected signing fingerprint")
    if type(valid_through_unix) is not int or valid_through_unix < 1:
        raise PolicyError("Phase 40 key-validity horizon is invalid")
    packets = _run_gpg(
        payload, gpg_executable=gpg_executable,
        fixture_mode=fixture_mode, list_packets=True)
    packet_text = (packets.stdout + b"\n" + packets.stderr).decode(
        "utf-8", errors="replace").lower()
    secret_present = (
        "secret key packet" in packet_text
        or "secret sub key packet" in packet_text
        or ":secret key packet:" in packet_text
        or ":secret sub key packet:" in packet_text
    )
    if secret_present:
        raise PolicyError("Phase 40 verification keyring contains secret-key packets")
    listing = _run_gpg(
        payload, gpg_executable=gpg_executable,
        fixture_mode=fixture_mode, list_packets=False)
    text = (listing.stdout + b"\n" + listing.stderr).decode(
        "utf-8", errors="strict")
    records, primary = _key_records(text)
    primaries = [item for item in records if item["kind"] == "pub"]
    if len(primaries) != 1 or primary != expected_primary:
        raise PolicyError("Phase 40 keyring primary fingerprint is not uniquely pinned")
    matches = [item for item in records if item["fingerprint"] == expected_signing]
    if len(matches) != 1:
        raise PolicyError("Phase 40 signing fingerprint is not uniquely present")
    signing = matches[0]
    if "s" not in signing["capabilities"].lower():
        raise PolicyError("Phase 40 admitted key lacks signing capability")
    algorithm = signing["algorithm"]
    bits = signing["bits"]
    curve = signing["curve"]
    if algorithm in {1, 3}:
        if bits < 3072:
            raise PolicyError("Phase 40 RSA signing key is below 3072 bits")
        algorithm_name = "rsa"
    elif algorithm == 22:
        if curve.lower() not in {"ed25519", "ed448"}:
            raise PolicyError("Phase 40 EdDSA signing curve is not admitted")
        algorithm_name = "eddsa"
    elif algorithm == 19:
        if curve.lower() not in {
            "nistp256", "nistp384", "nistp521", "brainpoolp256r1",
            "brainpoolp384r1", "brainpoolp512r1",
        }:
            raise PolicyError("Phase 40 ECDSA signing curve is not admitted")
        algorithm_name = "ecdsa"
    else:
        raise PolicyError("Phase 40 signing algorithm is not admitted")
    expires = signing["expires"]
    if expires and expires < valid_through_unix + MIN_KEY_VALIDITY_AFTER_ROOT:
        raise PolicyError("Phase 40 signing key expires before the trust horizon")
    return KeyIdentity(
        primary_fingerprint=primary,
        signing_fingerprint=expected_signing,
        signing_algorithm=algorithm_name,
        signing_bits=bits,
        signing_curve=curve,
        signing_created_unix=signing["created"],
        signing_expires_unix=expires,
        public_key_count=len(primaries),
        public_subkey_count=len(records) - len(primaries),
        signing_capability_verified=True,
        secret_packets_present=False,
        keyring=measured,
    )


def inspect_verification_keyring(
    path: Path, *, expected_primary_fingerprint: str,
    expected_signing_fingerprint: str, valid_through_unix: int,
    gpg_executable: str | Path = "/usr/bin/gpg",
    fixture_mode: bool = False,
) -> KeyIdentity:
    """Measure a public verification keyring once and inspect those bytes."""
    measured, payload = measure_file(
        path, maximum=MAX_KEYRING_BYTES,
        context="Phase 40 verification keyring")
    return _inspect_verification_keyring_payload(
        measured=measured, payload=payload,
        expected_primary_fingerprint=expected_primary_fingerprint,
        expected_signing_fingerprint=expected_signing_fingerprint,
        valid_through_unix=valid_through_unix,
        gpg_executable=gpg_executable, fixture_mode=fixture_mode)


def trust_root_schema() -> dict[str, Any]:
    sha = {"type": "string", "pattern": "^[0-9a-f]{64}$"}
    fpr = {"type": "string", "pattern": "^[0-9A-F]{40}$"}
    key = {
        "type": "object", "additionalProperties": False,
        "required": [
            "role", "primary_fingerprint", "signing_fingerprint",
            "keyring_filename", "keyring_sha256", "keyring_bytes",
        ],
        "properties": {
            "role": {"type": "string"},
            "primary_fingerprint": fpr,
            "signing_fingerprint": fpr,
            "keyring_filename": {"type": "string", "minLength": 1,
                                 "maxLength": 192},
            "keyring_sha256": sha,
            "keyring_bytes": {"type": "integer", "minimum": 1,
                              "maximum": MAX_KEYRING_BYTES},
        },
    }
    required = [
        "format", "contract_digest", "phase39_contract_digest",
        "phase39_identities", "generation", "created_unix", "expires_unix",
        "owner", "build_node", "key_separation", "fixture_mode",
        "production_gate_approved", "production_dispatch_allowed",
        "iso_release_allowed", "trust_root_digest",
    ]
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://securityops.co/schemas/guix-center/phase40-owner-trust-root.schema.json",
        "title": "Security Ops Phase 40 owner trust root",
        "type": "object", "additionalProperties": False,
        "required": required,
        "properties": {
            "format": {"const": TRUST_ROOT_FORMAT},
            "contract_digest": sha,
            "phase39_contract_digest": sha,
            "phase39_identities": {
                "type": "object", "additionalProperties": False,
                "required": list(PHASE39_IDENTITIES),
                "properties": {name: sha for name in PHASE39_IDENTITIES},
            },
            "generation": {"type": "integer", "minimum": 1},
            "created_unix": {"type": "integer", "minimum": 1},
            "expires_unix": {"type": "integer", "minimum": 1},
            "owner": key,
            "build_node": {
                **key,
                "properties": {
                    **key["properties"],
                    "node_id": {"type": "string", "minLength": 1,
                                "maxLength": 128},
                },
                "required": key["required"] + ["node_id"],
            },
            "key_separation": {
                "type": "object", "additionalProperties": False,
                "required": [
                    "distinct_primary_fingerprints",
                    "distinct_signing_fingerprints",
                    "distinct_keyring_digests",
                    "owner_secret_on_build_node_allowed",
                    "build_node_secret_on_owner_host_allowed",
                ],
                "properties": {
                    "distinct_primary_fingerprints": {"const": True},
                    "distinct_signing_fingerprints": {"const": True},
                    "distinct_keyring_digests": {"const": True},
                    "owner_secret_on_build_node_allowed": {"const": False},
                    "build_node_secret_on_owner_host_allowed": {"const": False},
                },
            },
            "fixture_mode": {"type": "boolean"},
            "production_gate_approved": {"const": False},
            "production_dispatch_allowed": {"const": False},
            "iso_release_allowed": {"const": False},
            "trust_root_digest": sha,
        },
    }


def trust_state_schema() -> dict[str, Any]:
    """Return the closed schema for the locally admitted trust state.

    The trust-root document is signed and portable.  The trust state is the
    local, monotonic admission record derived from that verified document.  It
    deliberately contains only public identities and digests.
    """
    sha = {"type": "string", "pattern": "^[0-9a-f]{64}$"}
    fpr = {"type": "string", "pattern": "^[0-9A-F]{40}$"}
    required = [
        "format", "contract_digest", "phase39_contract_digest",
        "generation", "trust_root_digest", "trust_root_verification_digest",
        "previous_state_digest", "owner_primary_fingerprint",
        "owner_job_signer_fingerprint", "owner_keyring_sha256",
        "build_node_primary_fingerprint",
        "build_node_result_signer_fingerprint",
        "build_node_keyring_sha256", "build_node_id", "allowed_gate_names",
        "fixture_mode", "owner_trust_authenticated",
        "production_gate_approved", "production_dispatch_allowed",
        "iso_release_allowed", "state_digest",
    ]
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": (
            "https://securityops.co/schemas/guix-center/"
            "phase40-owner-trust-state.schema.json"
        ),
        "title": "Security Ops Phase 40 locally admitted owner trust state",
        "type": "object",
        "additionalProperties": False,
        "required": required,
        "properties": {
            "format": {"const": TRUST_STATE_FORMAT},
            "contract_digest": sha,
            "phase39_contract_digest": sha,
            "generation": {"type": "integer", "minimum": 1},
            "trust_root_digest": sha,
            "trust_root_verification_digest": sha,
            "previous_state_digest": sha,
            "owner_primary_fingerprint": fpr,
            "owner_job_signer_fingerprint": fpr,
            "owner_keyring_sha256": sha,
            "build_node_primary_fingerprint": fpr,
            "build_node_result_signer_fingerprint": fpr,
            "build_node_keyring_sha256": sha,
            "build_node_id": {
                "type": "string", "minLength": 1, "maxLength": 128,
            },
            "allowed_gate_names": {
                "type": "array",
                "minItems": len(phase39.GATE_NAMES),
                "maxItems": len(phase39.GATE_NAMES),
                "items": {"type": "string"},
            },
            "fixture_mode": {"type": "boolean"},
            "owner_trust_authenticated": {"type": "boolean"},
            "production_gate_approved": {"const": False},
            "production_dispatch_allowed": {"const": False},
            "iso_release_allowed": {"const": False},
            "state_digest": sha,
        },
    }


def input_closure_schema() -> dict[str, Any]:
    sha = {"type": "string", "pattern": "^[0-9a-f]{64}$"}
    artifact = {
        "type": "object", "additionalProperties": False,
        "required": [
            "role", "staged_filename", "sha256", "bytes", "mode",
        ],
        "properties": {
            "role": {"type": "string"},
            "staged_filename": {"type": "string", "minLength": 1,
                                "maxLength": 192},
            "sha256": sha,
            "bytes": {"type": "integer", "minimum": 1,
                      "maximum": MAX_ARTIFACT_BYTES},
            "mode": {"type": "integer", "minimum": 0, "maximum": 4095},
        },
    }
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://securityops.co/schemas/guix-center/phase40-owner-input-closure.schema.json",
        "title": "Security Ops Phase 40 owner input closure",
        "type": "object", "additionalProperties": False,
        "required": [
            "format", "contract_digest", "trust_root_digest",
            "phase39_contract_digest", "generation", "created_unix",
            "expires_unix", "artifact_count", "artifacts",
            "publisher_admission_receipts", "fixture_mode",
            "owner_inventory_is_publisher_admission",
            "production_gate_approved", "production_dispatch_allowed",
            "iso_release_allowed", "input_closure_digest",
        ],
        "properties": {
            "format": {"const": INPUT_CLOSURE_FORMAT},
            "contract_digest": sha,
            "trust_root_digest": sha,
            "phase39_contract_digest": sha,
            "generation": {"type": "integer", "minimum": 1},
            "created_unix": {"type": "integer", "minimum": 1},
            "expires_unix": {"type": "integer", "minimum": 1},
            "artifact_count": {"const": len(ARTIFACT_ROLES)},
            "artifacts": {
                "type": "array", "minItems": len(ARTIFACT_ROLES),
                "maxItems": len(ARTIFACT_ROLES), "items": artifact,
            },
            "publisher_admission_receipts": {
                "type": "array",
                "minItems": len(PUBLISHER_ADMISSION_RECEIPT_ROLES),
                "maxItems": len(PUBLISHER_ADMISSION_RECEIPT_ROLES),
                "items": {
                    "type": "object", "additionalProperties": False,
                    "required": ["role", "receipt_digest", "verified"],
                    "properties": {
                        "role": {"type": "string"},
                        "receipt_digest": sha,
                        "verified": {"type": "boolean"},
                    },
                },
            },
            "fixture_mode": {"type": "boolean"},
            "owner_inventory_is_publisher_admission": {"const": False},
            "production_gate_approved": {"const": False},
            "production_dispatch_allowed": {"const": False},
            "iso_release_allowed": {"const": False},
            "input_closure_digest": sha,
        },
    }


def _contract_unsigned() -> dict[str, Any]:
    trust_schema = trust_root_schema()
    state_schema = trust_state_schema()
    input_schema = input_closure_schema()
    return {
        "format": CONTRACT_FORMAT,
        "status": STATUS,
        "phase39_contract_digest": PHASE39_CONTRACT_DIGEST,
        "phase38_contract_digest": PHASE38_CONTRACT_DIGEST,
        "phase39_identities": dict(PHASE39_IDENTITIES),
        "schemas": {
            "trust_root": {
                "id": trust_schema["$id"],
                "canonical_sha256": hashlib.sha256(
                    canonical_json_bytes(trust_schema)).hexdigest(),
            },
            "trust_state": {
                "id": state_schema["$id"],
                "canonical_sha256": hashlib.sha256(
                    canonical_json_bytes(state_schema)).hexdigest(),
            },
            "input_closure": {
                "id": input_schema["$id"],
                "canonical_sha256": hashlib.sha256(
                    canonical_json_bytes(input_schema)).hexdigest(),
            },
            "additional_properties_allowed": False,
        },
        "key_policy": {
            "owner_and_build_node_keyrings_separate": True,
            "owner_and_build_node_signing_fingerprints_distinct": True,
            "minimal_public_verification_keyrings_required": True,
            "secret_key_packets_allowed": False,
            "owner_secret_on_build_node_allowed": False,
            "build_node_secret_on_owner_signing_host_allowed": False,
            "admitted_signing_algorithms": [
                "ed25519", "ed448", "ecdsa-nist-or-brainpool", "rsa-3072-plus",
            ],
            "dsa_allowed": False,
            "rsa_minimum_bits": 3072,
            "local_owner_fingerprint_pin_required": True,
            "local_owner_keyring_digest_pin_required": True,
            "local_build_node_fingerprint_pin_required": True,
            "local_build_node_keyring_digest_pin_required": True,
            "ambient_gnupg_configuration_allowed": False,
            "signature_verification_uses_kernel_sealed_memfd": True,
            "keyring_inspection_uses_kernel_sealed_memfd": True,
            "original_paths_reopened_after_measurement": False,
        },
        "local_trust_state": {
            "derived_only_from_verified_trust_root": True,
            "monotonic_generation_required": True,
            "previous_state_digest_required_after_generation_one": True,
            "exact_gate_allowlist": list(phase39.GATE_NAMES),
            "contains_secret_keys": False,
            "fixture_can_authenticate_owner": False,
            "atomic_private_publication_required": True,
        },
        "input_closure": {
            "artifact_roles": list(ARTIFACT_ROLES),
            "artifact_count": len(ARTIFACT_ROLES),
            "inherited_artifact_count": len(INHERITED_ARTIFACT_ROLES),
            "guix_qt_artifact_count": len(GUIX_QT_ARTIFACT_ROLES),
            "staged_filenames": {
                role: STAGED_FILENAMES[role] for role in ARTIFACT_ROLES
            },
            "role_maximum_bytes": {
                role: ROLE_LIMITS[role] for role in ARTIFACT_ROLES
            },
            "exact_role_order_required": True,
            "nofollow_required": True,
            "descriptor_bound_root_directory_required": True,
            "root_directory_identity_stable_during_measurement": True,
            "streaming_hash_without_payload_retention_required": True,
            "regular_single_link_required": True,
            "distinct_file_identities_required": True,
            "owner_signature_required": True,
            "publisher_admission_receipt_roles": list(
                PUBLISHER_ADMISSION_RECEIPT_ROLES),
            "owner_inventory_is_publisher_admission": False,
            "transport_integrity_is_publisher_admission": False,
            "rust_archive_filename": RUST_ARCHIVE_NAME,
            "rust_archive_sha256": RUST_ARCHIVE_SHA256,
            "rust_release_fingerprint": RUST_RELEASE_FINGERPRINT,
        },
        "build_node_paths": {
            "local_pin_file": NODE_PIN_FILE,
            "input_root": NODE_INPUT_ROOT,
            "evidence_root": NODE_EVIDENCE_ROOT,
            "paths_are_owner_job_bound": True,
            "local_pin_file_is_signed_job_input": False,
            "local_pin_file_is_out_of_band_policy": True,
        },
        "node_attestation": {
            "guix_store_prefix": "/gnu/store/",
            "required_executables": ["guix", "guile", "guild", "python3"],
            "exact_executable_hashes_required": True,
            "regular_single_link_required": True,
            "pyside6_import_required": True,
            "qtcore_import_required": True,
            "module_origins_must_be_in_guix_store": True,
            "python_user_site_allowed": False,
            "bounded_version_output_required": True,
            "attestation_is_gate_approval": False,
        },
        "gate1": {
            "phase39_gate_name": "authenticated-guix-qt-environment",
            "phase39_evidence_roles": list(
                phase39.GATE_EVIDENCE_ROLES["authenticated-guix-qt-environment"]),
            "trust_root_authentication_required": True,
            "owner_input_signature_required": True,
            "publisher_admission_receipts_required": True,
            "fixture_can_create_production_job": False,
            "unsigned_job_can_close_gate": False,
            "secret_key_generation_or_use_by_runtime_allowed": False,
        },
        "request_kit": {
            "files": list(KIT_FILES),
            "deterministic_generation_required": True,
            "contains_secret_keys": False,
            "invokes_secret_key_generation": False,
            "invokes_secret_key_signing": False,
        },
        "network_fetch_allowed": False,
        "production_gates_approved": 0,
        "production_dispatch_allowed": False,
        "iso_release_allowed": False,
        "execution_status": BLOCKED_STATUS,
    }


def phase40_contract() -> dict[str, Any]:
    unsigned = _contract_unsigned()
    return {**unsigned, "contract_digest": _digest(CONTRACT_DOMAIN, unsigned)}


def phase40_contract_digest() -> str:
    return phase40_contract()["contract_digest"]


def parse_phase40_contract(value: Mapping[str, Any]) -> dict[str, Any]:
    candidate = json.loads(canonical_json_bytes(value))
    if candidate != phase40_contract():
        raise PolicyError("Phase 40 owner-trust contract differs from closed policy")
    return candidate


def _key_document(role: str, identity: KeyIdentity,
                  *, node_id: str | None = None) -> dict[str, Any]:
    value = {
        "role": role,
        "primary_fingerprint": identity.primary_fingerprint,
        "signing_fingerprint": identity.signing_fingerprint,
        "keyring_filename": identity.keyring.filename,
        "keyring_sha256": identity.keyring.sha256,
        "keyring_bytes": identity.keyring.bytes,
    }
    if node_id is not None:
        value["node_id"] = _token(node_id, "Phase 40 build-node ID")
    return value


def create_trust_root(
    *, generation: int, created_unix: int, expires_unix: int,
    owner_identity: KeyIdentity, build_node_identity: KeyIdentity,
    build_node_id: str, fixture_mode: bool,
) -> dict[str, Any]:
    if type(generation) is not int or generation < 1:
        raise PolicyError("Phase 40 trust-root generation is invalid")
    if (type(created_unix) is not int or type(expires_unix) is not int
            or created_unix < 1 or not created_unix < expires_unix
            or expires_unix > created_unix + MAX_TRUST_ROOT_LIFETIME):
        raise PolicyError("Phase 40 trust-root lifetime is invalid")
    if type(fixture_mode) is not bool:
        raise PolicyError("Phase 40 trust-root fixture state is invalid")
    if not isinstance(owner_identity, KeyIdentity) or not isinstance(
            build_node_identity, KeyIdentity):
        raise PolicyError("Phase 40 trust-root key identities are invalid")
    if (
        owner_identity.primary_fingerprint
        == build_node_identity.primary_fingerprint
        or owner_identity.signing_fingerprint
        == build_node_identity.signing_fingerprint
        or owner_identity.keyring.sha256
        == build_node_identity.keyring.sha256
    ):
        raise PolicyError("Phase 40 owner and build-node keys must be distinct")
    if owner_identity.secret_packets_present or build_node_identity.secret_packets_present:
        raise PolicyError("Phase 40 trust root cannot bind secret-key packets")
    unsigned = {
        "format": TRUST_ROOT_FORMAT,
        "contract_digest": phase40_contract_digest(),
        "phase39_contract_digest": PHASE39_CONTRACT_DIGEST,
        "phase39_identities": dict(PHASE39_IDENTITIES),
        "generation": generation,
        "created_unix": created_unix,
        "expires_unix": expires_unix,
        "owner": _key_document("owner-job-signing", owner_identity),
        "build_node": _key_document(
            "build-node-result-signing", build_node_identity,
            node_id=build_node_id),
        "key_separation": {
            "distinct_primary_fingerprints": True,
            "distinct_signing_fingerprints": True,
            "distinct_keyring_digests": True,
            "owner_secret_on_build_node_allowed": False,
            "build_node_secret_on_owner_host_allowed": False,
        },
        "fixture_mode": fixture_mode,
        "production_gate_approved": False,
        "production_dispatch_allowed": False,
        "iso_release_allowed": False,
    }
    return {**unsigned, "trust_root_digest": _digest(TRUST_ROOT_DOMAIN, unsigned)}


def parse_trust_root(value: Mapping[str, Any], *, now_unix: int | None = None) -> dict[str, Any]:
    required = set(trust_root_schema()["required"])
    if type(value) is not dict or set(value) != required:
        raise PolicyError("Phase 40 trust-root fields are not closed")
    candidate = json.loads(canonical_json_bytes(value))
    if candidate["format"] != TRUST_ROOT_FORMAT:
        raise PolicyError("Phase 40 trust-root format is invalid")
    if candidate["contract_digest"] != phase40_contract_digest():
        raise PolicyError("Phase 40 trust-root contract digest drifted")
    if candidate["phase39_contract_digest"] != PHASE39_CONTRACT_DIGEST:
        raise PolicyError("Phase 40 trust-root Phase 39 contract drifted")
    if candidate["phase39_identities"] != PHASE39_IDENTITIES:
        raise PolicyError("Phase 40 trust-root source identities drifted")
    for name in ("owner", "build_node"):
        entry = candidate[name]
        expected_fields = {
            "role", "primary_fingerprint", "signing_fingerprint",
            "keyring_filename", "keyring_sha256", "keyring_bytes",
        }
        if name == "build_node":
            expected_fields.add("node_id")
        if type(entry) is not dict or set(entry) != expected_fields:
            raise PolicyError("Phase 40 trust-root key entry fields are not closed")
        _fingerprint(entry["primary_fingerprint"], f"Phase 40 {name} primary")
        _fingerprint(entry["signing_fingerprint"], f"Phase 40 {name} signing")
        _sha256(entry["keyring_sha256"], f"Phase 40 {name} keyring")
        if (type(entry["keyring_filename"]) is not str
                or not _FILENAME.fullmatch(entry["keyring_filename"])):
            raise PolicyError("Phase 40 trust-root keyring filename is unsafe")
        if type(entry["keyring_bytes"]) is not int or not (
                1 <= entry["keyring_bytes"] <= MAX_KEYRING_BYTES):
            raise PolicyError("Phase 40 trust-root keyring size is invalid")
        if name == "build_node":
            _token(entry["node_id"], "Phase 40 build-node ID")
    if candidate["owner"]["role"] != "owner-job-signing":
        raise PolicyError("Phase 40 owner key role drifted")
    if candidate["build_node"]["role"] != "build-node-result-signing":
        raise PolicyError("Phase 40 build-node key role drifted")
    if candidate["owner"]["primary_fingerprint"] == candidate["build_node"]["primary_fingerprint"]:
        raise PolicyError("Phase 40 primary key separation failed")
    if candidate["owner"]["signing_fingerprint"] == candidate["build_node"]["signing_fingerprint"]:
        raise PolicyError("Phase 40 signing key separation failed")
    if candidate["owner"]["keyring_sha256"] == candidate["build_node"]["keyring_sha256"]:
        raise PolicyError("Phase 40 keyring digest separation failed")
    if candidate["key_separation"] != {
        "distinct_primary_fingerprints": True,
        "distinct_signing_fingerprints": True,
        "distinct_keyring_digests": True,
        "owner_secret_on_build_node_allowed": False,
        "build_node_secret_on_owner_host_allowed": False,
    }:
        raise PolicyError("Phase 40 key-separation policy drifted")
    if (type(candidate["generation"]) is not int or candidate["generation"] < 1
            or type(candidate["created_unix"]) is not int
            or type(candidate["expires_unix"]) is not int
            or candidate["created_unix"] < 1
            or not candidate["created_unix"] < candidate["expires_unix"]
            or candidate["expires_unix"]
            > candidate["created_unix"] + MAX_TRUST_ROOT_LIFETIME):
        raise PolicyError("Phase 40 trust-root lifetime or generation is invalid")
    if type(candidate["fixture_mode"]) is not bool:
        raise PolicyError("Phase 40 trust-root fixture state is invalid")
    for flag in (
        "production_gate_approved", "production_dispatch_allowed", "iso_release_allowed",
    ):
        if candidate[flag] is not False:
            raise PolicyError("Phase 40 trust root attempted production promotion")
    unsigned = {key: candidate[key] for key in candidate if key != "trust_root_digest"}
    if candidate["trust_root_digest"] != _digest(TRUST_ROOT_DOMAIN, unsigned):
        raise PolicyError("Phase 40 trust-root digest is invalid")
    if now_unix is not None:
        if type(now_unix) is not int or now_unix < 1:
            raise PolicyError("Phase 40 trust-root verification time is invalid")
        if now_unix < candidate["created_unix"] or now_unix > candidate["expires_unix"]:
            raise PolicyError("Phase 40 trust root is not valid at the supplied time")
    return candidate


def verify_signed_trust_root(
    *, trust_root_path: Path, signature_path: Path,
    owner_keyring_path: Path, build_node_keyring_path: Path,
    expected_owner_primary_fingerprint: str,
    expected_owner_signing_fingerprint: str,
    expected_owner_keyring_sha256: str,
    expected_build_node_primary_fingerprint: str,
    expected_build_node_signing_fingerprint: str,
    expected_build_node_keyring_sha256: str,
    now_unix: int,
    gpg_executable: str | Path = "/usr/bin/gpg",
    gpgv_executable: str | Path = "/usr/bin/gpgv",
) -> VerifiedTrustRoot:
    owner_primary = _fingerprint(
        expected_owner_primary_fingerprint, "Phase 40 locally pinned owner primary")
    owner_signing = _fingerprint(
        expected_owner_signing_fingerprint, "Phase 40 locally pinned owner signing")
    owner_digest = _sha256(
        expected_owner_keyring_sha256, "Phase 40 locally pinned owner keyring")
    node_primary = _fingerprint(
        expected_build_node_primary_fingerprint,
        "Phase 40 locally pinned build-node primary")
    node_signing = _fingerprint(
        expected_build_node_signing_fingerprint,
        "Phase 40 locally pinned build-node signing")
    node_digest = _sha256(
        expected_build_node_keyring_sha256,
        "Phase 40 locally pinned build-node keyring")
    root_meta, root_bytes = measure_file(
        trust_root_path, maximum=MAX_TRUST_ROOT_BYTES,
        context="Phase 40 signed trust root")
    signature_meta, signature = measure_file(
        signature_path, maximum=MAX_SIGNATURE_BYTES,
        context="Phase 40 trust-root signature")
    owner_meta, owner_bytes = measure_file(
        owner_keyring_path, maximum=MAX_KEYRING_BYTES,
        context="Phase 40 owner keyring")
    node_meta, node_bytes = measure_file(
        build_node_keyring_path, maximum=MAX_KEYRING_BYTES,
        context="Phase 40 build-node keyring")
    document = parse_trust_root(
        _strict_json(root_bytes, "Phase 40 trust root"), now_unix=now_unix)
    fixture_mode = document["fixture_mode"]
    if (
        document["owner"]["primary_fingerprint"] != owner_primary
        or document["owner"]["signing_fingerprint"] != owner_signing
        or document["owner"]["keyring_sha256"] != owner_digest
        or owner_meta.sha256 != owner_digest
        or document["build_node"]["primary_fingerprint"] != node_primary
        or document["build_node"]["signing_fingerprint"] != node_signing
        or document["build_node"]["keyring_sha256"] != node_digest
        or node_meta.sha256 != node_digest
    ):
        raise PolicyError("Phase 40 trust root differs from local out-of-band pins")
    if (
        document["owner"]["keyring_filename"] != owner_meta.filename
        or document["owner"]["keyring_bytes"] != owner_meta.bytes
        or document["build_node"]["keyring_filename"] != node_meta.filename
        or document["build_node"]["keyring_bytes"] != node_meta.bytes
    ):
        raise PolicyError("Phase 40 trust-root keyring metadata drifted")
    owner_identity = _inspect_verification_keyring_payload(
        measured=owner_meta, payload=owner_bytes,
        expected_primary_fingerprint=owner_primary,
        expected_signing_fingerprint=owner_signing,
        valid_through_unix=document["expires_unix"],
        gpg_executable=gpg_executable, fixture_mode=fixture_mode)
    node_identity = _inspect_verification_keyring_payload(
        measured=node_meta, payload=node_bytes,
        expected_primary_fingerprint=node_primary,
        expected_signing_fingerprint=node_signing,
        valid_through_unix=document["expires_unix"],
        gpg_executable=gpg_executable, fixture_mode=fixture_mode)
    phase39._verify_signature(  # type: ignore[attr-defined]
        payload=root_bytes, signature=signature, keyring=owner_bytes,
        expected_fingerprint=owner_signing,
        gpgv_executable=gpgv_executable,
        fixture_mode=fixture_mode, role="phase40-trust-root")
    key_separation = bool(
        owner_identity.primary_fingerprint != node_identity.primary_fingerprint
        and owner_identity.signing_fingerprint != node_identity.signing_fingerprint
        and owner_identity.keyring.sha256 != node_identity.keyring.sha256
    )
    # The digest/fingerprint checks above are authoritative; also explicitly
    # reject the same device/inode even when two pathnames name it.
    if (
        owner_identity.keyring.device == node_identity.keyring.device
        and owner_identity.keyring.inode == node_identity.keyring.inode
    ):
        raise PolicyError("Phase 40 owner and build-node keyrings alias one file")
    if not key_separation:
        raise PolicyError("Phase 40 owner/build-node key separation failed")
    owner_authenticated = bool(not fixture_mode and key_separation)
    unsigned = {
        "format": TRUST_ROOT_VERIFICATION_FORMAT,
        "trust_root_digest": document["trust_root_digest"],
        "signed_input_sha256": {
            "trust-root": root_meta.sha256,
            "trust-root-signature": signature_meta.sha256,
            "owner-keyring": owner_meta.sha256,
            "build-node-keyring": node_meta.sha256,
        },
        "owner_primary_fingerprint": owner_primary,
        "owner_signing_fingerprint": owner_signing,
        "build_node_primary_fingerprint": node_primary,
        "build_node_signing_fingerprint": node_signing,
        "signature_verified": True,
        "local_owner_pin_verified": True,
        "local_build_node_pin_verified": True,
        "key_separation_verified": key_separation,
        "fixture_mode": fixture_mode,
        "owner_authenticated": owner_authenticated,
        "production_gate_approved": False,
        "production_dispatch_allowed": False,
        "iso_release_allowed": False,
    }
    verification_digest = _digest(TRUST_VERIFICATION_DOMAIN, unsigned)
    return VerifiedTrustRoot(
        document=document,
        trust_root_digest=document["trust_root_digest"],
        owner_identity=owner_identity,
        build_node_identity=node_identity,
        signature_verified=True,
        local_owner_pin_verified=True,
        local_build_node_pin_verified=True,
        key_separation_verified=True,
        fixture_mode=fixture_mode,
        owner_authenticated=owner_authenticated,
        verification_digest=verification_digest,
    )


def create_trust_state(
    *, verified_trust_root: VerifiedTrustRoot,
    previous_state: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Derive a local monotonic admission state from a verified trust root."""
    if not isinstance(verified_trust_root, VerifiedTrustRoot):
        raise PolicyError("Phase 40 verified trust root is required")
    document = verified_trust_root.document
    generation = document["generation"]
    if previous_state is None:
        if generation != 1:
            raise PolicyError(
                "Phase 40 initial trust state must start at generation one")
        previous_digest = "0" * 64
    else:
        previous = parse_trust_state(previous_state)
        if generation != previous["generation"] + 1:
            raise PolicyError(
                "Phase 40 trust-state generation is not strictly consecutive")
        if document["trust_root_digest"] == previous["trust_root_digest"]:
            raise PolicyError("Phase 40 trust-root rotation reused the old root")
        previous_digest = previous["state_digest"]
    fixture_mode = verified_trust_root.fixture_mode
    owner_authenticated = bool(
        verified_trust_root.owner_authenticated and not fixture_mode)
    unsigned = {
        "format": TRUST_STATE_FORMAT,
        "contract_digest": phase40_contract_digest(),
        "phase39_contract_digest": PHASE39_CONTRACT_DIGEST,
        "generation": generation,
        "trust_root_digest": verified_trust_root.trust_root_digest,
        "trust_root_verification_digest": (
            verified_trust_root.verification_digest),
        "previous_state_digest": previous_digest,
        "owner_primary_fingerprint": (
            verified_trust_root.owner_identity.primary_fingerprint),
        "owner_job_signer_fingerprint": (
            verified_trust_root.owner_identity.signing_fingerprint),
        "owner_keyring_sha256": (
            verified_trust_root.owner_identity.keyring.sha256),
        "build_node_primary_fingerprint": (
            verified_trust_root.build_node_identity.primary_fingerprint),
        "build_node_result_signer_fingerprint": (
            verified_trust_root.build_node_identity.signing_fingerprint),
        "build_node_keyring_sha256": (
            verified_trust_root.build_node_identity.keyring.sha256),
        "build_node_id": document["build_node"]["node_id"],
        "allowed_gate_names": list(phase39.GATE_NAMES),
        "fixture_mode": fixture_mode,
        "owner_trust_authenticated": owner_authenticated,
        "production_gate_approved": False,
        "production_dispatch_allowed": False,
        "iso_release_allowed": False,
    }
    return {**unsigned, "state_digest": _digest(TRUST_STATE_DOMAIN, unsigned)}


def parse_trust_state(value: Mapping[str, Any]) -> dict[str, Any]:
    required = set(trust_state_schema()["required"])
    if type(value) is not dict or set(value) != required:
        raise PolicyError("Phase 40 trust-state fields are not closed")
    candidate = json.loads(canonical_json_bytes(value))
    if candidate["format"] != TRUST_STATE_FORMAT:
        raise PolicyError("Phase 40 trust-state format is invalid")
    if candidate["contract_digest"] != phase40_contract_digest():
        raise PolicyError("Phase 40 trust-state contract identity drifted")
    if candidate["phase39_contract_digest"] != PHASE39_CONTRACT_DIGEST:
        raise PolicyError("Phase 40 trust-state Phase 39 identity drifted")
    if type(candidate["generation"]) is not int or candidate["generation"] < 1:
        raise PolicyError("Phase 40 trust-state generation is invalid")
    for field in (
        "trust_root_digest", "trust_root_verification_digest",
        "previous_state_digest", "owner_keyring_sha256",
        "build_node_keyring_sha256",
    ):
        _sha256(candidate[field], f"Phase 40 trust-state {field}")
    for field in (
        "owner_primary_fingerprint", "owner_job_signer_fingerprint",
        "build_node_primary_fingerprint",
        "build_node_result_signer_fingerprint",
    ):
        _fingerprint(candidate[field], f"Phase 40 trust-state {field}")
    _token(candidate["build_node_id"], "Phase 40 trust-state build-node ID")
    if candidate["allowed_gate_names"] != list(phase39.GATE_NAMES):
        raise PolicyError("Phase 40 trust-state gate allowlist drifted")
    for field in (
        "fixture_mode", "owner_trust_authenticated",
        "production_gate_approved", "production_dispatch_allowed",
        "iso_release_allowed",
    ):
        if type(candidate[field]) is not bool:
            raise PolicyError(f"Phase 40 trust-state {field} is invalid")
    if (candidate["production_gate_approved"]
            or candidate["production_dispatch_allowed"]
            or candidate["iso_release_allowed"]):
        raise PolicyError("Phase 40 trust state cannot promote release gates")
    if candidate["owner_trust_authenticated"] == candidate["fixture_mode"]:
        raise PolicyError(
            "Phase 40 fixture/authenticated trust-state relationship is invalid")
    if candidate["generation"] == 1:
        if candidate["previous_state_digest"] != "0" * 64:
            raise PolicyError(
                "Phase 40 initial trust state has a previous-state digest")
    elif candidate["previous_state_digest"] == "0" * 64:
        raise PolicyError(
            "Phase 40 rotated trust state lacks a previous-state digest")
    unsigned = {key: candidate[key] for key in candidate if key != "state_digest"}
    expected = _digest(TRUST_STATE_DOMAIN, unsigned)
    if candidate["state_digest"] != expected:
        raise PolicyError("Phase 40 trust-state digest is invalid")
    return candidate


def _strict_state(value: Mapping[str, Any]) -> dict[str, Any]:
    """Compatibility alias used by the gate-specific semantic verifier."""
    return parse_trust_state(value)


def publish_trust_state(path: Path, value: Mapping[str, Any]) -> dict[str, Any]:
    """Atomically publish an initial or consecutive local trust state.

    The state contains no secret material.  A private lock and directory fsync
    make rollback attempts and concurrent writers fail closed.
    """
    state = parse_trust_state(value)
    destination = path.absolute()
    parent = destination.parent
    parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if parent.is_symlink():
        raise PolicyError("Phase 40 trust-state parent cannot be a symbolic link")
    parent_info = parent.stat()
    if (not stat.S_ISDIR(parent_info.st_mode)
            or stat.S_IMODE(parent_info.st_mode) & 0o022
            or parent_info.st_uid not in {0, os.getuid()}):
        raise PolicyError("Phase 40 trust-state parent is not private")
    lock_path = parent / f".{destination.name}.lock"
    lock_flags = (
        os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        lock_fd = os.open(lock_path, lock_flags, 0o600)
    except OSError as exc:
        raise PolicyError("Phase 40 trust-state lock cannot be opened") from exc
    try:
        os.fchmod(lock_fd, 0o600)
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        if destination.exists() or destination.is_symlink():
            measured, current_bytes = measure_file(
                destination, maximum=MAX_TRUST_ROOT_BYTES,
                context="Phase 40 current trust state")
            del measured
            current = parse_trust_state(
                _strict_json(current_bytes, "Phase 40 current trust state"))
            if (state["generation"] != current["generation"] + 1
                    or state["previous_state_digest"]
                        != current["state_digest"]):
                raise PolicyError(
                    "Phase 40 trust-state update is stale or non-monotonic")
        elif (state["generation"] != 1
              or state["previous_state_digest"] != "0" * 64):
            raise PolicyError("Phase 40 initial trust-state publication is invalid")
        payload = canonical_json_bytes(state)
        fd, raw = tempfile.mkstemp(prefix=".phase40-state-", dir=parent)
        temporary = Path(raw)
        try:
            os.fchmod(fd, 0o600)
            view = memoryview(payload)
            while view:
                written = os.write(fd, view)
                if written <= 0:
                    raise PolicyError("Phase 40 trust-state write did not complete")
                view = view[written:]
            os.fsync(fd)
            os.close(fd)
            fd = -1
            os.replace(temporary, destination)
            directory_fd = os.open(
                parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        finally:
            if fd >= 0:
                os.close(fd)
            temporary.unlink(missing_ok=True)
    finally:
        fcntl.flock(lock_fd, fcntl.LOCK_UN)
        os.close(lock_fd)
    return state


def _artifact_manifest_record(role: str, measured: MeasuredFile) -> dict[str, Any]:
    if measured.filename != STAGED_FILENAMES[role]:
        raise PolicyError(f"Phase 40 staged filename drifted for {role}")
    return {
        "role": role,
        "staged_filename": measured.filename,
        "sha256": measured.sha256,
        "bytes": measured.bytes,
        "mode": measured.mode,
    }


def create_input_closure_manifest(
    *, trust_root_digest: str, generation: int,
    created_unix: int, expires_unix: int,
    artifacts: Sequence[Mapping[str, Any]],
    publisher_admission_receipts: Sequence[Mapping[str, Any]],
    fixture_mode: bool,
) -> dict[str, Any]:
    trust_digest = _sha256(trust_root_digest, "Phase 40 trust-root digest")
    if (type(generation) is not int or generation < 1
            or type(created_unix) is not int or type(expires_unix) is not int
            or created_unix < 1 or not created_unix < expires_unix
            or expires_unix > created_unix + MAX_MANIFEST_LIFETIME):
        raise PolicyError("Phase 40 input-closure lifetime is invalid")
    if type(fixture_mode) is not bool:
        raise PolicyError("Phase 40 input-closure fixture state is invalid")
    if type(artifacts) not in {list, tuple} or len(artifacts) != len(ARTIFACT_ROLES):
        raise PolicyError("Phase 40 input artifact inventory is incomplete")
    checked_artifacts: list[dict[str, Any]] = []
    for expected_role, raw in zip(ARTIFACT_ROLES, artifacts, strict=True):
        fields = {"role", "staged_filename", "sha256", "bytes", "mode"}
        if type(raw) is not dict or set(raw) != fields:
            raise PolicyError("Phase 40 input artifact fields are not closed")
        item = dict(raw)
        if item["role"] != expected_role:
            raise PolicyError("Phase 40 input artifact role order drifted")
        if item["staged_filename"] != STAGED_FILENAMES[expected_role]:
            raise PolicyError("Phase 40 input artifact filename drifted")
        _sha256(item["sha256"], f"Phase 40 artifact {expected_role}")
        if type(item["bytes"]) is not int or not (
                1 <= item["bytes"] <= ROLE_LIMITS[expected_role]):
            raise PolicyError("Phase 40 input artifact size is invalid")
        if type(item["mode"]) is not int or not (0 <= item["mode"] <= 0o7777):
            raise PolicyError("Phase 40 input artifact mode is invalid")
        if item["mode"] & 0o022 or item["mode"] & 0o7000:
            raise PolicyError("Phase 40 input artifact mode is unsafe")
        checked_artifacts.append(item)
    if (not fixture_mode
            and checked_artifacts[0]["sha256"] != RUST_ARCHIVE_SHA256):
        raise PolicyError("Phase 40 non-fixture Rust archive digest is not pinned")
    if type(publisher_admission_receipts) not in {list, tuple} or len(
            publisher_admission_receipts) != len(PUBLISHER_ADMISSION_RECEIPT_ROLES):
        raise PolicyError("Phase 40 publisher admission receipt inventory is incomplete")
    receipts: list[dict[str, Any]] = []
    for expected_role, raw in zip(
            PUBLISHER_ADMISSION_RECEIPT_ROLES,
            publisher_admission_receipts, strict=True):
        fields = {"role", "receipt_digest", "verified"}
        if type(raw) is not dict or set(raw) != fields or raw["role"] != expected_role:
            raise PolicyError("Phase 40 publisher receipt role order drifted")
        receipt = {
            "role": expected_role,
            "receipt_digest": _sha256(
                raw["receipt_digest"], f"Phase 40 receipt {expected_role}"),
            "verified": raw["verified"],
        }
        if type(receipt["verified"]) is not bool:
            raise PolicyError("Phase 40 publisher receipt state is invalid")
        if fixture_mode and receipt["verified"]:
            raise PolicyError("Phase 40 fixture cannot verify publisher admission")
        receipts.append(receipt)
    unsigned = {
        "format": INPUT_CLOSURE_FORMAT,
        "contract_digest": phase40_contract_digest(),
        "trust_root_digest": trust_digest,
        "phase39_contract_digest": PHASE39_CONTRACT_DIGEST,
        "generation": generation,
        "created_unix": created_unix,
        "expires_unix": expires_unix,
        "artifact_count": len(ARTIFACT_ROLES),
        "artifacts": checked_artifacts,
        "publisher_admission_receipts": receipts,
        "fixture_mode": fixture_mode,
        "owner_inventory_is_publisher_admission": False,
        "production_gate_approved": False,
        "production_dispatch_allowed": False,
        "iso_release_allowed": False,
    }
    return {
        **unsigned,
        "input_closure_digest": _digest(INPUT_CLOSURE_DOMAIN, unsigned),
    }


def parse_input_closure(value: Mapping[str, Any], *, now_unix: int | None = None) -> dict[str, Any]:
    required = set(input_closure_schema()["required"])
    if type(value) is not dict or set(value) != required:
        raise PolicyError("Phase 40 input-closure fields are not closed")
    candidate = json.loads(canonical_json_bytes(value))
    recreated = create_input_closure_manifest(
        trust_root_digest=candidate["trust_root_digest"],
        generation=candidate["generation"],
        created_unix=candidate["created_unix"],
        expires_unix=candidate["expires_unix"],
        artifacts=candidate["artifacts"],
        publisher_admission_receipts=candidate["publisher_admission_receipts"],
        fixture_mode=candidate["fixture_mode"],
    )
    if candidate != recreated:
        raise PolicyError("Phase 40 input-closure content or digest drifted")
    if now_unix is not None:
        if type(now_unix) is not int or now_unix < candidate["created_unix"] \
                or now_unix > candidate["expires_unix"]:
            raise PolicyError("Phase 40 input closure is not valid at this time")
    return candidate


def measure_input_root(input_root: Path) -> tuple[InputArtifact, ...]:
    """Measure the exact input closure through one stable directory descriptor."""
    root = input_root.absolute()
    flags = (os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
             | getattr(os, "O_CLOEXEC", 0)
             | getattr(os, "O_NOFOLLOW", 0))
    try:
        root_fd = os.open(root, flags)
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise PolicyError(
                "Phase 40 input root cannot be a symbolic link") from exc
        raise PolicyError(
            "Phase 40 input root cannot be opened as a private directory"
        ) from exc
    try:
        root_before = os.fstat(root_fd)
        if (not stat.S_ISDIR(root_before.st_mode)
                or stat.S_IMODE(root_before.st_mode) & 0o022
                or root_before.st_uid not in {0, os.getuid()}):
            raise PolicyError("Phase 40 input root is not a private directory")
        expected_names = sorted(STAGED_FILENAMES.values())
        try:
            observed_names = sorted(os.listdir(root_fd))
        except OSError as exc:
            raise PolicyError(
                "Phase 40 input root inventory cannot be read safely"
            ) from exc
        if observed_names != expected_names:
            raise PolicyError("Phase 40 input root has missing or extra artifacts")
        artifacts: list[InputArtifact] = []
        identities: set[tuple[int, int]] = set()
        child_flags = (os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
                       | getattr(os, "O_NOFOLLOW", 0))
        for role in ARTIFACT_ROLES:
            filename = STAGED_FILENAMES[role]
            try:
                fd = os.open(filename, child_flags, dir_fd=root_fd)
            except OSError as exc:
                if exc.errno == errno.ELOOP:
                    raise PolicyError(
                        f"Phase 40 input artifact {role} cannot be symbolic") from exc
                raise PolicyError(
                    f"Phase 40 input artifact {role} cannot be opened safely"
                ) from exc
            try:
                measured, payload = _measure_open_file(
                    fd, display_path=os.fspath(root / filename),
                    filename=filename, maximum=ROLE_LIMITS[role],
                    context=f"Phase 40 input artifact {role}",
                    allow_empty=False, capture_payload=False,
                )
            finally:
                os.close(fd)
            if payload is not None:
                raise AssertionError(
                    "Phase 40 input artifact payload was retained in memory")
            identity = (measured.device, measured.inode)
            if identity in identities:
                raise PolicyError(
                    "Phase 40 input artifacts alias a file identity")
            identities.add(identity)
            artifacts.append(InputArtifact(
                role=role,
                staged_filename=measured.filename,
                sha256=measured.sha256,
                bytes=measured.bytes,
                mode=measured.mode,
                device=measured.device,
                inode=measured.inode,
            ))
        root_after = os.fstat(root_fd)
        if _directory_identity(root_before) != _directory_identity(root_after):
            raise PolicyError(
                "Phase 40 input root changed while artifacts were measured")
        return tuple(artifacts)
    finally:
        os.close(root_fd)


def verify_signed_input_closure(
    *, manifest_path: Path, signature_path: Path,
    owner_keyring_path: Path, input_root: Path,
    verified_trust_root: VerifiedTrustRoot,
    now_unix: int, gpgv_executable: str | Path = "/usr/bin/gpgv",
) -> VerifiedInputClosure:
    if not isinstance(verified_trust_root, VerifiedTrustRoot):
        raise PolicyError("Phase 40 verified trust root is required")
    manifest_meta, manifest_bytes = measure_file(
        manifest_path, maximum=MAX_INPUT_MANIFEST_BYTES,
        context="Phase 40 signed input manifest")
    _, signature = measure_file(
        signature_path, maximum=MAX_SIGNATURE_BYTES,
        context="Phase 40 input-manifest signature")
    owner_meta, owner_key = measure_file(
        owner_keyring_path, maximum=MAX_KEYRING_BYTES,
        context="Phase 40 input-manifest owner keyring")
    if owner_meta.sha256 != verified_trust_root.owner_identity.keyring.sha256:
        raise PolicyError("Phase 40 input manifest used a different owner keyring")
    document = parse_input_closure(
        _strict_json(manifest_bytes, "Phase 40 input closure"), now_unix=now_unix)
    if document["trust_root_digest"] != verified_trust_root.trust_root_digest:
        raise PolicyError("Phase 40 input closure binds another trust root")
    if document["fixture_mode"] != verified_trust_root.fixture_mode:
        raise PolicyError("Phase 40 trust-root and input fixture states differ")
    phase39._verify_signature(  # type: ignore[attr-defined]
        payload=manifest_bytes, signature=signature, keyring=owner_key,
        expected_fingerprint=(
            verified_trust_root.owner_identity.signing_fingerprint),
        gpgv_executable=gpgv_executable,
        fixture_mode=document["fixture_mode"],
        role="phase40-owner-input-closure")
    measured = measure_input_root(input_root)
    for expected, actual in zip(document["artifacts"], measured, strict=True):
        if (
            expected["role"] != actual.role
            or expected["staged_filename"] != actual.staged_filename
            or expected["sha256"] != actual.sha256
            or expected["bytes"] != actual.bytes
            or expected["mode"] != actual.mode
        ):
            raise PolicyError("Phase 40 input artifact differs from signed manifest")
    exact_rust = measured[0].sha256 == RUST_ARCHIVE_SHA256
    if not document["fixture_mode"] and not exact_rust:
        raise PolicyError("Phase 40 Rust archive differs from the pinned release")
    receipts_verified = all(
        item["verified"] for item in document["publisher_admission_receipts"])
    owner_inventory_authenticated = bool(
        verified_trust_root.owner_authenticated and not document["fixture_mode"])
    ready = bool(owner_inventory_authenticated and exact_rust and receipts_verified)
    unsigned = {
        "format": INPUT_CLOSURE_VERIFICATION_FORMAT,
        "manifest_sha256": manifest_meta.sha256,
        "input_closure_digest": document["input_closure_digest"],
        "trust_root_digest": document["trust_root_digest"],
        "artifact_set_digest": hashlib.sha256(
            b"SECURITYOPS-PHASE40-ARTIFACT-SET-V1\x00"
            + canonical_json_bytes([item.to_dict() for item in measured])
        ).hexdigest(),
        "artifact_count": len(measured),
        "owner_signature_verified": True,
        "exact_inventory_verified": True,
        "all_regular_single_link": True,
        "all_distinct_file_identities": True,
        "exact_rust_archive_bound": exact_rust,
        "owner_inventory_authenticated": owner_inventory_authenticated,
        "publisher_admission_receipts_verified": receipts_verified,
        "fixture_mode": document["fixture_mode"],
        "ready_for_gate1_job": ready,
        "production_gate_approved": False,
        "production_dispatch_allowed": False,
        "iso_release_allowed": False,
    }
    verification_digest = _digest(INPUT_VERIFICATION_DOMAIN, unsigned)
    return VerifiedInputClosure(
        document=document,
        input_closure_digest=document["input_closure_digest"],
        trust_root_digest=document["trust_root_digest"],
        artifacts=measured,
        owner_signature_verified=True,
        exact_inventory_verified=True,
        all_regular_single_link=True,
        all_distinct_file_identities=True,
        exact_rust_archive_bound=exact_rust,
        owner_inventory_authenticated=owner_inventory_authenticated,
        publisher_admission_receipts_verified=receipts_verified,
        fixture_mode=document["fixture_mode"],
        ready_for_gate1_job=ready,
        verification_digest=verification_digest,
    )


def gate1_signing_request_template() -> dict[str, Any]:
    unsigned = {
        "format": SIGNING_REQUEST_FORMAT,
        "status": "BLOCKED_PHASE40_OWNER_MUST_COMPLETE_AND_SIGN_GATE1_JOB",
        "phase40_contract_digest": phase40_contract_digest(),
        "phase39_contract_digest": PHASE39_CONTRACT_DIGEST,
        "gate_name": "authenticated-guix-qt-environment",
        "trust_state_digest": "OWNER_SUPPLIED_64_HEX_DIGEST",
        "trust_root_digest": "OWNER_SUPPLIED_64_HEX_DIGEST",
        "trust_root_verification_digest": "OWNER_SUPPLIED_64_HEX_DIGEST",
        "input_closure_digest": "OWNER_SUPPLIED_64_HEX_DIGEST",
        "input_closure_verification_digest": "OWNER_SUPPLIED_64_HEX_DIGEST",
        "owner_signing_fingerprint": "OWNER_SUPPLIED_40_HEX_FINGERPRINT",
        "build_node_signing_fingerprint": "OWNER_SUPPLIED_40_HEX_FINGERPRINT",
        "build_node_id": "OWNER_SUPPLIED_BUILD_NODE_ID",
        "job_id": 0,
        "created_unix": 0,
        "expires_unix": 0,
        "challenge_nonce": "OWNER_SUPPLIED_64_HEX_RANDOM_NONCE",
        "required_evidence_roles": list(
            phase39.GATE_EVIDENCE_ROLES["authenticated-guix-qt-environment"]),
        "commands": [
            {
                "sequence": 1,
                "argv": [
                    "/gnu/store/OWNER_SUPPLIED-securityops-phase40-bootstrap/bin/securityops-phase40-bootstrap",
                    "verify-node-input",
                    "--trust-state", "/var/lib/securityops/phase40/trust-state.json",
                    "--expected-trust-state-digest", "OWNER_SUPPLIED_64_HEX_DIGEST",
                    "--expected-trust-root-digest", "OWNER_SUPPLIED_64_HEX_DIGEST",
                    "--expected-trust-root-verification-digest", "OWNER_SUPPLIED_64_HEX_DIGEST",
                    "--expected-input-closure-digest", "OWNER_SUPPLIED_64_HEX_DIGEST",
                    "--expected-input-closure-verification-digest", "OWNER_SUPPLIED_64_HEX_DIGEST",
                    "--output", "/evidence/owner-input-closure.json",
                ],
                "network_allowed": False,
            },
            {
                "sequence": 2,
                "argv": [
                    "/gnu/store/OWNER_SUPPLIED-guix/bin/guix",
                    "describe", "--format=json",
                ],
                "network_allowed": False,
            },
            {
                "sequence": 3,
                "argv": [
                    "/gnu/store/OWNER_SUPPLIED-securityops-phase40-bootstrap/bin/securityops-phase40-bootstrap",
                    "attest-guix-qt",
                    "--guix", "/gnu/store/OWNER_SUPPLIED-guix/bin/guix",
                    "--guile", "/gnu/store/OWNER_SUPPLIED-guile/bin/guile",
                    "--guild", "/gnu/store/OWNER_SUPPLIED-guile/bin/guild",
                    "--python", "/gnu/store/OWNER_SUPPLIED-python/bin/python3",
                    "--output", "/evidence/guix-qt-attestation.json",
                ],
                "network_allowed": False,
            },
        ],
        "runtime_handles_secret_keys": False,
        "owner_signature_required": True,
        "build_node_result_signature_required": True,
        "fixture_mode": False,
        "production_gate_approved": False,
        "production_dispatch_allowed": False,
        "iso_release_allowed": False,
    }
    return {**unsigned, "request_digest": _digest(SIGNING_REQUEST_DOMAIN, unsigned)}


def create_gate1_signing_request(
    *, trust_root: VerifiedTrustRoot, trust_state: Mapping[str, Any],
    input_closure: VerifiedInputClosure,
    job_id: int, created_unix: int, expires_unix: int,
    challenge_nonce: str, build_node_id: str,
    bootstrap_executable: str, trust_state_path: str,
    guix_executable: str, guile_executable: str, guild_executable: str,
    python_executable: str,
) -> dict[str, Any]:
    if not isinstance(trust_root, VerifiedTrustRoot) or not isinstance(
            input_closure, VerifiedInputClosure):
        raise PolicyError("Phase 40 verified bootstrap objects are required")
    state = parse_trust_state(trust_state)
    if not trust_root.owner_authenticated or not input_closure.ready_for_gate1_job:
        raise PolicyError("Phase 40 real owner trust and publisher admissions are required")
    if input_closure.trust_root_digest != trust_root.trust_root_digest:
        raise PolicyError("Phase 40 Gate 1 request has mismatched trust roots")
    if (state["trust_root_digest"] != trust_root.trust_root_digest
            or state["trust_root_verification_digest"]
                != trust_root.verification_digest
            or not state["owner_trust_authenticated"]
            or state["fixture_mode"]):
        raise PolicyError("Phase 40 Gate 1 request has an unauthenticated trust state")
    commands = [
        phase39.create_command(
            sequence=1,
            argv=[
                bootstrap_executable, "verify-node-input",
                "--trust-state", _absolute_path(
                    trust_state_path, "Phase 40 trust-state path"),
                "--expected-trust-state-digest", state["state_digest"],
                "--expected-trust-root-digest", trust_root.trust_root_digest,
                "--expected-trust-root-verification-digest",
                trust_root.verification_digest,
                "--expected-input-closure-digest", input_closure.input_closure_digest,
                "--expected-input-closure-verification-digest",
                input_closure.verification_digest,
                "--output", "/evidence/owner-input-closure.json",
            ],
            timeout_seconds=600, network_allowed=False,
            working_directory_label="phase40-gate1-input"),
        phase39.create_command(
            sequence=2,
            argv=[guix_executable, "describe", "--format=json"],
            timeout_seconds=600, network_allowed=False,
            working_directory_label="phase40-gate1-guix"),
        phase39.create_command(
            sequence=3,
            argv=[
                bootstrap_executable, "attest-guix-qt",
                "--guix", guix_executable,
                "--guile", guile_executable,
                "--guild", guild_executable,
                "--python", python_executable,
                "--output", "/evidence/guix-qt-attestation.json",
            ],
            timeout_seconds=1800, network_allowed=False,
            working_directory_label="phase40-gate1-attestation"),
    ]
    job = phase39.create_gate_job(
        gate_name="authenticated-guix-qt-environment",
        job_id=job_id, created_unix=created_unix,
        expires_unix=expires_unix, challenge_nonce=challenge_nonce,
        owner_job_signer_fingerprint=(
            trust_root.owner_identity.signing_fingerprint),
        result_signer_fingerprint=(
            trust_root.build_node_identity.signing_fingerprint),
        build_node_id=build_node_id,
        commands=commands,
        prerequisite_receipt_digests=(),
        fixture_mode=False,
    )
    unsigned = {
        "format": SIGNING_REQUEST_FORMAT,
        "status": "PASS_PHASE40_GATE1_JOB_READY_FOR_OFFLINE_OWNER_SIGNATURE",
        "phase40_contract_digest": phase40_contract_digest(),
        "phase39_contract_digest": PHASE39_CONTRACT_DIGEST,
        "gate_name": "authenticated-guix-qt-environment",
        "trust_state_digest": state["state_digest"],
        "trust_root_digest": trust_root.trust_root_digest,
        "trust_root_verification_digest": trust_root.verification_digest,
        "input_closure_digest": input_closure.input_closure_digest,
        "input_closure_verification_digest": input_closure.verification_digest,
        "owner_signing_fingerprint": trust_root.owner_identity.signing_fingerprint,
        "build_node_signing_fingerprint": (
            trust_root.build_node_identity.signing_fingerprint),
        "build_node_id": _token(build_node_id, "Phase 40 build-node ID"),
        "job": job,
        "runtime_handles_secret_keys": False,
        "owner_signature_required": True,
        "build_node_result_signature_required": True,
        "fixture_mode": False,
        "production_gate_approved": False,
        "production_dispatch_allowed": False,
        "iso_release_allowed": False,
    }
    return {**unsigned, "request_digest": _digest(SIGNING_REQUEST_DOMAIN, unsigned)}



def _open_store_executable(
    path: str | Path, *, label: str,
) -> tuple[MeasuredFile, int, str]:
    """Open and measure a Guix Store executable once for descriptor execution."""
    candidate = Path(path)
    try:
        relative = candidate.relative_to("/gnu/store")
        resolved = candidate.resolve(strict=True)
    except (OSError, ValueError) as exc:
        raise PolicyError(
            f"Phase 40 {label} must be an available canonical Guix Store path"
        ) from exc
    if (
        not candidate.is_absolute()
        or resolved != candidate
        or len(relative.parts) < 2
        or _STORE_ITEM.fullmatch(relative.parts[0]) is None
        or any(part in {"", ".", ".."} or "\\" in part for part in relative.parts)
    ):
        raise PolicyError(
            f"Phase 40 {label} must be an absolute non-symbolic Guix Store path")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(candidate, flags)
    except OSError as exc:
        raise PolicyError(f"Phase 40 {label} cannot be opened safely") from exc
    try:
        before = os.fstat(fd)
        mode = stat.S_IMODE(before.st_mode)
        if (not stat.S_ISREG(before.st_mode)
                or before.st_size < 1
                or before.st_size > 256 * 1024 * 1024
                or not mode & 0o111
                or mode & 0o022
                or mode & 0o7000
                or before.st_uid != 0
                or before.st_gid != 0):
            raise PolicyError(f"Phase 40 {label} has an unsafe executable identity")
        digest = hashlib.sha256()
        remaining = before.st_size
        while remaining:
            block = os.read(fd, min(1024 * 1024, remaining))
            if not block:
                raise PolicyError(f"Phase 40 {label} was truncated while measuring")
            digest.update(block)
            remaining -= len(block)
        if os.read(fd, 1):
            raise PolicyError(f"Phase 40 {label} grew while measuring")
        after = os.fstat(fd)
        if _file_identity(before) != _file_identity(after):
            raise PolicyError(f"Phase 40 {label} changed while measuring")
        os.lseek(fd, 0, os.SEEK_SET)
        measured = MeasuredFile(
            path=os.fspath(candidate), filename=candidate.name,
            sha256=digest.hexdigest(), bytes=after.st_size, mode=mode,
            uid=after.st_uid, gid=after.st_gid, device=after.st_dev,
            inode=after.st_ino,
        )
        return measured, fd, f"/proc/self/fd/{fd}"
    except Exception:
        os.close(fd)
        raise


def _process_group_alive(pid: int) -> bool:
    try:
        os.killpg(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _terminate_process_group(
    pid: int, process: subprocess.Popen[bytes] | None = None,
) -> None:
    """Terminate a process group while reaping the directly owned process."""
    try:
        os.killpg(pid, signal.SIGTERM)
    except ProcessLookupError:
        if process is not None and process.poll() is None:
            process.wait(timeout=1)
        return
    if process is not None and process.poll() is None:
        try:
            process.wait(timeout=1)
        except subprocess.TimeoutExpired:
            pass
    deadline = time.monotonic() + 1.0
    while time.monotonic() < deadline:
        if not _process_group_alive(pid):
            return
        time.sleep(0.01)
    try:
        os.killpg(pid, signal.SIGKILL)
    except ProcessLookupError:
        if process is not None and process.poll() is None:
            process.wait(timeout=1)
        return
    if process is not None and process.poll() is None:
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired as exc:
            raise PolicyError(
                "Phase 40 attestation parent process could not be reaped") from exc
    deadline = time.monotonic() + 1.0
    while time.monotonic() < deadline:
        if not _process_group_alive(pid):
            return
        time.sleep(0.01)
    if _process_group_alive(pid):
        raise PolicyError(
            "Phase 40 attestation descendant process group could not be terminated")


def _bounded_command(
    argv: Sequence[str], *, inherited_fds: Sequence[int] = (),
    timeout: int = 30, maximum: int = 2 * 1024 * 1024,
) -> dict[str, Any]:
    """Run a fixed argv with bounded streaming output and process-tree cleanup."""
    if type(argv) not in {list, tuple} or not argv:
        raise PolicyError("Phase 40 attestation command is invalid")
    checked_argv: list[str] = []
    total_argv = 0
    for item in argv:
        if (type(item) is not str or not item or "\x00" in item
                or len(item.encode("utf-8")) > 4096):
            raise PolicyError("Phase 40 attestation command argument is invalid")
        total_argv += len(item.encode("utf-8"))
        checked_argv.append(item)
    if len(checked_argv) > 128 or total_argv > 64 * 1024:
        raise PolicyError("Phase 40 attestation argv exceeds its bound")
    executable = Path(checked_argv[0])
    if not executable.is_absolute():
        raise PolicyError("Phase 40 attestation command is not absolute")
    if type(timeout) is not int or not 1 <= timeout <= 3600:
        raise PolicyError("Phase 40 attestation timeout is invalid")
    if type(maximum) is not int or not 1 <= maximum <= 16 * 1024 * 1024:
        raise PolicyError("Phase 40 attestation output limit is invalid")
    pass_fds = tuple(inherited_fds)
    if (len(set(pass_fds)) != len(pass_fds)
            or any(type(item) is not int or item < 0 for item in pass_fds)):
        raise PolicyError("Phase 40 attestation descriptor inventory is invalid")
    process: subprocess.Popen[bytes] | None = None
    stdout = bytearray()
    stderr = bytearray()
    started = time.monotonic()
    selector = selectors.DefaultSelector()
    try:
        process = subprocess.Popen(
            checked_argv, executable=checked_argv[0],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, close_fds=True, pass_fds=pass_fds,
            start_new_session=True,
            env={
                "PATH": "/run/current-system/profile/bin:/usr/bin:/bin",
                "LANG": "C", "LC_ALL": "C",
                "PYTHONNOUSERSITE": "1", "PYTHONDONTWRITEBYTECODE": "1",
                "PYTHONSAFEPATH": "1", "HOME": "/nonexistent",
            },
        )
        assert process.stdout is not None and process.stderr is not None
        for stream, label in ((process.stdout, "stdout"), (process.stderr, "stderr")):
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, label)
        deadline = started + timeout
        failure = ""
        while selector.get_map() or process.poll() is None:
            if time.monotonic() >= deadline:
                failure = "Phase 40 attestation command timed out"
                break
            events = selector.select(timeout=0.01)
            for key, _ in events:
                current_total = len(stdout) + len(stderr)
                allowance = max(1, min(65536, maximum + 1 - current_total))
                try:
                    chunk = os.read(key.fileobj.fileno(), allowance)
                except BlockingIOError:
                    continue
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                target = stdout if key.data == "stdout" else stderr
                target.extend(chunk)
                if len(stdout) + len(stderr) > maximum:
                    failure = "Phase 40 attestation command output exceeded its bound"
                    break
            if failure:
                break
        if failure:
            _terminate_process_group(process.pid, process)
            raise PolicyError(failure)
        returncode = process.wait(timeout=5)
        time.sleep(0.02)
        if _process_group_alive(process.pid):
            _terminate_process_group(process.pid)
            raise PolicyError(
                "Phase 40 attestation command left a live descendant process group")
    except (OSError, subprocess.SubprocessError) as exc:
        if process is not None and process.poll() is None:
            _terminate_process_group(process.pid, process)
        raise PolicyError("Phase 40 attestation command did not complete") from exc
    finally:
        selector.close()
        if process is not None:
            for stream in (process.stdout, process.stderr):
                if stream is not None:
                    stream.close()
    if returncode != 0:
        raise PolicyError("Phase 40 attestation command failed")
    try:
        stdout_text = bytes(stdout).decode("utf-8", errors="strict")
        stderr_text = bytes(stderr).decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise PolicyError("Phase 40 attestation command output is not UTF-8") from exc
    return {
        "argv": checked_argv,
        "returncode": returncode,
        "stdout_sha256": hashlib.sha256(stdout).hexdigest(),
        "stdout_bytes": len(stdout),
        "stderr_sha256": hashlib.sha256(stderr).hexdigest(),
        "stderr_bytes": len(stderr),
        "stdout": stdout_text,
        "stderr": stderr_text,
        "elapsed_ns": int((time.monotonic() - started) * 1_000_000_000),
        "output_limit_bytes": maximum,
        "timed_out": False,
        "output_limited": False,
        "process_group_clean": True,
    }


def attest_guix_qt_environment(
    *, guix_executable: str | Path, guile_executable: str | Path,
    guild_executable: str | Path, python_executable: str | Path,
) -> dict[str, Any]:
    """Measure a real Guix/Guile/Qt/PySide environment without approving Gate 1."""
    requested = {
        "guix": guix_executable,
        "guile": guile_executable,
        "guild": guild_executable,
        "python3": python_executable,
    }
    executables: dict[str, dict[str, Any]] = {}
    execution_paths: dict[str, str] = {}
    descriptors: dict[str, int] = {}
    try:
        for label, path in requested.items():
            measured, fd, execution_path = _open_store_executable(path, label=label)
            executables[label] = measured.to_dict()
            descriptors[label] = fd
            execution_paths[label] = execution_path
        commands = {
            "guix_version": _bounded_command(
                [execution_paths["guix"], "--version"],
                inherited_fds=(descriptors["guix"],)),
            "guix_describe": _bounded_command(
                [execution_paths["guix"], "describe", "--format=json"],
                inherited_fds=(descriptors["guix"],)),
            "guile_version": _bounded_command(
                [execution_paths["guile"], "--version"],
                inherited_fds=(descriptors["guile"],)),
            "guild_version": _bounded_command(
                [execution_paths["guild"], "--version"],
                inherited_fds=(descriptors["guild"],)),
        }
        probe_source = (
            "import json, pathlib, PySide6, PySide6.QtCore; "
            "print(json.dumps({"
            "'pyside_version': getattr(PySide6, '__version__', ''),"
            "'qt_version': PySide6.QtCore.qVersion(),"
            "'pyside_origin': str(pathlib.Path(PySide6.__file__).resolve()),"
            "'qtcore_origin': str(pathlib.Path(PySide6.QtCore.__file__).resolve())"
            "}, sort_keys=True, separators=(',', ':')))"
        )
        probe = _bounded_command(
            [execution_paths["python3"], "-I", "-s", "-c", probe_source],
            inherited_fds=(descriptors["python3"],))
    finally:
        for fd in descriptors.values():
            try:
                os.close(fd)
            except OSError:
                pass
    try:
        module = json.loads(probe["stdout"].strip())
    except json.JSONDecodeError as exc:
        raise PolicyError("Phase 40 PySide6 probe did not emit strict JSON") from exc
    expected_module_fields = {
        "pyside_version", "qt_version", "pyside_origin", "qtcore_origin",
    }
    if type(module) is not dict or set(module) != expected_module_fields:
        raise PolicyError("Phase 40 PySide6 probe fields are not closed")
    for field in ("pyside_origin", "qtcore_origin"):
        origin = module[field]
        if type(origin) is not str or not origin.startswith("/gnu/store/"):
            raise PolicyError("Phase 40 Qt/PySide module origin is not in the Guix Store")
    unsigned = {
        "format": "securityops-phase40-guix-qt-node-attestation/1",
        "phase40_contract_digest": phase40_contract_digest(),
        "executables": executables,
        "commands": commands,
        "python_module_probe": {
            **module,
            "command_stdout_sha256": probe["stdout_sha256"],
            "command_stderr_sha256": probe["stderr_sha256"],
        },
        "all_executables_from_guix_store": True,
        "descriptor_bound_executable_identity": True,
        "qt_pyside_origins_from_guix_store": True,
        "python_user_site_allowed": False,
        "attestation_is_gate_approval": False,
        "production_gate_approved": False,
        "production_dispatch_allowed": False,
        "iso_release_allowed": False,
    }
    return {
        **unsigned,
        "attestation_digest": hashlib.sha256(
            b"SECURITYOPS-PHASE40-GUIX-QT-ATTESTATION-V1\x00"
            + canonical_json_bytes(unsigned)).hexdigest(),
    }


def _write_atomic(path: Path, payload: bytes, mode: int) -> None:
    parent = path.parent.absolute()
    if parent.is_symlink():
        raise PolicyError("Phase 40 output parent cannot be a symbolic link")
    parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = parent.stat()
    if (not stat.S_ISDIR(info.st_mode)
            or stat.S_IMODE(info.st_mode) & 0o022
            or info.st_uid not in {0, os.getuid()}):
        raise PolicyError("Phase 40 output parent is not private")
    if path.exists() or path.is_symlink():
        raise PolicyError("Phase 40 output destination already exists")
    fd, raw = tempfile.mkstemp(prefix=".phase40-", dir=parent)
    temporary = Path(raw)
    try:
        os.fchmod(fd, mode)
        view = memoryview(payload)
        written = 0
        while written < len(view):
            count = os.write(fd, view[written:])
            if count <= 0:
                raise PolicyError("Phase 40 output write did not complete")
            written += count
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


def _template_trust_root() -> dict[str, Any]:
    return {
        "format": TRUST_ROOT_FORMAT,
        "contract_digest": phase40_contract_digest(),
        "phase39_contract_digest": PHASE39_CONTRACT_DIGEST,
        "phase39_identities": dict(PHASE39_IDENTITIES),
        "generation": 1,
        "created_unix": 0,
        "expires_unix": 0,
        "owner": {
            "role": "owner-job-signing",
            "primary_fingerprint": "OWNER_SUPPLIED_40_HEX_FINGERPRINT",
            "signing_fingerprint": "OWNER_SUPPLIED_40_HEX_FINGERPRINT",
            "keyring_filename": "owner-job-keyring.gpg",
            "keyring_sha256": "OWNER_SUPPLIED_64_HEX_DIGEST",
            "keyring_bytes": 0,
        },
        "build_node": {
            "role": "build-node-result-signing",
            "node_id": "OWNER_SUPPLIED_BUILD_NODE_ID",
            "primary_fingerprint": "OWNER_SUPPLIED_40_HEX_FINGERPRINT",
            "signing_fingerprint": "OWNER_SUPPLIED_40_HEX_FINGERPRINT",
            "keyring_filename": "build-node-result-keyring.gpg",
            "keyring_sha256": "OWNER_SUPPLIED_64_HEX_DIGEST",
            "keyring_bytes": 0,
        },
        "key_separation": {
            "distinct_primary_fingerprints": True,
            "distinct_signing_fingerprints": True,
            "distinct_keyring_digests": True,
            "owner_secret_on_build_node_allowed": False,
            "build_node_secret_on_owner_host_allowed": False,
        },
        "fixture_mode": False,
        "production_gate_approved": False,
        "production_dispatch_allowed": False,
        "iso_release_allowed": False,
        "trust_root_digest": "OWNER_COMPUTED_BY_TOOL",
    }


def _template_input_closure() -> dict[str, Any]:
    return {
        "format": INPUT_CLOSURE_FORMAT,
        "contract_digest": phase40_contract_digest(),
        "trust_root_digest": "OWNER_SUPPLIED_64_HEX_DIGEST",
        "phase39_contract_digest": PHASE39_CONTRACT_DIGEST,
        "generation": 1,
        "created_unix": 0,
        "expires_unix": 0,
        "artifact_count": len(ARTIFACT_ROLES),
        "artifacts": [
            {
                "role": role,
                "staged_filename": STAGED_FILENAMES[role],
                "sha256": (
                    RUST_ARCHIVE_SHA256 if role == "rust-archive"
                    else "OWNER_SUPPLIED_64_HEX_DIGEST"
                ),
                "bytes": 0,
                "mode": 0o400,
            }
            for role in ARTIFACT_ROLES
        ],
        "publisher_admission_receipts": [
            {
                "role": role,
                "receipt_digest": "OWNER_SUPPLIED_64_HEX_DIGEST",
                "verified": False,
            }
            for role in PUBLISHER_ADMISSION_RECEIPT_ROLES
        ],
        "fixture_mode": False,
        "owner_inventory_is_publisher_admission": False,
        "production_gate_approved": False,
        "production_dispatch_allowed": False,
        "iso_release_allowed": False,
        "input_closure_digest": "OWNER_COMPUTED_BY_TOOL",
    }


def generate_bootstrap_kit(destination: Path) -> dict[str, Any]:
    root = destination.absolute()
    if root.exists() or root.is_symlink():
        raise PolicyError("Phase 40 bootstrap-kit destination already exists")
    parent = root.parent
    parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix=".phase40-kit-", dir=parent))
    temporary.chmod(0o700)
    try:
        files: dict[str, tuple[bytes, int]] = {
            "README.md": ((
                "# Security Ops OS Phase 40 owner bootstrap kit\n\n"
                "This kit never creates, imports, or uses a secret signing key. "
                "Complete the templates on an offline owner-controlled host, "
                "export minimal public verification keyrings, verify every digest, "
                "and sign the canonical trust root, input closure, and Phase 39 job "
                "using your separate offline signing workflow. A completed transport "
                "inventory is not publisher admission and cannot close a gate.\n"
            ).encode(), 0o444),
            "README.pt-BR.md": ((
                "# Kit de bootstrap do proprietário — Security Ops OS Fase 40\n\n"
                "Este kit nunca cria, importa ou usa uma chave secreta de assinatura. "
                "Preencha os modelos em um host offline controlado pelo proprietário, "
                "exporte chaveiros públicos mínimos, verifique todos os resumos e "
                "assine a raiz de confiança, o conjunto de entradas e o job da Fase 39 "
                "em um fluxo de assinatura separado. Integridade de transporte não é "
                "admissão do publicador e não fecha gate de produção.\n"
            ).encode(), 0o444),
            "phase40-owner-trust-contract.json": (
                canonical_json_bytes(phase40_contract()), 0o444),
            "phase40-owner-trust-root.schema.json": (
                canonical_json_bytes(trust_root_schema()), 0o444),
            "phase40-owner-trust-state.schema.json": (
                canonical_json_bytes(trust_state_schema()), 0o444),
            "phase40-owner-input-closure.schema.json": (
                canonical_json_bytes(input_closure_schema()), 0o444),
            "trust-root.template.json": (
                canonical_json_bytes(_template_trust_root()), 0o444),
            "input-closure.template.json": (
                canonical_json_bytes(_template_input_closure()), 0o444),
            "gate1-signing-request.template.json": (
                canonical_json_bytes(gate1_signing_request_template()), 0o444),
            "scripts/inspect-verification-keyring.py": ((
                "#!/usr/bin/env python3\n"
                "# Import phase40_owner_trust from the measured runtime and call "
                "inspect_verification_keyring with out-of-band fingerprints.\n"
                "raise SystemExit('Use securityops-phase40-bootstrap inspect-keyring')\n"
            ).encode(), 0o555),
            "scripts/verify-owner-bootstrap.py": ((
                "#!/usr/bin/env python3\n"
                "raise SystemExit('Use securityops-phase40-bootstrap verify-bootstrap')\n"
            ).encode(), 0o555),
            "scripts/create-gate1-job.py": ((
                "#!/usr/bin/env python3\n"
                "raise SystemExit('Use securityops-phase40-bootstrap create-gate1-job')\n"
            ).encode(), 0o555),
        }
        if tuple(sorted(files)) != tuple(sorted(KIT_FILES)):
            raise PolicyError("Phase 40 bootstrap-kit inventory drifted")
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
            "status": "PASS_PHASE40_DETERMINISTIC_SECRET_FREE_BOOTSTRAP_KIT_GENERATED",
            "phase40_contract_digest": phase40_contract_digest(),
            "files": records,
            "file_count": len(records),
            "contains_secret_keys": False,
            "invokes_secret_key_generation": False,
            "invokes_secret_key_signing": False,
            "production_gate_approved": False,
            "production_dispatch_allowed": False,
            "iso_release_allowed": False,
        }
        return {**unsigned, "kit_digest": _digest(KIT_DOMAIN, unsigned)}
    finally:
        if temporary.exists():
            shutil.rmtree(temporary)


def run_phase40_negative_matrix() -> dict[str, Any]:
    base = phase40_contract()
    cases: list[dict[str, Any]] = []

    def mutate(path: Sequence[str], value: Any) -> None:
        candidate = json.loads(canonical_json_bytes(base))
        target: Any = candidate
        for key in path[:-1]:
            target = target[key]
        target[path[-1]] = value
        cases.append(candidate)

    extra = json.loads(canonical_json_bytes(base))
    extra["unexpected"] = True
    cases.append(extra)
    mutate(("phase39_contract_digest",), "0" * 64)
    mutate(("phase39_identities", "runtime_commit"), "0" * 40)
    mutate(("key_policy", "owner_and_build_node_keyrings_separate"), False)
    mutate(("key_policy", "secret_key_packets_allowed"), True)
    mutate(("key_policy", "dsa_allowed"), True)
    mutate(("key_policy", "ambient_gnupg_configuration_allowed"), True)
    mutate(("key_policy", "original_paths_reopened_after_measurement"), True)
    mutate(("key_policy", "local_owner_fingerprint_pin_required"), False)
    mutate(("key_policy", "local_owner_keyring_digest_pin_required"), False)
    mutate(("key_policy", "local_build_node_fingerprint_pin_required"), False)
    mutate(("key_policy", "local_build_node_keyring_digest_pin_required"), False)
    removed = json.loads(canonical_json_bytes(base))
    removed["input_closure"]["artifact_roles"].pop()
    cases.append(removed)
    reordered = json.loads(canonical_json_bytes(base))
    roles = reordered["input_closure"]["artifact_roles"]
    roles[0], roles[1] = roles[1], roles[0]
    cases.append(reordered)
    guix_removed = json.loads(canonical_json_bytes(base))
    guix_removed["input_closure"]["artifact_roles"].remove("guix-source-bundle")
    cases.append(guix_removed)
    mutate(("input_closure", "descriptor_bound_root_directory_required"), False)
    mutate(("input_closure", "root_directory_identity_stable_during_measurement"), False)
    mutate(("input_closure", "streaming_hash_without_payload_retention_required"), False)
    mutate(("input_closure", "rust_archive_sha256"), "0" * 64)
    mutate(("gate1", "fixture_can_create_production_job"), True)
    mutate(("input_closure", "transport_integrity_is_publisher_admission"), True)
    mutate(("input_closure", "owner_inventory_is_publisher_admission"), True)
    mutate(("gate1", "publisher_admission_receipts_required"), False)
    mutate(("network_fetch_allowed",), True)
    mutate(("gate1", "secret_key_generation_or_use_by_runtime_allowed"), True)
    mutate(("production_dispatch_allowed",), True)
    mutate(("iso_release_allowed",), True)
    if len(cases) != len(NEGATIVE_CASES):
        raise AssertionError("Phase 40 negative matrix inventory drifted")
    rejected: list[str] = []
    for name, candidate in zip(NEGATIVE_CASES, cases, strict=True):
        try:
            parse_phase40_contract(candidate)
        except PolicyError:
            rejected.append(name)
        else:
            raise AssertionError(f"Phase 40 negative case was accepted: {name}")
    unsigned = {
        "format": "securityops-phase40-negative-matrix/1",
        "cases": list(NEGATIVE_CASES),
        "case_count": len(NEGATIVE_CASES),
        "rejected": rejected,
        "all_rejected": len(rejected) == len(NEGATIVE_CASES),
        "production_gates_approved": 0,
        "production_dispatch_allowed": False,
        "iso_release_allowed": False,
    }
    return {**unsigned, "evidence_digest": hashlib.sha256(
        b"SECURITYOPS-PHASE40-NEGATIVE-MATRIX-V1\x00"
        + canonical_json_bytes(unsigned)).hexdigest()}


def phase40_environment_observation() -> dict[str, Any]:
    commands = {
        name: shutil.which(name) or ""
        for name in ("gpg", "gpgv", "guix", "guile", "guild", "rustc", "cargo",
                     "qemu-system-x86_64", "xorriso")
    }
    devices = {
        name: Path(name).exists()
        for name in ("/dev/kvm", "/dev/vhost-vsock", "/dev/vsock")
    }
    unsigned = {
        "format": "securityops-phase40-environment-observation/1",
        "commands": commands,
        "devices": devices,
        "owner_trust_root_present": False,
        "owner_authenticated_input_closure_present": False,
        "non_fixture_gate1_job_present": False,
        "production_gates_approved": 0,
        "production_dispatch_allowed": False,
        "iso_release_allowed": False,
        "iso_bytes_present": False,
    }
    return {**unsigned, "observation_digest": hashlib.sha256(
        b"SECURITYOPS-PHASE40-ENVIRONMENT-OBSERVATION-V1\x00"
        + canonical_json_bytes(unsigned)).hexdigest()}


def phase40_selftest() -> dict[str, Any]:
    contract = parse_phase40_contract(phase40_contract())
    negatives = run_phase40_negative_matrix()
    with tempfile.TemporaryDirectory(prefix="phase40-kit-selftest-") as raw:
        root = Path(raw)
        root.chmod(0o700)
        kit = generate_bootstrap_kit(root / "kit")
        kit_count = kit["file_count"]
    return {
        "format": "securityops-phase40-selftest/1",
        "status": STATUS,
        "contract_digest": contract["contract_digest"],
        "artifact_count": len(ARTIFACT_ROLES),
        "negative_cases_rejected": len(negatives["rejected"]),
        "bootstrap_kit_files": kit_count,
        "production_gates_approved": 0,
        "production_dispatch_allowed": False,
        "iso_release_allowed": False,
    }


__all__ = [
    "ARTIFACT_ROLES", "BLOCKED_STATUS", "CONTRACT_FORMAT",
    "attest_guix_qt_environment",
    "GUIX_QT_ARTIFACT_ROLES", "INHERITED_ARTIFACT_ROLES", "INPUT_CLOSURE_FORMAT",
    "KIT_FILES", "KeyIdentity", "MeasuredFile", "NEGATIVE_CASES",
    "PUBLISHER_ADMISSION_RECEIPT_ROLES", "ROLE_LIMITS", "SIGNING_REQUEST_FORMAT",
    "STAGED_FILENAMES", "STATUS", "TRUST_ROOT_FORMAT", "TRUST_STATE_FORMAT",
    "VerifiedInputClosure", "VerifiedTrustRoot",
    "create_gate1_signing_request", "create_input_closure_manifest",
    "create_trust_root", "create_trust_state", "generate_bootstrap_kit",
    "gate1_signing_request_template", "input_closure_schema",
    "inspect_verification_keyring", "measure_file", "measure_file_streaming",
    "measure_input_root",
    "parse_input_closure", "parse_phase40_contract", "parse_trust_root",
    "parse_trust_state", "phase40_contract", "phase40_contract_digest",
    "phase40_environment_observation", "phase40_selftest",
    "publish_trust_state", "run_phase40_negative_matrix",
    "trust_root_schema", "trust_state_schema", "verify_signed_input_closure",
    "verify_signed_trust_root",
]
