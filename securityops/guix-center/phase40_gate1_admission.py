# CodeMark v1 project=4c63e0fe-589c-4944-8449-97e211a38b72 file=2e2b9999adc254bd80cab3c59ee8e6d5 owner="Cristian Cezar Mois\u00e9s"
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Phase 40 semantic admission for the first production gate.

Phase 39 authenticates an owner-signed job, a separately signed build-node
result, and the exact result artifacts.  Phase 40 adds the semantic boundary
for ``authenticated-guix-qt-environment``.  A signed JSON object is not enough:
the admitted owner trust root, the exact 35-artifact input closure, immutable
Guix Store executables, Qt/PySide runtime, and host attestation must all bind to
the same job challenge.

The module may approve only Gate 1 and only for non-fixture, owner-authenticated
objects.  It never enables production dispatch or ISO release by itself.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
from pathlib import Path
import re
from typing import Any, Final, Mapping, Sequence

try:
    from . import phase39_owner_execution as phase39
    from . import phase40_owner_trust as phase40
except ImportError:  # pragma: no cover - installed Guix Center copy
    import phase39_owner_execution as phase39  # type: ignore[no-redef]
    import phase40_owner_trust as phase40  # type: ignore[no-redef]

PolicyError = phase39.PolicyError
canonical_json_bytes = phase39.canonical_json_bytes

CONTRACT_FORMAT: Final[str] = "securityops-phase40-gate1-admission-contract/1"
OWNER_INPUT_FORMAT: Final[str] = "securityops-phase40-gate1-owner-input-evidence/1"
TOOLCHAIN_FORMAT: Final[str] = "securityops-phase40-gate1-guix-toolchain-evidence/1"
QT_RUNTIME_FORMAT: Final[str] = "securityops-phase40-gate1-qt-runtime-evidence/1"
HOST_FORMAT: Final[str] = "securityops-phase40-gate1-host-attestation/1"
RECEIPT_FORMAT: Final[str] = "securityops-phase40-gate1-semantic-receipt/1"
STATUS: Final[str] = "PASS_PHASE40_AUTHENTICATED_GUIX_QT_ENVIRONMENT_GATE"
BLOCKED_STATUS: Final[str] = "BLOCKED_PHASE40_AUTHENTICATED_GUIX_QT_ENVIRONMENT_REQUIRED"

CONTRACT_DOMAIN: Final[bytes] = b"SECURITYOPS-PHASE40-GATE1-CONTRACT-V1\x00"
OWNER_INPUT_DOMAIN: Final[bytes] = b"SECURITYOPS-PHASE40-GATE1-OWNER-INPUT-V1\x00"
TOOLCHAIN_DOMAIN: Final[bytes] = b"SECURITYOPS-PHASE40-GATE1-TOOLCHAIN-V1\x00"
QT_RUNTIME_DOMAIN: Final[bytes] = b"SECURITYOPS-PHASE40-GATE1-QT-RUNTIME-V1\x00"
HOST_DOMAIN: Final[bytes] = b"SECURITYOPS-PHASE40-GATE1-HOST-V1\x00"
RECEIPT_DOMAIN: Final[bytes] = b"SECURITYOPS-PHASE40-GATE1-RECEIPT-V1\x00"
NEGATIVE_DOMAIN: Final[bytes] = b"SECURITYOPS-PHASE40-GATE1-NEGATIVE-V1\x00"

FIRST_GATE: Final[str] = phase39.GATE_NAMES[0]
EVIDENCE_ROLES: Final[tuple[str, ...]] = phase39.GATE_EVIDENCE_ROLES[FIRST_GATE]
TOOL_NAMES: Final[tuple[str, ...]] = ("guix", "guile", "guild", "python3")

_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9.+:_~-]{0,127}\Z")
_STORE_PATH = re.compile(
    r"/gnu/store/[0-9a-z]{32}-[^/\x00]+(?:/[^/\x00]+)*\Z"
)
MAX_JSON_BYTES: Final[int] = 64 * 1024 * 1024


@dataclass(frozen=True)
class VerifiedGate1Admission:
    trust_root_digest: str
    input_closure_digest: str
    phase39_verification_digest: str
    phase39_job_digest: str
    phase39_result_digest: str
    owner_input_evidence_digest: str
    toolchain_evidence_digest: str
    qt_runtime_evidence_digest: str
    host_attestation_digest: str
    semantic_evidence_verified: bool
    owner_trust_authenticated: bool
    input_closure_authenticated: bool
    gate_approved: bool
    fixture_mode: bool
    production_gates_approved: int
    receipt_digest: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "format": RECEIPT_FORMAT,
            "status": STATUS if self.gate_approved else BLOCKED_STATUS,
            **asdict(self),
            "production_dispatch_allowed": False,
            "iso_release_allowed": False,
            "iso_bytes_present": False,
        }


def _digest(domain: bytes, value: Mapping[str, Any]) -> str:
    return hashlib.sha256(domain + canonical_json_bytes(value)).hexdigest()


def _sha(value: Any, context: str, *, nonzero: bool = True) -> str:
    if type(value) is not str or not _HEX64.fullmatch(value):
        raise PolicyError(f"{context} must be a lowercase SHA-256 digest")
    if nonzero and value == "0" * 64:
        raise PolicyError(f"{context} cannot be zero")
    return value


def _token(value: Any, context: str) -> str:
    if type(value) is not str or not _TOKEN.fullmatch(value):
        raise PolicyError(f"{context} is not a safe token")
    return value


def _version(value: Any, context: str) -> str:
    if type(value) is not str or not _VERSION.fullmatch(value):
        raise PolicyError(f"{context} is invalid")
    return value


def _store_path(value: Any, context: str, *, executable: str | None = None) -> str:
    if type(value) is not str or not _STORE_PATH.fullmatch(value):
        raise PolicyError(f"{context} is not an immutable Guix Store path")
    candidate = Path(value)
    try:
        relative = candidate.relative_to("/gnu/store")
    except ValueError as exc:
        raise PolicyError(f"{context} is not an immutable Guix Store path") from exc
    if (
        candidate.as_posix() != value
        or not relative.parts
        or any(part in {"", ".", ".."} or "\\" in part for part in relative.parts)
    ):
        raise PolicyError(f"{context} is not an immutable Guix Store path")
    if executable is not None and not value.endswith(f"/bin/{executable}"):
        raise PolicyError(f"{context} does not name {executable}")
    return value


def _strict_json(payload: bytes, context: str) -> dict[str, Any]:
    def pairs(values: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, item in values:
            if key in result:
                raise PolicyError(f"{context} contains a duplicate JSON key")
            result[key] = item
        return result

    try:
        value = json.loads(
            payload.decode("utf-8", errors="strict"), object_pairs_hook=pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PolicyError(f"{context} is not strict UTF-8 JSON") from exc
    if type(value) is not dict or canonical_json_bytes(value) != payload:
        raise PolicyError(f"{context} is not a canonical JSON object")
    return value


def _binding(
    *, trust_root_digest: str, input_closure_digest: str,
    job_digest: str, challenge_nonce: str,
) -> dict[str, str]:
    return {
        "trust_root_digest": _sha(
            trust_root_digest, "Phase 40 trust-root binding"),
        "input_closure_digest": _sha(
            input_closure_digest, "Phase 40 input-closure binding"),
        "job_digest": _sha(job_digest, "Phase 40 job binding"),
        "challenge_nonce": _sha(
            challenge_nonce, "Phase 40 challenge binding"),
    }


def _contract_unsigned() -> dict[str, Any]:
    return {
        "format": CONTRACT_FORMAT,
        "status": STATUS,
        "phase40_owner_trust_contract_digest": phase40.phase40_contract_digest(),
        "phase39_contract_digest": phase39.phase39_contract_digest(),
        "gate_name": FIRST_GATE,
        "gate_index": 1,
        "evidence_roles": list(EVIDENCE_ROLES),
        "evidence_formats": {
            "owner-input-closure": OWNER_INPUT_FORMAT,
            "guix-store-toolchain": TOOLCHAIN_FORMAT,
            "qt-pyside-runtime": QT_RUNTIME_FORMAT,
            "host-attestation": HOST_FORMAT,
        },
        "owner_input": {
            "artifact_roles": list(phase40.ARTIFACT_ROLES),
            "artifact_count": len(phase40.ARTIFACT_ROLES),
            "owner_verified_input_object_required": True,
            "exact_rust_archive_required": True,
            "publisher_admission_receipts_required": True,
            "fixture_can_authenticate": False,
        },
        "guix_toolchain": {
            "tools": list(TOOL_NAMES),
            "all_executables_under_guix_store": True,
            "exact_profile_manifest_digest_required": True,
            "complete_closure_digest_required": True,
            "channel_lock_digest_required": True,
            "fixture_can_authenticate": False,
        },
        "qt_runtime": {
            "qt6_store_path_required": True,
            "pyside6_store_path_required": True,
            "python_module_origin_under_guix_store": True,
            "offscreen_probe_required": True,
            "plugin_inventory_digest_required": True,
            "fixture_can_authenticate": False,
        },
        "semantic_boundary": {
            "phase39_dual_signature_verification_required": True,
            "phase39_descriptor_remeasurement_required": True,
            "exact_owner_and_node_fingerprints_required": True,
            "exact_build_node_id_required": True,
            "all_documents_bind_trust_input_job_and_challenge": True,
            "host_attestation_digest_matches_signed_result": True,
            "only_first_gate_may_be_approved": True,
        },
        "truth_boundary": {
            "signed_json_without_semantic_validation_is_gate_evidence": False,
            "fixture_exchange_is_production_gate": False,
            "package_definition_is_guix_store_closure": False,
            "python_import_model_is_qt_execution": False,
            "capability_probe_is_execution": False,
        },
        "production_gates_approved": 0,
        "production_dispatch_allowed": False,
        "iso_release_allowed": False,
    }


def gate1_contract() -> dict[str, Any]:
    unsigned = _contract_unsigned()
    return {**unsigned, "contract_digest": _digest(CONTRACT_DOMAIN, unsigned)}


def gate1_contract_digest() -> str:
    return gate1_contract()["contract_digest"]


def parse_gate1_contract(value: Mapping[str, Any]) -> dict[str, Any]:
    candidate = json.loads(canonical_json_bytes(value))
    if candidate != gate1_contract():
        raise PolicyError("Phase 40 Gate 1 contract differs from closed policy")
    return candidate


def create_owner_input_evidence(
    *, trust_root_digest: str, input_closure_digest: str,
    input_verification_digest: str, artifact_set_digest: str,
    artifact_count: int, exact_rust_archive_bound: bool,
    publisher_admission_receipts_verified: bool,
    owner_inventory_authenticated: bool,
    job_digest: str, challenge_nonce: str, fixture_mode: bool,
) -> dict[str, Any]:
    binding = _binding(
        trust_root_digest=trust_root_digest,
        input_closure_digest=input_closure_digest,
        job_digest=job_digest, challenge_nonce=challenge_nonce)
    flags = (
        exact_rust_archive_bound, publisher_admission_receipts_verified,
        owner_inventory_authenticated, fixture_mode,
    )
    if any(type(item) is not bool for item in flags):
        raise PolicyError("Phase 40 owner-input flags are invalid")
    if type(artifact_count) is not int or artifact_count != len(phase40.ARTIFACT_ROLES):
        raise PolicyError("Phase 40 owner-input artifact count drifted")
    authenticated = bool(
        exact_rust_archive_bound
        and publisher_admission_receipts_verified
        and owner_inventory_authenticated
        and not fixture_mode
    )
    unsigned = {
        "format": OWNER_INPUT_FORMAT,
        "contract_digest": gate1_contract_digest(),
        **binding,
        "input_verification_digest": _sha(
            input_verification_digest, "Phase 40 input verification"),
        "artifact_set_digest": _sha(
            artifact_set_digest, "Phase 40 artifact set"),
        "artifact_count": artifact_count,
        "exact_rust_archive_bound": exact_rust_archive_bound,
        "publisher_admission_receipts_verified":
            publisher_admission_receipts_verified,
        "owner_inventory_authenticated": owner_inventory_authenticated,
        "input_closure_authenticated": authenticated,
        "fixture_mode": fixture_mode,
        "production_dispatch_allowed": False,
        "iso_release_allowed": False,
    }
    return {**unsigned, "evidence_digest": _digest(OWNER_INPUT_DOMAIN, unsigned)}


def parse_owner_input_evidence(value: Mapping[str, Any]) -> dict[str, Any]:
    fields = {
        "format", "contract_digest", "trust_root_digest",
        "input_closure_digest", "job_digest", "challenge_nonce",
        "input_verification_digest", "artifact_set_digest", "artifact_count",
        "exact_rust_archive_bound", "publisher_admission_receipts_verified",
        "owner_inventory_authenticated", "input_closure_authenticated",
        "fixture_mode", "production_dispatch_allowed", "iso_release_allowed",
        "evidence_digest",
    }
    if type(value) is not dict or set(value) != fields:
        raise PolicyError("Phase 40 owner-input evidence fields are not closed")
    candidate = json.loads(canonical_json_bytes(value))
    if candidate["format"] != OWNER_INPUT_FORMAT:
        raise PolicyError("Phase 40 owner-input evidence format drifted")
    recreated = create_owner_input_evidence(
        trust_root_digest=candidate["trust_root_digest"],
        input_closure_digest=candidate["input_closure_digest"],
        input_verification_digest=candidate["input_verification_digest"],
        artifact_set_digest=candidate["artifact_set_digest"],
        artifact_count=candidate["artifact_count"],
        exact_rust_archive_bound=candidate["exact_rust_archive_bound"],
        publisher_admission_receipts_verified=
            candidate["publisher_admission_receipts_verified"],
        owner_inventory_authenticated=candidate["owner_inventory_authenticated"],
        job_digest=candidate["job_digest"],
        challenge_nonce=candidate["challenge_nonce"],
        fixture_mode=candidate["fixture_mode"],
    )
    if candidate != recreated:
        raise PolicyError("Phase 40 owner-input evidence identity drifted")
    return candidate


def create_guix_toolchain_evidence(
    *, trust_root_digest: str, input_closure_digest: str,
    job_digest: str, challenge_nonce: str,
    system_profile: str, profile_manifest_digest: str,
    tools: Sequence[Mapping[str, Any]], qt6_store_path: str,
    pyside6_store_path: str, python_module_origin: str,
    channel_lock_digest: str, closure_digest: str,
    guix_center_source_digest: str, fixture_mode: bool,
) -> dict[str, Any]:
    binding = _binding(
        trust_root_digest=trust_root_digest,
        input_closure_digest=input_closure_digest,
        job_digest=job_digest, challenge_nonce=challenge_nonce)
    if type(fixture_mode) is not bool:
        raise PolicyError("Phase 40 toolchain fixture flag is invalid")
    profile = _store_path(system_profile, "Phase 40 system profile")
    if type(tools) not in {list, tuple} or len(tools) != len(TOOL_NAMES):
        raise PolicyError("Phase 40 toolchain inventory is incomplete")
    normalized: list[dict[str, Any]] = []
    for expected_name, item in zip(TOOL_NAMES, tools, strict=True):
        fields = {"name", "path", "sha256", "bytes", "version", "build_id"}
        if type(item) is not dict or set(item) != fields or item["name"] != expected_name:
            raise PolicyError("Phase 40 toolchain role order drifted")
        if type(item["bytes"]) is not int or not 1 <= item["bytes"] <= 512 * 1024 * 1024:
            raise PolicyError("Phase 40 tool executable size is invalid")
        build_id = item["build_id"]
        if type(build_id) is not str or len(build_id) > 256 or any(ord(ch) < 32 for ch in build_id):
            raise PolicyError("Phase 40 tool build ID is invalid")
        normalized.append({
            "name": expected_name,
            "path": _store_path(
                item["path"], f"Phase 40 {expected_name}", executable=expected_name),
            "sha256": _sha(item["sha256"], f"Phase 40 {expected_name}"),
            "bytes": item["bytes"],
            "version": _version(item["version"], f"Phase 40 {expected_name} version"),
            "build_id": build_id,
        })
    qt_path = _store_path(qt6_store_path, "Phase 40 Qt 6 Store path")
    pyside_path = _store_path(pyside6_store_path, "Phase 40 PySide 6 Store path")
    module_origin = _store_path(
        python_module_origin, "Phase 40 PySide module origin")
    if not module_origin.startswith(pyside_path.rstrip("/") + "/"):
        raise PolicyError("Phase 40 PySide module origin differs from admitted closure")
    authenticated = not fixture_mode
    unsigned = {
        "format": TOOLCHAIN_FORMAT,
        "contract_digest": gate1_contract_digest(),
        **binding,
        "system_profile": profile,
        "profile_manifest_digest": _sha(
            profile_manifest_digest, "Phase 40 profile manifest"),
        "tools": normalized,
        "qt6_store_path": qt_path,
        "pyside6_store_path": pyside_path,
        "python_module_origin": module_origin,
        "channel_lock_digest": _sha(
            channel_lock_digest, "Phase 40 channel lock"),
        "closure_digest": _sha(closure_digest, "Phase 40 closure"),
        "guix_center_source_digest": _sha(
            guix_center_source_digest, "Phase 40 Guix Center source"),
        "toolchain_authenticated": authenticated,
        "fixture_mode": fixture_mode,
        "production_dispatch_allowed": False,
        "iso_release_allowed": False,
    }
    return {**unsigned, "evidence_digest": _digest(TOOLCHAIN_DOMAIN, unsigned)}


def parse_guix_toolchain_evidence(value: Mapping[str, Any]) -> dict[str, Any]:
    fields = {
        "format", "contract_digest", "trust_root_digest",
        "input_closure_digest", "job_digest", "challenge_nonce",
        "system_profile", "profile_manifest_digest", "tools",
        "qt6_store_path", "pyside6_store_path", "python_module_origin",
        "channel_lock_digest", "closure_digest", "guix_center_source_digest",
        "toolchain_authenticated", "fixture_mode",
        "production_dispatch_allowed", "iso_release_allowed", "evidence_digest",
    }
    if type(value) is not dict or set(value) != fields:
        raise PolicyError("Phase 40 toolchain evidence fields are not closed")
    candidate = json.loads(canonical_json_bytes(value))
    if candidate["format"] != TOOLCHAIN_FORMAT:
        raise PolicyError("Phase 40 toolchain evidence format drifted")
    recreated = create_guix_toolchain_evidence(
        trust_root_digest=candidate["trust_root_digest"],
        input_closure_digest=candidate["input_closure_digest"],
        job_digest=candidate["job_digest"],
        challenge_nonce=candidate["challenge_nonce"],
        system_profile=candidate["system_profile"],
        profile_manifest_digest=candidate["profile_manifest_digest"],
        tools=candidate["tools"],
        qt6_store_path=candidate["qt6_store_path"],
        pyside6_store_path=candidate["pyside6_store_path"],
        python_module_origin=candidate["python_module_origin"],
        channel_lock_digest=candidate["channel_lock_digest"],
        closure_digest=candidate["closure_digest"],
        guix_center_source_digest=candidate["guix_center_source_digest"],
        fixture_mode=candidate["fixture_mode"],
    )
    if candidate != recreated:
        raise PolicyError("Phase 40 toolchain evidence identity drifted")
    return candidate


def create_qt_runtime_evidence(
    *, trust_root_digest: str, input_closure_digest: str,
    job_digest: str, challenge_nonce: str,
    qt_version: str, pyside_version: str, python_version: str,
    qt_platform: str, display_backend: str,
    qt6_store_path: str, pyside6_store_path: str,
    python_module_origin: str, plugin_inventory_digest: str,
    offscreen_probe_digest: str, offscreen_probe_passed: bool,
    fixture_mode: bool,
) -> dict[str, Any]:
    binding = _binding(
        trust_root_digest=trust_root_digest,
        input_closure_digest=input_closure_digest,
        job_digest=job_digest, challenge_nonce=challenge_nonce)
    if type(offscreen_probe_passed) is not bool or type(fixture_mode) is not bool:
        raise PolicyError("Phase 40 Qt runtime flags are invalid")
    qt_path = _store_path(qt6_store_path, "Phase 40 Qt runtime Store path")
    pyside_path = _store_path(pyside6_store_path, "Phase 40 PySide runtime Store path")
    module_origin = _store_path(
        python_module_origin, "Phase 40 PySide runtime module origin")
    if not module_origin.startswith(pyside_path.rstrip("/") + "/"):
        raise PolicyError("Phase 40 Qt runtime module origin differs from PySide closure")
    runtime_authenticated = bool(offscreen_probe_passed and not fixture_mode)
    unsigned = {
        "format": QT_RUNTIME_FORMAT,
        "contract_digest": gate1_contract_digest(),
        **binding,
        "qt_version": _version(qt_version, "Phase 40 Qt version"),
        "pyside_version": _version(pyside_version, "Phase 40 PySide version"),
        "python_version": _version(python_version, "Phase 40 Python version"),
        "qt_platform": _token(qt_platform, "Phase 40 Qt platform"),
        "display_backend": _token(display_backend, "Phase 40 display backend"),
        "qt6_store_path": qt_path,
        "pyside6_store_path": pyside_path,
        "python_module_origin": module_origin,
        "plugin_inventory_digest": _sha(
            plugin_inventory_digest, "Phase 40 Qt plugin inventory"),
        "offscreen_probe_digest": _sha(
            offscreen_probe_digest, "Phase 40 Qt offscreen probe"),
        "offscreen_probe_passed": offscreen_probe_passed,
        "runtime_authenticated": runtime_authenticated,
        "fixture_mode": fixture_mode,
        "production_dispatch_allowed": False,
        "iso_release_allowed": False,
    }
    return {**unsigned, "evidence_digest": _digest(QT_RUNTIME_DOMAIN, unsigned)}


def parse_qt_runtime_evidence(value: Mapping[str, Any]) -> dict[str, Any]:
    fields = {
        "format", "contract_digest", "trust_root_digest",
        "input_closure_digest", "job_digest", "challenge_nonce",
        "qt_version", "pyside_version", "python_version", "qt_platform",
        "display_backend", "qt6_store_path", "pyside6_store_path",
        "python_module_origin", "plugin_inventory_digest",
        "offscreen_probe_digest", "offscreen_probe_passed",
        "runtime_authenticated", "fixture_mode", "production_dispatch_allowed",
        "iso_release_allowed", "evidence_digest",
    }
    if type(value) is not dict or set(value) != fields:
        raise PolicyError("Phase 40 Qt runtime evidence fields are not closed")
    candidate = json.loads(canonical_json_bytes(value))
    if candidate["format"] != QT_RUNTIME_FORMAT:
        raise PolicyError("Phase 40 Qt runtime evidence format drifted")
    recreated = create_qt_runtime_evidence(
        trust_root_digest=candidate["trust_root_digest"],
        input_closure_digest=candidate["input_closure_digest"],
        job_digest=candidate["job_digest"],
        challenge_nonce=candidate["challenge_nonce"],
        qt_version=candidate["qt_version"],
        pyside_version=candidate["pyside_version"],
        python_version=candidate["python_version"],
        qt_platform=candidate["qt_platform"],
        display_backend=candidate["display_backend"],
        qt6_store_path=candidate["qt6_store_path"],
        pyside6_store_path=candidate["pyside6_store_path"],
        python_module_origin=candidate["python_module_origin"],
        plugin_inventory_digest=candidate["plugin_inventory_digest"],
        offscreen_probe_digest=candidate["offscreen_probe_digest"],
        offscreen_probe_passed=candidate["offscreen_probe_passed"],
        fixture_mode=candidate["fixture_mode"],
    )
    if candidate != recreated:
        raise PolicyError("Phase 40 Qt runtime evidence identity drifted")
    return candidate


def create_host_attestation(
    *, trust_root_digest: str, input_closure_digest: str,
    job_digest: str, challenge_nonce: str,
    build_node_id: str, observed_unix: int,
    architecture: str, kernel_release: str,
    os_release_digest: str, boot_id_digest: str,
    command_attestation_digest: str, time_source: str,
    fixture_mode: bool,
) -> dict[str, Any]:
    binding = _binding(
        trust_root_digest=trust_root_digest,
        input_closure_digest=input_closure_digest,
        job_digest=job_digest, challenge_nonce=challenge_nonce)
    if type(observed_unix) is not int or observed_unix < 1:
        raise PolicyError("Phase 40 host-attestation time is invalid")
    if type(fixture_mode) is not bool:
        raise PolicyError("Phase 40 host-attestation fixture flag is invalid")
    unsigned = {
        "format": HOST_FORMAT,
        "contract_digest": gate1_contract_digest(),
        **binding,
        "build_node_id": _token(build_node_id, "Phase 40 build-node ID"),
        "observed_unix": observed_unix,
        "architecture": _token(architecture, "Phase 40 architecture"),
        "kernel_release": _version(kernel_release, "Phase 40 kernel release"),
        "os_release_digest": _sha(os_release_digest, "Phase 40 OS release"),
        "boot_id_digest": _sha(boot_id_digest, "Phase 40 boot ID"),
        "command_attestation_digest": _sha(
            command_attestation_digest, "Phase 40 command attestation"),
        "time_source": _token(time_source, "Phase 40 time source"),
        "host_authenticated": not fixture_mode,
        "capability_probe_is_gate_execution": False,
        "fixture_mode": fixture_mode,
        "production_dispatch_allowed": False,
        "iso_release_allowed": False,
    }
    return {**unsigned, "evidence_digest": _digest(HOST_DOMAIN, unsigned)}


def parse_host_attestation(value: Mapping[str, Any]) -> dict[str, Any]:
    fields = {
        "format", "contract_digest", "trust_root_digest",
        "input_closure_digest", "job_digest", "challenge_nonce",
        "build_node_id", "observed_unix", "architecture", "kernel_release",
        "os_release_digest", "boot_id_digest", "command_attestation_digest",
        "time_source", "host_authenticated", "capability_probe_is_gate_execution",
        "fixture_mode", "production_dispatch_allowed", "iso_release_allowed",
        "evidence_digest",
    }
    if type(value) is not dict or set(value) != fields:
        raise PolicyError("Phase 40 host-attestation fields are not closed")
    candidate = json.loads(canonical_json_bytes(value))
    if candidate["format"] != HOST_FORMAT:
        raise PolicyError("Phase 40 host-attestation format drifted")
    recreated = create_host_attestation(
        trust_root_digest=candidate["trust_root_digest"],
        input_closure_digest=candidate["input_closure_digest"],
        job_digest=candidate["job_digest"],
        challenge_nonce=candidate["challenge_nonce"],
        build_node_id=candidate["build_node_id"],
        observed_unix=candidate["observed_unix"],
        architecture=candidate["architecture"],
        kernel_release=candidate["kernel_release"],
        os_release_digest=candidate["os_release_digest"],
        boot_id_digest=candidate["boot_id_digest"],
        command_attestation_digest=candidate["command_attestation_digest"],
        time_source=candidate["time_source"],
        fixture_mode=candidate["fixture_mode"],
    )
    if candidate != recreated:
        raise PolicyError("Phase 40 host-attestation identity drifted")
    return candidate


def _load_evidence_json(
    *, evidence_root: Path, filename: str,
    expected_sha256: str, expected_bytes: int,
) -> dict[str, Any]:
    measured, payload = phase40.measure_file(
        evidence_root / filename,
        maximum=MAX_JSON_BYTES,
        context=f"Phase 40 semantic evidence {filename}")
    if measured.sha256 != expected_sha256 or measured.bytes != expected_bytes:
        raise PolicyError("Phase 40 semantic evidence differs from signed result")
    return _strict_json(payload, "Phase 40 semantic evidence")


def verify_gate1_semantics(
    *, verification: phase39.VerifiedGateExchange,
    job_document: Mapping[str, Any], result_document: Mapping[str, Any],
    verified_trust_root: phase40.VerifiedTrustRoot,
    verified_input_closure: phase40.VerifiedInputClosure,
    evidence_root: Path,
) -> VerifiedGate1Admission:
    if not isinstance(verification, phase39.VerifiedGateExchange):
        raise PolicyError("Phase 40 requires a verified Phase 39 exchange")
    if not isinstance(verified_trust_root, phase40.VerifiedTrustRoot):
        raise PolicyError("Phase 40 requires a verified owner trust root")
    if not isinstance(verified_input_closure, phase40.VerifiedInputClosure):
        raise PolicyError("Phase 40 requires a verified input closure")
    job = phase39.parse_gate_job(job_document)
    result = phase39.parse_gate_result(
        result_document, job=job, evidence_root=evidence_root)
    if (
        verification.gate_name != FIRST_GATE
        or verification.gate_index != 1
        or job.gate_name != FIRST_GATE
        or result.gate_name != FIRST_GATE
    ):
        raise PolicyError("Phase 40 semantic verifier accepts only Gate 1")
    if (
        verification.job_digest != job.job_digest
        or verification.result_digest != result.result_digest
    ):
        raise PolicyError("Phase 40 signed exchange identity drifted")
    trust_document = verified_trust_root.document
    if (
        job.owner_fingerprint
            != verified_trust_root.owner_identity.signing_fingerprint
        or job.result_fingerprint
            != verified_trust_root.build_node_identity.signing_fingerprint
        or job.document["build_node_id"]
            != trust_document["build_node"]["node_id"]
    ):
        raise PolicyError("Phase 40 job differs from admitted owner trust root")
    if (
        verified_input_closure.trust_root_digest
            != verified_trust_root.trust_root_digest
    ):
        raise PolicyError("Phase 40 input closure binds another trust root")
    records = result.document["evidence"]
    if [item["role"] for item in records] != list(EVIDENCE_ROLES):
        raise PolicyError("Phase 40 Gate 1 evidence role order drifted")
    documents = [
        _load_evidence_json(
            evidence_root=evidence_root,
            filename=item["filename"],
            expected_sha256=item["sha256"],
            expected_bytes=item["bytes"],
        )
        for item in records
    ]
    owner_input = parse_owner_input_evidence(documents[0])
    toolchain = parse_guix_toolchain_evidence(documents[1])
    qt_runtime = parse_qt_runtime_evidence(documents[2])
    host = parse_host_attestation(documents[3])
    expected_binding = {
        "trust_root_digest": verified_trust_root.trust_root_digest,
        "input_closure_digest": verified_input_closure.input_closure_digest,
        "job_digest": job.job_digest,
        "challenge_nonce": job.document["challenge_nonce"],
    }
    for document in documents:
        for key, expected in expected_binding.items():
            if document[key] != expected:
                raise PolicyError("Phase 40 semantic evidence binding drifted")
    if (
        owner_input["input_verification_digest"]
            != verified_input_closure.verification_digest
        or owner_input["artifact_count"] != len(verified_input_closure.artifacts)
    ):
        raise PolicyError("Phase 40 owner-input evidence differs from local verification")
    artifact_set_digest = hashlib.sha256(
        b"SECURITYOPS-PHASE40-ARTIFACT-SET-V1\x00"
        + canonical_json_bytes(
            [item.to_dict() for item in verified_input_closure.artifacts])
    ).hexdigest()
    if owner_input["artifact_set_digest"] != artifact_set_digest:
        raise PolicyError("Phase 40 owner-input artifact-set digest drifted")
    if (
        host["build_node_id"] != trust_document["build_node"]["node_id"]
        or host["evidence_digest"]
            != result.document["host_attestation_digest"]
    ):
        raise PolicyError("Phase 40 host attestation differs from signed result")
    fixture_mode = bool(
        verification.fixture_mode
        or job.fixture_mode
        or result.fixture_mode
        or verified_trust_root.fixture_mode
        or verified_input_closure.fixture_mode
        or any(document["fixture_mode"] for document in documents)
    )
    owner_authenticated = bool(verified_trust_root.owner_authenticated)
    input_authenticated = bool(verified_input_closure.ready_for_gate1_job)
    semantic_ok = bool(
        owner_input["input_closure_authenticated"]
        and toolchain["toolchain_authenticated"]
        and qt_runtime["runtime_authenticated"]
        and host["host_authenticated"]
        and owner_authenticated
        and input_authenticated
        and not fixture_mode
    )
    approved = bool(
        verification.owner_signature_verified
        and verification.result_signature_verified
        and verification.evidence_inventory_verified
        and verification.replay_ledger_updated
        and verification.owner_authenticated
        and verification.gate_approved
        and semantic_ok
        and not fixture_mode
    )
    unsigned = {
        "format": RECEIPT_FORMAT,
        "status": STATUS if approved else BLOCKED_STATUS,
        "trust_root_digest": verified_trust_root.trust_root_digest,
        "input_closure_digest": verified_input_closure.input_closure_digest,
        "phase39_verification_digest": verification.verification_digest,
        "phase39_job_digest": job.job_digest,
        "phase39_result_digest": result.result_digest,
        "owner_input_evidence_digest": owner_input["evidence_digest"],
        "toolchain_evidence_digest": toolchain["evidence_digest"],
        "qt_runtime_evidence_digest": qt_runtime["evidence_digest"],
        "host_attestation_digest": host["evidence_digest"],
        "semantic_evidence_verified": semantic_ok,
        "owner_trust_authenticated": owner_authenticated,
        "input_closure_authenticated": input_authenticated,
        "gate_approved": approved,
        "fixture_mode": fixture_mode,
        "production_gates_approved": 1 if approved else 0,
        "production_dispatch_allowed": False,
        "iso_release_allowed": False,
        "iso_bytes_present": False,
    }
    receipt_digest = _digest(RECEIPT_DOMAIN, unsigned)
    return VerifiedGate1Admission(
        trust_root_digest=verified_trust_root.trust_root_digest,
        input_closure_digest=verified_input_closure.input_closure_digest,
        phase39_verification_digest=verification.verification_digest,
        phase39_job_digest=job.job_digest,
        phase39_result_digest=result.result_digest,
        owner_input_evidence_digest=owner_input["evidence_digest"],
        toolchain_evidence_digest=toolchain["evidence_digest"],
        qt_runtime_evidence_digest=qt_runtime["evidence_digest"],
        host_attestation_digest=host["evidence_digest"],
        semantic_evidence_verified=semantic_ok,
        owner_trust_authenticated=owner_authenticated,
        input_closure_authenticated=input_authenticated,
        gate_approved=approved,
        fixture_mode=fixture_mode,
        production_gates_approved=1 if approved else 0,
        receipt_digest=receipt_digest,
    )


def blocked_gate1_observation() -> dict[str, Any]:
    unsigned = {
        "format": "securityops-phase40-gate1-observation/1",
        "status": BLOCKED_STATUS,
        "contract_digest": gate1_contract_digest(),
        "owner_trust_authenticated": False,
        "owner_input_closure_authenticated": False,
        "dual_signed_gate1_exchange_present": False,
        "guix_store_toolchain_present": False,
        "qt_pyside_runtime_present": False,
        "host_attestation_present": False,
        "semantic_evidence_verified": False,
        "production_gates_approved": 0,
        "production_dispatch_allowed": False,
        "iso_release_allowed": False,
        "iso_bytes_present": False,
        "release_decision": "NOT RELEASE READY — BLOCKERS LISTED",
    }
    return {**unsigned, "observation_digest": _digest(RECEIPT_DOMAIN, unsigned)}


def run_gate1_negative_matrix() -> dict[str, Any]:
    base = gate1_contract()
    cases: list[tuple[str, dict[str, Any]]] = []

    def mutation(name: str, path: Sequence[str], value: Any) -> None:
        candidate = json.loads(canonical_json_bytes(base))
        current: Any = candidate
        for key in path[:-1]:
            current = current[key]
        current[path[-1]] = value
        cases.append((name, candidate))

    mutation("owner-contract-drift", ("phase40_owner_trust_contract_digest",), "0" * 64)
    mutation("evidence-order-drift", ("evidence_roles",), list(reversed(EVIDENCE_ROLES)))
    mutation("input-count-drift", ("owner_input", "artifact_count"), 34)
    mutation("fixture-input-promotion", ("owner_input", "fixture_can_authenticate"), True)
    mutation("non-store-tool-promotion", ("guix_toolchain", "all_executables_under_guix_store"), False)
    mutation("missing-closure-digest", ("guix_toolchain", "complete_closure_digest_required"), False)
    mutation("qt-offscreen-optional", ("qt_runtime", "offscreen_probe_required"), False)
    mutation("qt-fixture-promotion", ("qt_runtime", "fixture_can_authenticate"), True)
    mutation("dual-signature-optional", ("semantic_boundary", "phase39_dual_signature_verification_required"), False)
    mutation("remeasurement-optional", ("semantic_boundary", "phase39_descriptor_remeasurement_required"), False)
    mutation("host-binding-optional", ("semantic_boundary", "host_attestation_digest_matches_signed_result"), False)
    mutation("later-gate-promotion", ("semantic_boundary", "only_first_gate_may_be_approved"), False)
    mutation("signed-json-promotion", ("truth_boundary", "signed_json_without_semantic_validation_is_gate_evidence"), True)
    mutation("fixture-exchange-promotion", ("truth_boundary", "fixture_exchange_is_production_gate"), True)
    mutation("package-definition-promotion", ("truth_boundary", "package_definition_is_guix_store_closure"), True)
    mutation("headless-model-promotion", ("truth_boundary", "python_import_model_is_qt_execution"), True)
    mutation("capability-probe-promotion", ("truth_boundary", "capability_probe_is_execution"), True)
    mutation("production-count-promotion", ("production_gates_approved",), 1)
    mutation("dispatch-promotion", ("production_dispatch_allowed",), True)
    mutation("iso-promotion", ("iso_release_allowed",), True)
    extra = json.loads(canonical_json_bytes(base))
    extra["unexpected"] = True
    cases.append(("extra-field", extra))
    rejected: list[str] = []
    for name, candidate in cases:
        try:
            parse_gate1_contract(candidate)
        except PolicyError:
            rejected.append(name)
        else:
            raise AssertionError(f"Phase 40 Gate 1 negative case accepted: {name}")
    unsigned = {
        "format": "securityops-phase40-gate1-negative-matrix/1",
        "cases": [name for name, _ in cases],
        "case_count": len(cases),
        "rejected": rejected,
        "all_rejected": len(rejected) == len(cases),
        "production_gates_approved": 0,
        "production_dispatch_allowed": False,
        "iso_release_allowed": False,
    }
    return {**unsigned, "evidence_digest": _digest(NEGATIVE_DOMAIN, unsigned)}


def gate1_selftest() -> dict[str, Any]:
    contract = parse_gate1_contract(gate1_contract())
    negatives = run_gate1_negative_matrix()
    observation = blocked_gate1_observation()
    return {
        "format": "securityops-phase40-gate1-selftest/1",
        "status": "PASS_PHASE40_GATE1_CONTRACT_AND_FAIL_CLOSED_SEMANTICS",
        "contract_digest": contract["contract_digest"],
        "evidence_roles": list(EVIDENCE_ROLES),
        "negative_cases_rejected": len(negatives["rejected"]),
        "local_gate_status": observation["status"],
        "production_gates_approved": 0,
        "production_dispatch_allowed": False,
        "iso_release_allowed": False,
    }


__all__ = [
    "BLOCKED_STATUS", "CONTRACT_FORMAT", "EVIDENCE_ROLES", "FIRST_GATE",
    "HOST_FORMAT", "OWNER_INPUT_FORMAT", "QT_RUNTIME_FORMAT", "RECEIPT_FORMAT",
    "STATUS", "TOOLCHAIN_FORMAT", "VerifiedGate1Admission",
    "blocked_gate1_observation", "create_guix_toolchain_evidence",
    "create_host_attestation", "create_owner_input_evidence",
    "create_qt_runtime_evidence", "gate1_contract", "gate1_contract_digest",
    "gate1_selftest", "parse_gate1_contract", "parse_guix_toolchain_evidence",
    "parse_host_attestation", "parse_owner_input_evidence",
    "parse_qt_runtime_evidence", "run_gate1_negative_matrix",
    "verify_gate1_semantics",
]
