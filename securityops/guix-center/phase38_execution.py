# CodeMark v1 project=4c63e0fe-589c-4944-8449-97e211a38b72 file=653f342bbe7f597ab65184ca96fa9fd9 owner="Cristian Cezar Mois\u00e9s"
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-SecurityOps-Commercial
"""Phase 38 measured execution and machine-readable validation boundary.

This module defines exact production gate requirements, a descriptor-measured
local capability attestation, and a fail-closed local gate report.  A capability
probe is not itself proof that Guix, Qt, KVM, AF_VSOCK, Linux 7.2, VMs, the
installer, desktops, or an ISO executed successfully.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import shutil
import stat
import subprocess
from typing import Any, Final, Mapping

try:
    from . import phase36_guix_center as phase36
    from . import phase37_guix_center as phase37
except ImportError:  # Installed Guix Center sibling modules.
    import guix_backend as phase36  # type: ignore[no-redef]
    import phase37_guix_center as phase37  # type: ignore[no-redef]

PolicyError = phase36.PolicyError
canonical_json_bytes = phase36.canonical_json_bytes

CONTRACT_FORMAT: Final[str] = "securityops-phase38-execution-contract/1"
CAPABILITY_FORMAT: Final[str] = "securityops-phase38-capability-attestation/1"
GATE_REPORT_FORMAT: Final[str] = "securityops-phase38-local-gate-report/1"
STATUS: Final[str] = "PASS_PHASE38_MACHINE_READABLE_VALIDATION_AND_EXECUTION_GATE_BOUNDARY"
CONTRACT_DOMAIN: Final[bytes] = b"SECURITYOPS-PHASE38-EXECUTION-CONTRACT-V1\x00"
CAPABILITY_DOMAIN: Final[bytes] = b"SECURITYOPS-PHASE38-CAPABILITY-ATTESTATION-V1\x00"
GATE_REPORT_DOMAIN: Final[bytes] = b"SECURITYOPS-PHASE38-LOCAL-GATE-REPORT-V1\x00"

PHASE37_IDENTITIES: Final[dict[str, str]] = {
    "runtime_commit": "c5be97e879f99e7f143e165d8df26e73421a6890",
    "runtime_tree": "b9a5127a3cddbf45827fddbc12d277c0fe0f40d8",
    "securityops_os_commit": "b483df2b28fb8aacbc677db41a78308d1b160117",
    "securityops_os_tree": "817b51cbd945eb2079abad49836c84b0aeb1cd0f",
    "stable_v1_13_0": "8373fd789c9a525d6128abfd3d7a93ad4db3348b",
}

COMMANDS: Final[tuple[str, ...]] = (
    "guix", "guile", "guild", "python3", "xvfb-run", "dbus-run-session",
    "qemu-system-x86_64", "qemu-img", "xorriso", "grub-mkrescue",
    "mksquashfs", "rustc", "cargo", "gpgv", "git", "gcc", "readelf",
)
PYTHON_MODULES: Final[tuple[str, ...]] = ("PySide6", "psutil", "jsonschema")
DEVICES: Final[tuple[str, ...]] = ("/dev/kvm", "/dev/vhost-vsock", "/dev/vsock")
MAX_EXECUTABLE_BYTES: Final[int] = 512 * 1024 * 1024


@dataclass(frozen=True)
class GateSpec:
    name: str
    evidence_scope: str
    prerequisites: tuple[str, ...]
    requirements: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "evidence_scope": self.evidence_scope,
            "prerequisites": list(self.prerequisites),
            "requirements": list(self.requirements),
        }


GATE_SPECS: Final[tuple[GateSpec, ...]] = (
    GateSpec(
        "authenticated-guix-qt-environment", "authenticated-guix-runtime", (),
        ("guix-guile-guild-from-admitted-store", "qt6-pyside6-runtime", "owner-authenticated-closure"),
    ),
    GateSpec(
        "reproducible-guix-center-derivation", "guix-derivation",
        ("authenticated-guix-qt-environment",),
        ("two-clean-builds", "identical-store-output", "closure-sbom-provenance"),
    ),
    GateSpec(
        "qt-offscreen-matrix", "qt-offscreen",
        ("reproducible-guix-center-derivation",),
        ("eight-pages", "six-page-states", "thirty-accessibility-widgets", "hidpi-layout-matrix"),
    ),
    GateSpec(
        "qt-interactive-accessibility", "interactive-graphical-session",
        ("qt-offscreen-matrix",),
        ("keyboard-traversal", "screen-reader-metadata", "real-display-session", "restart-recovery"),
    ),
    GateSpec(
        "real-guix-transaction-matrix", "real-guix-profile",
        ("reproducible-guix-center-derivation",),
        ("all-fifteen-actions", "disposable-profile", "receipt-log-journal-authentication", "no-root-escalation"),
    ),
    GateSpec(
        "foreign-distribution-onboarding", "foreign-distribution",
        ("real-guix-transaction-matrix",),
        ("guix-system", "two-foreign-distributions", "store-resolved-executable"),
    ),
    GateSpec(
        "eight-hour-stability-soak", "end-to-end-soak",
        ("qt-interactive-accessibility", "real-guix-transaction-matrix"),
        ("duration-at-least-28800-seconds", "memory-cpu-cache-evidence", "daemon-network-gui-power-loss"),
    ),
    GateSpec(
        "linux-7.2-reproducible-build-and-boot", "booted-linux-7.2",
        ("authenticated-guix-qt-environment",),
        ("two-guix-builds", "exact-kconfig-validation", "byte-or-closure-reproducibility", "boot-regression-matrix"),
    ),
    GateSpec(
        "personal-vm-kvm-network-persistence", "kvm-personal-vm",
        ("linux-7.2-reproducible-build-and-boot",),
        ("real-kvm", "outbound-network", "encrypted-durable-storage", "host-root-and-cross-profile-denial"),
    ),
    GateSpec(
        "gaming-vm-kvm-gpu-audio", "kvm-gaming-vm",
        ("linux-7.2-reproducible-build-and-boot",),
        ("steam-heroic-lutris", "pipewire-controller", "virtio-gpu", "iommu-required-for-passthrough", "vfio-noiommu-forbidden"),
    ),
    GateSpec(
        "installer2-disk-matrix", "booted-installer",
        ("linux-7.2-reproducible-build-and-boot",),
        ("uefi-and-bios", "encrypted-and-prepartitioned", "cancel-interrupt-power-loss-recovery", "stable-disk-identity"),
    ),
    GateSpec(
        "desktop-boot-and-gnome-absence", "booted-desktops",
        ("linux-7.2-reproducible-build-and-boot",),
        ("sway", "xmonad-xlibre", "plasma", "xfce", "lxde", "no-selectable-gnome-session"),
    ),
    GateSpec(
        "kvm-microvm-af-vsock", "real-kvm-af-vsock",
        ("linux-7.2-reproducible-build-and-boot",),
        ("real-kvm", "real-af-vsock", "peer-identity-replay-rollback", "pressure-death-cleanup-secret-scan"),
    ),
    GateSpec(
        "reproducible-iso-build-and-boot", "bootable-iso",
        (
            "personal-vm-kvm-network-persistence", "gaming-vm-kvm-gpu-audio",
            "installer2-disk-matrix", "desktop-boot-and-gnome-absence", "kvm-microvm-af-vsock",
            "eight-hour-stability-soak", "foreign-distribution-onboarding",
        ),
        ("two-byte-identical-isos", "sbom-provenance", "bios-uefi-live-install-recovery", "negative-release-gates"),
    ),
)

BLOCKERS: Final[tuple[str, ...]] = (
    "BLOCKED_PHASE38_AUTHENTICATED_GUIX_QT_ENVIRONMENT_REQUIRED",
    "BLOCKED_PHASE38_REPRODUCIBLE_GUIX_CENTER_DERIVATION_REQUIRED",
    "BLOCKED_PHASE38_QT_OFFSCREEN_MATRIX_REQUIRED",
    "BLOCKED_PHASE38_QT_INTERACTIVE_ACCESSIBILITY_REQUIRED",
    "BLOCKED_PHASE38_REAL_GUIX_TRANSACTION_MATRIX_REQUIRED",
    "BLOCKED_PHASE38_FOREIGN_DISTRIBUTION_MATRIX_REQUIRED",
    "BLOCKED_PHASE38_EIGHT_HOUR_STABILITY_SOAK_REQUIRED",
    "BLOCKED_PHASE38_LINUX_7_2_REPRODUCIBLE_BUILD_AND_BOOT_REQUIRED",
    "BLOCKED_PHASE38_PERSONAL_VM_KVM_NETWORK_PERSISTENCE_REQUIRED",
    "BLOCKED_PHASE38_GAMING_VM_KVM_GPU_AUDIO_REQUIRED",
    "BLOCKED_PHASE38_INSTALLER2_DISK_MATRIX_REQUIRED",
    "BLOCKED_PHASE38_DESKTOP_BOOT_AND_GNOME_ABSENCE_REQUIRED",
    "BLOCKED_PHASE38_REAL_KVM_AF_VSOCK_REQUIRED",
    "BLOCKED_PHASE38_REPRODUCIBLE_BOOTABLE_ISO_REQUIRED",
)


def _digest(domain: bytes, value: Mapping[str, Any]) -> str:
    return hashlib.sha256(domain + canonical_json_bytes(value)).hexdigest()


def phase38_contract() -> dict[str, Any]:
    return {
        "format": CONTRACT_FORMAT,
        "status": STATUS,
        "phase37_starting_identities": dict(PHASE37_IDENTITIES),
        "validation": {
            "worker_result_format": "securityops-phase38-unittest-worker-result/1",
            "machine_readable_result_required": True,
            "result_write_only_descriptor_inherited": True,
            "result_descriptor_closed_on_exec_for_test_children": True,
            "exact_test_inventory_bound": True,
            "test_source_bytes_read_through_descriptor": True,
            "test_source_size_and_sha256_bound": True,
            "challenge_bound_to_plan_and_shard": True,
            "worker_source_digest_bound": True,
            "cumulative_runner_source_digest_bound": True,
            "duplicate_json_keys_rejected": True,
            "human_readable_log_is_result_authority": False,
            "result_count_regex_parsing_allowed": False,
            "bounded_logs_enforced_during_execution": True,
            "bounded_worker_receipt": True,
            "process_group_cleanup_required": True,
            "historical_phase37_anomaly_preserved": True,
        },
        "guix_center": {
            "toolkit": "Qt 6 / PySide 6",
            "architecture_count": 1,
            "pages": list(phase37.PAGES),
            "page_states": list(phase37.PAGE_STATES),
            "accessibility_widget_count": sum(len(items) for items in phase37.ACCESSIBILITY_MANIFEST.values()),
            "allowed_actions": list(phase36.ACTIONS),
            "per_user_only": True,
            "root_escalation_allowed": False,
            "shell_execution_allowed": False,
            "caller_supplied_argv_allowed": False,
            "system_reconfigure_available": False,
        },
        "gate_order": [spec.to_dict() for spec in GATE_SPECS],
        "truth_boundary": {
            "fixture_guix_is_real_guix": False,
            "headless_model_is_qt_execution": False,
            "qt_offscreen_is_interactive_session": False,
            "kconfig_is_built_kernel": False,
            "tcg_is_kvm": False,
            "af_unix_is_af_vsock": False,
            "vm_plan_is_running_vm": False,
            "archive_is_bootable_iso": False,
        },
        "blockers": list(BLOCKERS),
        "production_gate_count": len(GATE_SPECS),
        "production_gates_approved": 0,
        "production_dispatch_allowed": False,
        "iso_release_allowed": False,
    }


def phase38_contract_digest() -> str:
    return _digest(CONTRACT_DOMAIN, phase38_contract())


def parse_phase38_contract(value: Mapping[str, Any]) -> dict[str, Any]:
    candidate = json.loads(canonical_json_bytes(value))
    if candidate != phase38_contract():
        raise PolicyError("Phase 38 execution contract differs from the closed contract")
    return candidate


def _bounded_version(path: str) -> dict[str, Any]:
    try:
        result = subprocess.run(
            [path, "--version"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            check=False,
            timeout=3,
            env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
        )
        lines = result.stdout[:4096].strip().splitlines()
        return {"returncode": result.returncode, "first_line": lines[0] if lines else ""}
    except (OSError, subprocess.SubprocessError) as error:
        return {"returncode": None, "first_line": "", "error": type(error).__name__}


def _measure_regular_file(path: Path) -> dict[str, Any]:
    descriptor = os.open(
        path,
        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= MAX_EXECUTABLE_BYTES:
            raise PolicyError("capability executable is not a bounded regular file")
        digest = hashlib.sha256()
        remaining = before.st_size
        while remaining:
            block = os.read(descriptor, min(1024 * 1024, remaining))
            if not block:
                raise PolicyError("capability executable was truncated")
            digest.update(block)
            remaining -= len(block)
        if os.read(descriptor, 1):
            raise PolicyError("capability executable grew while measured")
        after = os.fstat(descriptor)
        identity = lambda item: (
            item.st_dev, item.st_ino, item.st_mode, item.st_uid, item.st_gid,
            item.st_nlink, item.st_size, item.st_mtime_ns, item.st_ctime_ns,
        )
        if identity(before) != identity(after):
            raise PolicyError("capability executable changed while measured")
        return {
            "regular": True,
            "executable": bool(stat.S_IMODE(before.st_mode) & 0o111),
            "size": before.st_size,
            "sha256": digest.hexdigest(),
            "mode": stat.S_IMODE(before.st_mode),
            "uid": before.st_uid,
            "gid": before.st_gid,
            "device": before.st_dev,
            "inode": before.st_ino,
            "link_count": before.st_nlink,
        }
    finally:
        os.close(descriptor)


def _measure_command(name: str, *, include_versions: bool) -> dict[str, Any]:
    candidate = shutil.which(name)
    if candidate is None:
        result: dict[str, Any] = {
            "available": False, "candidate": None, "resolved": None,
            "regular": False, "executable": False, "size": None,
            "sha256": None, "mode": None, "uid": None, "gid": None,
            "device": None, "inode": None, "link_count": None,
            "in_guix_store": False,
        }
        if include_versions:
            result["version"] = {"returncode": None, "first_line": "", "error": "Unavailable"}
        return result
    try:
        resolved = Path(candidate).resolve(strict=True)
        measured = _measure_regular_file(resolved)
    except (OSError, PolicyError):
        result = {
            "available": False, "candidate": candidate, "resolved": None,
            "regular": False, "executable": False, "size": None,
            "sha256": None, "mode": None, "uid": None, "gid": None,
            "device": None, "inode": None, "link_count": None,
            "in_guix_store": False,
        }
        if include_versions:
            result["version"] = {"returncode": None, "first_line": "", "error": "Unmeasurable"}
        return result
    result: dict[str, Any] = {
        "available": measured["regular"] and measured["executable"],
        "candidate": candidate,
        "resolved": os.fspath(resolved),
        **measured,
        "in_guix_store": os.fspath(resolved).startswith("/gnu/store/"),
    }
    if include_versions:
        result["version"] = _bounded_version(os.fspath(resolved))
    return result


def _measure_module(name: str) -> dict[str, Any]:
    try:
        spec = importlib.util.find_spec(name)
    except (ImportError, ValueError):
        spec = None
    return {
        "available": spec is not None,
        "origin": None if spec is None or spec.origin in (None, "built-in") else spec.origin,
    }


def _measure_device(name: str) -> dict[str, Any]:
    path = Path(name)
    try:
        metadata = path.lstat()
    except OSError:
        return {
            "available": False, "character_device": False, "symlink": False,
            "readable": False, "writable": False, "major": None, "minor": None,
        }
    character = stat.S_ISCHR(metadata.st_mode)
    return {
        "available": True,
        "character_device": character,
        "symlink": stat.S_ISLNK(metadata.st_mode),
        "readable": os.access(path, os.R_OK),
        "writable": os.access(path, os.W_OK),
        "major": os.major(metadata.st_rdev) if character else None,
        "minor": os.minor(metadata.st_rdev) if character else None,
    }


def _derived_capabilities(
    commands: Mapping[str, Mapping[str, Any]],
    modules: Mapping[str, Mapping[str, Any]],
    devices: Mapping[str, Mapping[str, Any]],
) -> dict[str, bool]:
    guix_commands = ("guix", "guile", "guild")
    store_resident_guix = all(
        commands[name]["available"] and commands[name]["in_guix_store"]
        for name in guix_commands
    )
    qt_runtime = bool(modules["PySide6"]["available"])
    kvm_device = devices["/dev/kvm"]
    vsock_devices = (devices["/dev/vhost-vsock"], devices["/dev/vsock"])
    return {
        # Store residency is a discovery fact only.  It does not authenticate
        # the channel, executable closure, daemon, ACL, or daemon policy.
        "store_resident_guix_candidate": store_resident_guix,
        "qt_runtime": qt_runtime,
        "qt_offscreen_harness": bool(
            qt_runtime and commands["xvfb-run"]["available"] and commands["dbus-run-session"]["available"]
        ),
        "rust_toolchain_candidate": bool(commands["rustc"]["available"] and commands["cargo"]["available"]),
        "kvm_candidate": bool(
            commands["qemu-system-x86_64"]["available"]
            and kvm_device["available"] and kvm_device["character_device"]
            and not kvm_device["symlink"] and kvm_device["readable"] and kvm_device["writable"]
        ),
        "af_vsock_candidate": bool(
            commands["qemu-system-x86_64"]["available"]
            and any(item["available"] and item["character_device"] and not item["symlink"] for item in vsock_devices)
        ),
        "iso_toolchain_candidate": bool(
            commands["xorriso"]["available"]
            and commands["grub-mkrescue"]["available"]
            and commands["mksquashfs"]["available"]
        ),
    }


def capability_attestation(*, include_versions: bool = False) -> dict[str, Any]:
    commands = {name: _measure_command(name, include_versions=include_versions) for name in COMMANDS}
    modules = {name: _measure_module(name) for name in PYTHON_MODULES}
    devices = {name: _measure_device(name) for name in DEVICES}
    unsigned: dict[str, Any] = {
        "format": CAPABILITY_FORMAT,
        "status": "PASS_PHASE38_LOCAL_CAPABILITY_PROBE_FAIL_CLOSED",
        "versions_included": include_versions,
        "host": {
            "system": platform.system(),
            "machine": platform.machine(),
            "kernel_release": platform.release(),
            "python_version": platform.python_version(),
        },
        "commands": commands,
        "python_modules": modules,
        "devices": devices,
        "derived_capabilities": _derived_capabilities(commands, modules, devices),
        "capability_probe_is_execution_gate_evidence": False,
        "owner_authenticated": False,
        "production_gates_approved": 0,
        "production_dispatch_allowed": False,
        "iso_release_allowed": False,
    }
    return {**unsigned, "attestation_digest": _digest(CAPABILITY_DOMAIN, unsigned)}


def _is_sha256(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _validate_capability_structure(report: Mapping[str, Any]) -> None:
    host = report.get("host")
    if type(host) is not dict or set(host) != {"system", "machine", "kernel_release", "python_version"}:
        raise PolicyError("Phase 38 host capability fields are not closed")
    if any(not isinstance(value, str) or not value or len(value) > 512 for value in host.values()):
        raise PolicyError("Phase 38 host capability value is invalid")

    versions_included = report["versions_included"]
    command_fields = {
        "available", "candidate", "resolved", "regular", "executable", "size",
        "sha256", "mode", "uid", "gid", "device", "inode", "link_count",
        "in_guix_store",
    }
    if versions_included:
        command_fields.add("version")
    for name, command in report["commands"].items():
        if type(command) is not dict or set(command) != command_fields:
            raise PolicyError(f"Phase 38 command capability fields are not closed: {name}")
        for field in ("available", "regular", "executable", "in_guix_store"):
            if type(command[field]) is not bool:
                raise PolicyError(f"Phase 38 command capability Boolean is invalid: {name}/{field}")
        for field in ("candidate", "resolved"):
            value = command[field]
            if value is not None and (not isinstance(value, str) or not value or len(value) > 4096):
                raise PolicyError(f"Phase 38 command capability path is invalid: {name}/{field}")
        for field in ("size", "mode", "uid", "gid", "device", "inode", "link_count"):
            value = command[field]
            if value is not None and (type(value) is not int or value < 0):
                raise PolicyError(f"Phase 38 command capability number is invalid: {name}/{field}")
        if command["sha256"] is not None and not _is_sha256(command["sha256"]):
            raise PolicyError(f"Phase 38 command capability digest is invalid: {name}")
        if command["available"]:
            if (
                not command["regular"] or not command["executable"]
                or command["resolved"] is None or not _is_sha256(command["sha256"])
                or type(command["size"]) is not int or command["size"] <= 0
                or type(command["link_count"]) is not int or command["link_count"] <= 0
            ):
                raise PolicyError(f"Phase 38 available command lacks measured identity: {name}")
        if versions_included:
            version = command["version"]
            if type(version) is not dict or set(version) not in (
                {"returncode", "first_line"}, {"returncode", "first_line", "error"},
            ):
                raise PolicyError(f"Phase 38 command version fields are invalid: {name}")
            if version["returncode"] is not None and type(version["returncode"]) is not int:
                raise PolicyError(f"Phase 38 command version return code is invalid: {name}")
            if not isinstance(version["first_line"], str) or len(version["first_line"]) > 4096:
                raise PolicyError(f"Phase 38 command version output is invalid: {name}")
            if "error" in version and (
                not isinstance(version["error"], str) or not version["error"] or len(version["error"]) > 256
            ):
                raise PolicyError(f"Phase 38 command version error is invalid: {name}")

    for name, module in report["python_modules"].items():
        if type(module) is not dict or set(module) != {"available", "origin"}:
            raise PolicyError(f"Phase 38 Python-module capability fields are invalid: {name}")
        if type(module["available"]) is not bool:
            raise PolicyError(f"Phase 38 Python-module capability flag is invalid: {name}")
        if module["origin"] is not None and (
            not isinstance(module["origin"], str) or not module["origin"] or len(module["origin"]) > 4096
        ):
            raise PolicyError(f"Phase 38 Python-module origin is invalid: {name}")

    device_fields = {
        "available", "character_device", "symlink", "readable", "writable", "major", "minor",
    }
    for name, device in report["devices"].items():
        if type(device) is not dict or set(device) != device_fields:
            raise PolicyError(f"Phase 38 device capability fields are invalid: {name}")
        for field in ("available", "character_device", "symlink", "readable", "writable"):
            if type(device[field]) is not bool:
                raise PolicyError(f"Phase 38 device capability Boolean is invalid: {name}/{field}")
        for field in ("major", "minor"):
            value = device[field]
            if value is not None and (type(value) is not int or value < 0):
                raise PolicyError(f"Phase 38 device capability number is invalid: {name}/{field}")

    expected_derived = {
        "store_resident_guix_candidate", "qt_runtime", "qt_offscreen_harness",
        "rust_toolchain_candidate", "kvm_candidate", "af_vsock_candidate",
        "iso_toolchain_candidate",
    }
    derived = report["derived_capabilities"]
    if type(derived) is not dict or set(derived) != expected_derived or any(
        type(value) is not bool for value in derived.values()
    ):
        raise PolicyError("Phase 38 derived capability fields are invalid")


def parse_capability_attestation(
    value: Mapping[str, Any], *, verify_current_environment: bool = False,
) -> dict[str, Any]:
    fields = {
        "format", "status", "versions_included", "host", "commands",
        "python_modules", "devices", "derived_capabilities",
        "capability_probe_is_execution_gate_evidence", "owner_authenticated",
        "production_gates_approved", "production_dispatch_allowed",
        "iso_release_allowed", "attestation_digest",
    }
    if type(value) is not dict or set(value) != fields:
        raise PolicyError("Phase 38 capability attestation fields are not closed")
    report = json.loads(canonical_json_bytes(value))
    if report["format"] != CAPABILITY_FORMAT or report["status"] != "PASS_PHASE38_LOCAL_CAPABILITY_PROBE_FAIL_CLOSED":
        raise PolicyError("Phase 38 capability attestation identity is invalid")
    if type(report["versions_included"]) is not bool:
        raise PolicyError("Phase 38 capability version flag is invalid")
    if set(report["commands"]) != set(COMMANDS):
        raise PolicyError("Phase 38 command inventory is incomplete")
    if set(report["python_modules"]) != set(PYTHON_MODULES):
        raise PolicyError("Phase 38 Python-module inventory is incomplete")
    if set(report["devices"]) != set(DEVICES):
        raise PolicyError("Phase 38 device inventory is incomplete")
    _validate_capability_structure(report)
    derived = _derived_capabilities(report["commands"], report["python_modules"], report["devices"])
    if report["derived_capabilities"] != derived:
        raise PolicyError("Phase 38 derived capabilities do not match measured facts")
    if report["capability_probe_is_execution_gate_evidence"] is not False:
        raise PolicyError("Phase 38 capability probe attempted to become execution evidence")
    if report["owner_authenticated"] is not False:
        raise PolicyError("local Phase 38 capability probe claimed owner authentication")
    if report["production_gates_approved"] != 0 or report["production_dispatch_allowed"] or report["iso_release_allowed"]:
        raise PolicyError("Phase 38 capability attestation attempted release promotion")
    supplied = report.pop("attestation_digest")
    if not _is_sha256(supplied) or supplied != _digest(CAPABILITY_DOMAIN, report):
        raise PolicyError("Phase 38 capability attestation digest mismatch")
    report["attestation_digest"] = supplied
    if verify_current_environment:
        current = capability_attestation(include_versions=report["versions_included"])
        if report != current:
            raise PolicyError("Phase 38 capability attestation differs from the current environment")
    return report


def local_gate_report(attestation: Mapping[str, Any]) -> dict[str, Any]:
    checked = parse_capability_attestation(attestation)
    capabilities = checked["derived_capabilities"]
    capability_notes = {
        "authenticated-guix-qt-environment": [
            "store-resident-guix-candidate"
            if capabilities["store_resident_guix_candidate"]
            else "missing-store-resident-guix-tools",
            "store-residency-is-not-authentication",
            "explicit-measured-client-daemon-channel-and-acl-required",
            "qt_runtime" if capabilities["qt_runtime"] else "missing-pyside6-runtime",
            "owner-authenticated-closure-required",
        ],
        "qt-offscreen-matrix": [
            "qt-offscreen-candidate" if capabilities["qt_offscreen_harness"] else "missing-qt-offscreen-candidate",
            "actual-matrix-not-executed-by-capability-probe",
        ],
        "linux-7.2-reproducible-build-and-boot": ["actual-linux-7.2-guix-build-and-boot-required"],
        "personal-vm-kvm-network-persistence": [
            "kvm-candidate" if capabilities["kvm_candidate"] else "missing-kvm-candidate",
            "actual-personal-vm-execution-required",
        ],
        "gaming-vm-kvm-gpu-audio": [
            "kvm-candidate" if capabilities["kvm_candidate"] else "missing-kvm-candidate",
            "actual-gaming-vm-execution-required",
        ],
        "kvm-microvm-af-vsock": [
            "kvm-candidate" if capabilities["kvm_candidate"] else "missing-kvm-candidate",
            "af-vsock-candidate" if capabilities["af_vsock_candidate"] else "missing-af-vsock-candidate",
            "actual-authenticated-af-vsock-execution-required",
        ],
        "reproducible-iso-build-and-boot": [
            "iso-toolchain-candidate" if capabilities["iso_toolchain_candidate"] else "missing-iso-toolchain-candidate",
            "actual-two-build-and-boot-matrix-required",
        ],
    }
    gates = []
    for spec, blocker in zip(GATE_SPECS, BLOCKERS, strict=True):
        notes = capability_notes.get(spec.name, ["actual-capability-execution-evidence-required"])
        gates.append({
            "name": spec.name,
            "state": "blocked",
            "evidence_scope": spec.evidence_scope,
            "prerequisites": list(spec.prerequisites),
            "requirements": list(spec.requirements),
            "observations": notes,
            "blocker": blocker,
            "production_gate_approved": False,
        })
    unsigned: dict[str, Any] = {
        "format": GATE_REPORT_FORMAT,
        "status": "BLOCKED_PHASE38_REAL_EXECUTION_CAPABILITIES_UNAVAILABLE_OR_UNEXECUTED",
        "phase38_contract_digest": phase38_contract_digest(),
        "capability_attestation_digest": checked["attestation_digest"],
        "gates": gates,
        "passed_gate_names": [],
        "blocked_gate_names": [spec.name for spec in GATE_SPECS],
        "blockers": list(BLOCKERS),
        "production_gates_approved": 0,
        "production_dispatch_allowed": False,
        "iso_release_allowed": False,
        "iso_bytes_present": False,
    }
    return {**unsigned, "report_digest": _digest(GATE_REPORT_DOMAIN, unsigned)}


def parse_local_gate_report(value: Mapping[str, Any], attestation: Mapping[str, Any]) -> dict[str, Any]:
    expected = local_gate_report(attestation)
    candidate = json.loads(canonical_json_bytes(value))
    if candidate != expected:
        raise PolicyError("Phase 38 local gate report differs from measured fail-closed state")
    return candidate


def phase38_selftest() -> dict[str, Any]:
    contract = phase38_contract()
    parse_phase38_contract(contract)
    mutations = (
        lambda value: value["validation"].__setitem__("machine_readable_result_required", False),
        lambda value: value["validation"].__setitem__("human_readable_log_is_result_authority", True),
        lambda value: value["validation"].__setitem__("result_count_regex_parsing_allowed", True),
        lambda value: value["validation"].__setitem__("worker_source_digest_bound", False),
        lambda value: value["validation"].__setitem__("test_source_size_and_sha256_bound", False),
        lambda value: value["validation"].__setitem__("cumulative_runner_source_digest_bound", False),
        lambda value: value["validation"].__setitem__("bounded_logs_enforced_during_execution", False),
        lambda value: value["validation"].__setitem__("test_source_bytes_read_through_descriptor", False),
        lambda value: value["validation"].__setitem__("historical_phase37_anomaly_preserved", False),
        lambda value: value["guix_center"].__setitem__("architecture_count", 2),
        lambda value: value["guix_center"].__setitem__("root_escalation_allowed", True),
        lambda value: value["truth_boundary"].__setitem__("tcg_is_kvm", True),
        lambda value: value["truth_boundary"].__setitem__("af_unix_is_af_vsock", True),
        lambda value: value["truth_boundary"].__setitem__("archive_is_bootable_iso", True),
        lambda value: value["gate_order"].pop(),
        lambda value: value["gate_order"].reverse(),
        lambda value: value["blockers"].pop(),
        lambda value: value.__setitem__("production_gates_approved", 1),
        lambda value: value.__setitem__("production_dispatch_allowed", True),
        lambda value: value.__setitem__("iso_release_allowed", True),
    )
    rejected = 0
    for mutate in mutations:
        candidate = json.loads(json.dumps(contract))
        mutate(candidate)
        try:
            parse_phase38_contract(candidate)
        except PolicyError:
            rejected += 1
    if rejected != len(mutations):
        raise AssertionError("Phase 38 contract self-test accepted a downgrade")
    attestation = capability_attestation(include_versions=False)
    parse_capability_attestation(attestation, verify_current_environment=True)
    gate_report = local_gate_report(attestation)
    parse_local_gate_report(gate_report, attestation)
    return {
        "status": STATUS,
        "contract_digest": phase38_contract_digest(),
        "negative_cases_rejected": rejected,
        "capability_attestation_digest": attestation["attestation_digest"],
        "gate_report_digest": gate_report["report_digest"],
        "production_gates_approved": 0,
        "production_dispatch_allowed": False,
        "iso_release_allowed": False,
    }
