#!/usr/bin/env python3
# CodeMark v1 project=4c63e0fe-589c-4944-8449-97e211a38b72 file=84d21c6207ea5fbda3d72ff47af3fa40 owner="Cristian Cezar Mois\u00e9s"
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-SecurityOps-Commercial
"""Collect Phase 38 Guix Center capability and portable execution evidence.

This runner executes only gates whose prerequisites actually exist.  Headless
models, fixture actions, and SQLite measurements remain explicitly portable and
cannot promote Guix, Qt, KVM, AF_VSOCK, boot, or ISO gates.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import time
from typing import Any

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, os.fspath(SCRIPT_DIR))

import phase37_matrix as matrix  # noqa: E402
from phase46_guix_execution import VerifiedGuixExecutionProfile  # noqa: E402
from phase37_ui_model import render_headless_snapshot, validate_headless_snapshot  # noqa: E402
from phase38_execution import (  # noqa: E402
    capability_attestation,
    local_gate_report,
    parse_capability_attestation,
    parse_local_gate_report,
    phase38_contract_digest,
)

FORMAT = "securityops-phase38-gate-runner-evidence/1"
DOMAIN = b"SECURITYOPS-PHASE38-GATE-RUNNER-EVIDENCE-V1\x00"


def _private_output_directory(path: Path) -> Path:
    candidate = path.absolute()
    parent = candidate.parent.resolve(strict=True)
    candidate = parent / candidate.name
    try:
        metadata = candidate.lstat()
    except FileNotFoundError:
        candidate.mkdir(mode=0o700)
        metadata = candidate.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise RuntimeError("Phase 38 output root must be a real directory")
    if metadata.st_uid != os.getuid():
        raise RuntimeError("Phase 38 output root has an unexpected owner")
    os.chmod(candidate, 0o700)
    verified = candidate.lstat()
    if stat.S_IMODE(verified.st_mode) != 0o700:
        raise RuntimeError("Phase 38 output root is not private")
    return candidate


def canonical(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def digest(value: dict[str, Any]) -> str:
    return hashlib.sha256(DOMAIN + canonical(value)).hexdigest()


def _headless_matrix() -> dict[str, Any]:
    vectors: list[dict[str, Any]] = []
    states = {
        "discover": "loading",
        "installed": "ready",
        "updates": "empty",
        "generations": "stale",
        "profiles": "offline",
        "channels-and-trust": "error",
        "storage": "ready",
        "activity": "ready",
    }
    for width in (640, 1080, 1920):
        for scale in (1.0, 1.25, 1.5, 2.0):
            snapshot = render_headless_snapshot(
                width_px=width, height_px=820, scale_factor=scale,
                page_states=states,
            )
            validate_headless_snapshot(snapshot)
            vectors.append({
                "width_px": width,
                "scale_factor": scale,
                "layout": snapshot["layout"]["mode"],
                "snapshot_digest": snapshot["snapshot_digest"],
            })
    return {
        "status": "PASS_PHASE38_PORTABLE_HEADLESS_LAYOUT_MODEL",
        "vectors": vectors,
        "vector_count": len(vectors),
        "headless_model_is_qt_execution": False,
        "production_gate_approved": False,
    }


def collect(
    *,
    os_root: Path,
    output_root: Path,
    soak_seconds: float,
    guix_execution_profile: VerifiedGuixExecutionProfile | None = None,
) -> dict[str, Any]:
    os_root = os_root.resolve(strict=True)
    output_root = _private_output_directory(output_root)
    capabilities = capability_attestation(include_versions=True)
    parse_capability_attestation(capabilities, verify_current_environment=True)
    gates = local_gate_report(capabilities)
    parse_local_gate_report(gates, capabilities)
    frontend = os_root / "securityops/guix-center/securityops_guix_center.py"
    started = time.monotonic()
    portable: dict[str, Any] = {
        "headless_ui": _headless_matrix(),
        "state_model": matrix.state_model_matrix(iterations=2_000),
        "failure_classification": matrix.failure_classification_matrix(),
    }
    if soak_seconds > 0:
        portable["bounded_soak"] = matrix.bounded_soak(10_000, soak_seconds)
    derived = capabilities["derived_capabilities"]
    qt = (
        matrix.qt_offscreen_matrix(frontend, output_root)
        if derived["qt_offscreen_harness"]
        else {"status": "BLOCKED_PYSIDE6_OR_QT_OFFSCREEN_HARNESS_UNAVAILABLE", "executed": False}
    )
    guix = matrix.guix_derivation_matrix(
        os_root,
        output_root,
        execution_profile=guix_execution_profile,
    )
    unsigned: dict[str, Any] = {
        "format": FORMAT,
        "status": "PASS_PHASE38_LOCAL_EVIDENCE_COLLECTION_FAIL_CLOSED",
        "phase38_contract_digest": phase38_contract_digest(),
        "capability_attestation": capabilities,
        "local_gate_report": gates,
        "portable": portable,
        "capability_gated": {
            "qt_offscreen": qt,
            "guix_derivation": guix,
            "qt_interactive": {
                "status": "BLOCKED_REAL_INTERACTIVE_GRAPHICAL_SESSION_REQUIRED",
                "executed": False,
            },
            "real_guix_transactions": {
                "status": "BLOCKED_DISPOSABLE_REAL_GUIX_PROFILE_MATRIX_REQUIRED",
                "executed": False,
            },
            "linux_7_2": {
                "status": "BLOCKED_TWO_GUIX_BUILDS_AND_BOOT_REQUIRED",
                "executed": False,
            },
            "kvm_af_vsock": {
                "status": "BLOCKED_REAL_KVM_AF_VSOCK_REQUIRED",
                "executed": False,
            },
            "iso": {
                "status": "BLOCKED_TWO_REPRODUCIBLE_BOOTABLE_ISOS_REQUIRED",
                "executed": False,
            },
        },
        "elapsed_seconds": round(time.monotonic() - started, 6),
        "production_gates_approved": 0,
        "production_dispatch_allowed": False,
        "iso_release_allowed": False,
        "iso_bytes_present": False,
    }
    return {**unsigned, "evidence_digest": digest(unsigned)}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--os-root", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--soak-seconds", type=float, default=0.0)
    args = parser.parse_args(argv)
    if not 0.0 <= args.soak_seconds <= 28_800:
        parser.error("--soak-seconds must be in [0, 28800]")
    output_root = _private_output_directory(args.output_root)
    output = args.output.absolute()
    if output.parent.resolve(strict=True) != output_root:
        parser.error("--output must be a direct child of --output-root")
    if output.exists() and output.is_symlink():
        parser.error("--output must not be a symbolic link")
    evidence = collect(
        os_root=args.os_root, output_root=output_root,
        soak_seconds=args.soak_seconds,
    )
    matrix.atomic_json(output, evidence)
    print(json.dumps(evidence, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
