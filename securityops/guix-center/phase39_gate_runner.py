#!/usr/bin/env python3
# CodeMark v1 project=4c63e0fe-589c-4944-8449-97e211a38b72 file=cbddf69f87b15e84861729c4aff0f57a owner="Cristian Cezar Mois\u00e9s"
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-SecurityOps-Commercial
"""Collect or import Phase 39 owner-signed execution-gate evidence.

Without an explicit exchange directory this runner produces a measured,
fail-closed local report. With one, it verifies dual-signed gate exchanges in
strict gate order and remeasures every referenced log and evidence file.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import time
from typing import Any

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import phase38_execution as phase38
import phase39_owner_execution as phase39

FORMAT = "securityops-phase39-gate-runner-evidence/1"
DOMAIN = b"SECURITYOPS-PHASE39-GATE-RUNNER-EVIDENCE-V1\x00"


def canonical(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"),
        ensure_ascii=False).encode("utf-8")


def digest(value: dict[str, Any]) -> str:
    return hashlib.sha256(DOMAIN + canonical(value)).hexdigest()


def _private_directory(path: Path, *, create: bool = False) -> Path:
    candidate = path.absolute()
    if create:
        candidate.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(candidate, 0o700)
    if candidate.is_symlink():
        raise phase39.PolicyError(
            "Phase 39 gate-runner directory cannot be a symbolic link")
    info = candidate.stat()
    if (not stat.S_ISDIR(info.st_mode)
            or stat.S_IMODE(info.st_mode) & 0o022
            or info.st_uid not in {0, os.getuid()}):
        raise phase39.PolicyError(
            "Phase 39 gate-runner directory is not private")
    return candidate


def _write_atomic(path: Path, value: dict[str, Any]) -> None:
    parent = _private_directory(path.parent, create=True)
    payload = json.dumps(
        value, sort_keys=True, indent=2,
        ensure_ascii=False).encode("utf-8") + b"\n"
    descriptor, raw = tempfile.mkstemp(
        prefix=".phase39-evidence-", dir=parent)
    temporary = Path(raw)
    try:
        os.fchmod(descriptor, 0o600)
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise phase39.PolicyError(
                    "unable to write Phase 39 gate evidence")
            view = view[written:]
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        os.replace(temporary, path)
        directory_fd = os.open(
            parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _exchange_directory(
    root: Path, index: int, gate_name: str,
) -> Path:
    return root / f"{index:02d}-{gate_name}"


def _verify_available_exchanges(
    *, exchange_root: Path, output_root: Path,
    owner_fingerprint: str, now_unix: int, gpgv: Path,
) -> list[phase39.VerifiedGateExchange]:
    root = _private_directory(exchange_root)
    ledger = output_root / "state" / "replay-ledger.json"
    verified: list[phase39.VerifiedGateExchange] = []
    for index, gate_name in enumerate(phase39.GATE_NAMES, 1):
        gate_root = _exchange_directory(root, index, gate_name)
        if not gate_root.exists():
            break
        gate_root = _private_directory(gate_root)
        evidence_root = _private_directory(gate_root / "evidence")
        item = phase39.verify_signed_gate_exchange(
            job_path=gate_root / "job.json",
            job_signature_path=gate_root / "job.json.sig",
            owner_keyring_path=gate_root / "owner-job-keyring.gpg",
            result_path=gate_root / "result.json",
            result_signature_path=gate_root / "result.json.sig",
            result_keyring_path=gate_root / "result-keyring.gpg",
            evidence_root=evidence_root,
            replay_ledger_path=ledger,
            expected_owner_fingerprint=owner_fingerprint,
            now_unix=now_unix,
            gpgv_executable=gpgv,
        )
        if item.gate_name != gate_name:
            raise phase39.PolicyError(
                "Phase 39 exchange directory gate identity drifted")
        verified.append(item)
    return verified


def collect(
    *, os_root: Path, output_root: Path,
    exchange_root: Path | None = None,
    owner_fingerprint: str | None = None,
    now_unix: int | None = None,
    gpgv: Path = Path("/usr/bin/gpgv"),
) -> dict[str, Any]:
    os_root = os_root.resolve(strict=True)
    output_root = _private_directory(output_root, create=True)
    contract_path = (
        os_root / "securityops/guix-center/"
        "phase39-owner-execution-contract.json"
    )
    contract = json.loads(contract_path.read_text(encoding="utf-8"))
    phase39.parse_phase39_contract(contract)
    attestation = phase38.capability_attestation(
        include_versions=False)
    phase38.parse_capability_attestation(
        attestation, verify_current_environment=True)
    verifications: list[phase39.VerifiedGateExchange] = []
    if exchange_root is not None:
        if owner_fingerprint is None:
            raise phase39.PolicyError(
                "Phase 39 exchange import requires a locally pinned "
                "owner fingerprint")
        verifications = _verify_available_exchanges(
            exchange_root=exchange_root,
            output_root=output_root,
            owner_fingerprint=owner_fingerprint,
            now_unix=int(time.time()) if now_unix is None else now_unix,
            gpgv=gpgv,
        )
    evaluation = phase39.evaluate_gate_verifications(verifications)
    unsigned = {
        "format": FORMAT,
        "status": evaluation["status"],
        "phase39_contract_digest":
            phase39.phase39_contract_digest(),
        "phase38_capability_attestation_digest":
            attestation["attestation_digest"],
        "capability_probe_is_gate_evidence": False,
        "exchange_root_supplied": exchange_root is not None,
        "verified_exchange_count": len(verifications),
        "verified_exchanges": [
            item.to_dict() for item in verifications
        ],
        "ordered_evaluation": evaluation,
        "production_gates_approved":
            evaluation["production_gates_approved"],
        "production_dispatch_allowed":
            evaluation["production_dispatch_allowed"],
        "iso_release_allowed": evaluation["iso_release_allowed"],
        "iso_bytes_present": evaluation["iso_bytes_present"],
        "release_decision": evaluation["release_decision"],
    }
    return {**unsigned, "evidence_digest": digest(unsigned)}


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description=__doc__)
    value.add_argument("--os-root", type=Path, required=True)
    value.add_argument("--output-root", type=Path, required=True)
    value.add_argument("--output", type=Path, required=True)
    value.add_argument("--exchange-root", type=Path)
    value.add_argument("--owner-fingerprint")
    value.add_argument("--now", type=int)
    value.add_argument(
        "--gpgv", type=Path, default=Path("/usr/bin/gpgv"))
    return value


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    value = collect(
        os_root=args.os_root,
        output_root=args.output_root,
        exchange_root=args.exchange_root,
        owner_fingerprint=args.owner_fingerprint,
        now_unix=args.now,
        gpgv=args.gpgv,
    )
    _write_atomic(args.output, value)
    print(json.dumps(
        value, sort_keys=True, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
