# CodeMark v1 project=4c63e0fe-589c-4944-8449-97e211a38b72 file=d091d83e20dd58b09cf19b2568e4930b owner="Cristian Cezar Mois\u00e9s"
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Phase 45 concrete gate-execution harness.

Phase 44 is the final source-level Gate 1 authority boundary.  Phase 45 does not
add another authority protocol.  It turns the inherited contracts into a
bounded execution harness that measures the current host, executes every
portable check that is genuinely available, and leaves production gates
blocked until the exact externally controlled receipts and hardware exist.
"""
from __future__ import annotations

from dataclasses import dataclass
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
import sys
import time
from typing import Any, Final, Mapping, Sequence

try:
    from . import phase38_execution as phase38
    from . import phase40_owner_trust as phase40
    from . import process_groups
except ImportError:  # pragma: no cover - installed Guix Center sibling copy
    import phase38_execution as phase38  # type: ignore[no-redef]
    import phase40_owner_trust as phase40  # type: ignore[no-redef]
    import process_groups  # type: ignore[no-redef]

PolicyError = phase40.PolicyError
canonical_json_bytes = phase40.canonical_json_bytes

CONTRACT_FORMAT: Final[str] = "securityops-phase45-execution-contract/1"
REPORT_FORMAT: Final[str] = "securityops-phase45-execution-report/1"
STATUS: Final[str] = "PASS_PHASE45_CONCRETE_EXECUTION_HARNESS_AND_PORTABLE_EVIDENCE"
BLOCKED_STATUS: Final[str] = "BLOCKED_PHASE45_EXTERNAL_AUTHORITY_GUIX_HARDWARE_AND_ISO_EXECUTION_REQUIRED"
CONTRACT_DOMAIN: Final[bytes] = b"SECURITYOPS-PHASE45-EXECUTION-CONTRACT-V1\x00"
REPORT_DOMAIN: Final[bytes] = b"SECURITYOPS-PHASE45-EXECUTION-REPORT-V1\x00"
STEP_DOMAIN: Final[bytes] = b"SECURITYOPS-PHASE45-EXECUTION-STEP-V1\x00"

PHASE44_IDENTITIES: Final[dict[str, str]] = {
    "runtime_commit": "5c087d847086ba8af3f360625c3b5a10708f619e",
    "runtime_tree": "5f1ac251f0ea159243fdd1eda4625c72b6b09084",
    "securityops_os_commit": "0dc30bf84ae576c081722c0c24d9558b3d76c6bd",
    "securityops_os_tree": "25bade878df465612385c9e2d981ce7756e570fa",
    "stable_v1_13_0": "8373fd789c9a525d6128abfd3d7a93ad4db3348b",
}
PHASE44_CONTRACT_DIGESTS: Final[dict[str, str]] = {
    "gate1_closure": "c7c5797db1a4b0945f088c46fe38ef95c1dc1e6d163c825da9b4a9c501997636",
    "gate1_dossier": "faf075ec156a4b167feda6a4822833cceaa6273aeef4ce75f84f973bf23b4a34",
    "offline_admission": "d78d6b02b4740c2efb5450aa2e80d0907853117c3490a6fd5407ffd66960690c",
}

PORTABLE_STEP_NAMES: Final[tuple[str, ...]] = (
    "source-identities",
    "guix-center-portable-matrix",
    "native-reproducibility-probe",
    "python-bytecode-validation",
    "git-diff-check",
)
PRODUCTION_GATE_NAMES: Final[tuple[str, ...]] = tuple(spec.name for spec in phase38.GATE_SPECS)
PHASE45_BLOCKERS: Final[tuple[str, ...]] = (
    "BLOCKED_PHASE45_REAL_SIX_ROLE_AUTHORITY_AND_GATE1_RECEIPT_REQUIRED",
    "BLOCKED_PHASE45_AUTHENTICATED_35_ARTIFACT_CLOSURE_REQUIRED",
    "BLOCKED_PHASE45_AUTHENTICATED_GUIX_GUILE_QT_PYSIDE_ENVIRONMENT_REQUIRED",
    "BLOCKED_PHASE45_REPRODUCIBLE_GUIX_CENTER_STORE_CLOSURE_REQUIRED",
    "BLOCKED_PHASE45_REAL_QT_OFFSCREEN_INTERACTIVE_ACCESSIBILITY_REQUIRED",
    "BLOCKED_PHASE45_REAL_GUIX_TRANSACTION_AND_FOREIGN_DISTRO_MATRIX_REQUIRED",
    "BLOCKED_PHASE45_EIGHT_HOUR_END_TO_END_SOAK_REQUIRED",
    "BLOCKED_PHASE45_CANONICAL_EVELIN_ESQUEMA_AND_RUST_RUNTIME_REQUIRED",
    "BLOCKED_PHASE45_LINUX_7_2_REPRODUCIBLE_BUILD_AND_BOOT_REQUIRED",
    "BLOCKED_PHASE45_PERSONAL_AND_GAMING_KVM_VM_EXECUTION_REQUIRED",
    "BLOCKED_PHASE45_INSTALLER2_AND_FIVE_DESKTOP_BOOT_MATRIX_REQUIRED",
    "BLOCKED_PHASE45_REAL_KVM_AF_VSOCK_EXECUTION_REQUIRED",
    "BLOCKED_PHASE45_TWO_REPRODUCIBLE_BOOTABLE_INSTALLABLE_ISOS_REQUIRED",
)

MAX_STEP_OUTPUT: Final[int] = 8 * 1024 * 1024
MAX_FILE_BYTES: Final[int] = 512 * 1024 * 1024
MAX_STEP_SECONDS: Final[int] = 900
_PROCESS_GROUP_TERM_GRACE: Final[float] = 0.75
_PROCESS_GROUP_KILL_GRACE: Final[float] = 1.25
_RUNNER_SIGNALS: Final[tuple[signal.Signals, ...]] = (
    signal.SIGHUP,
    signal.SIGINT,
    signal.SIGTERM,
)
ZERO_SHA: Final[str] = "0" * 64
_NATIVE_DISCOVERY_PATH: Final[str] = (
    "/run/current-system/profile/sbin:/run/current-system/profile/bin:"
    "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
)
_NATIVE_TOOL_NAMES: Final[tuple[str, ...]] = ("gcc", "as", "ld", "readelf")


def _digest(domain: bytes, value: Mapping[str, Any]) -> str:
    return hashlib.sha256(domain + canonical_json_bytes(value)).hexdigest()


def _sha256_path(path: Path, *, maximum: int = MAX_FILE_BYTES) -> dict[str, Any]:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise PolicyError(f"{path} is not a regular file")
        if before.st_nlink != 1:
            raise PolicyError(f"{path} must have exactly one hard link")
        if not 0 <= before.st_size <= maximum:
            raise PolicyError(f"{path} exceeds the bounded file size")
        digest = hashlib.sha256()
        remaining = before.st_size
        while remaining:
            block = os.read(descriptor, min(1024 * 1024, remaining))
            if not block:
                raise PolicyError(f"{path} was truncated during measurement")
            digest.update(block)
            remaining -= len(block)
        if os.read(descriptor, 1):
            raise PolicyError(f"{path} grew during measurement")
        after = os.fstat(descriptor)
        identity = lambda item: (
            item.st_dev, item.st_ino, item.st_mode, item.st_uid, item.st_gid,
            item.st_nlink, item.st_size, item.st_mtime_ns, item.st_ctime_ns,
        )
        if identity(before) != identity(after):
            raise PolicyError(f"{path} changed during measurement")
        return {
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


def _secure_directory(path: Path, *, create: bool = True) -> Path:
    path = path.absolute()
    if create:
        path.mkdir(mode=0o700, parents=True, exist_ok=False)
    metadata = path.lstat()
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise PolicyError(f"{path} is not a safe directory")
    if metadata.st_uid != os.getuid():
        raise PolicyError(f"{path} is not owned by the current user")
    if stat.S_IMODE(metadata.st_mode) & 0o077:
        raise PolicyError(f"{path} must be private")
    return path


def _atomic_json(path: Path, value: Mapping[str, Any]) -> dict[str, Any]:
    payload = canonical_json_bytes(value) + b"\n"
    parent = path.parent
    parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(parent, 0o700)
    temporary = parent / f".{path.name}.{os.getpid()}.tmp"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    descriptor = os.open(temporary, flags, 0o600)
    try:
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise PolicyError("atomic JSON publication made no progress")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.replace(temporary, path)
    directory_fd = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)
    return _sha256_path(path, maximum=16 * 1024 * 1024)


def _unsigned_phase45_contract() -> dict[str, Any]:
    return {
        "format": CONTRACT_FORMAT,
        "status": STATUS,
        "phase44_starting_identities": dict(PHASE44_IDENTITIES),
        "phase44_contract_digests": dict(PHASE44_CONTRACT_DIGESTS),
        "phase38_gate_contract_digest": phase38.phase38_contract_digest(),
        "mission": {
            "phase44_is_final_source_level_gate1_authority_boundary": True,
            "new_trust_protocol_added": False,
            "execute_available_capabilities_instead_of_promoting_probes": True,
            "external_authority_may_not_be_generated_by_executor": True,
        },
        "portable_execution": {
            "steps": list(PORTABLE_STEP_NAMES),
            "portable_result_is_production_gate_evidence": False,
            "source_git_identities_verified": True,
            "guix_center_portable_matrix_executes": True,
            "native_probe_built_twice_and_compared": True,
            "bounded_process_groups_and_outputs": True,
            "shell_execution_allowed": False,
            "ambient_user_site_allowed": False,
        },
        "real_gate_execution": {
            "gate_order": [spec.to_dict() for spec in phase38.GATE_SPECS],
            "gate1_requires_phase44_final_receipt": True,
            "gate1_requires_nonfixture_external_authority": True,
            "downstream_gate_requires_predecessor_receipts": True,
            "guix_store_object_measurement_required": True,
            "descriptor_bound_artifact_measurement_required": True,
            "real_qt_execution_required": True,
            "real_kvm_required": True,
            "real_af_vsock_required": True,
            "two_reproducible_iso_builds_required": True,
        },
        "truth_boundary": {
            "portable_matrix_is_real_guix": False,
            "headless_model_is_qt_execution": False,
            "native_probe_is_compiled_rust_runtime": False,
            "capability_probe_is_gate_execution": False,
            "tcg_is_kvm": False,
            "af_unix_is_af_vsock": False,
            "vm_plan_is_running_vm": False,
            "archive_is_bootable_iso": False,
        },
        "blockers": list(PHASE45_BLOCKERS),
        "production_gate_count": len(PRODUCTION_GATE_NAMES),
        "production_gates_approved": 0,
        "production_dispatch_allowed": False,
        "iso_release_allowed": False,
        "iso_bytes_present": False,
    }


def phase45_contract_digest() -> str:
    return _digest(CONTRACT_DOMAIN, _unsigned_phase45_contract())


def phase45_contract() -> dict[str, Any]:
    unsigned = _unsigned_phase45_contract()
    return {**unsigned, "contract_digest": _digest(CONTRACT_DOMAIN, unsigned)}


def parse_phase45_contract(value: Mapping[str, Any]) -> dict[str, Any]:
    candidate = json.loads(canonical_json_bytes(value))
    if candidate != phase45_contract():
        raise PolicyError("Phase 45 execution contract differs from the closed contract")
    return candidate


def execution_report_schema() -> dict[str, Any]:
    sha = {"type": "string", "pattern": "^[0-9a-f]{64}$"}
    step = {
        "type": "object",
        "additionalProperties": False,
        "required": [
            "name", "classification", "returncode", "duration_ns", "timed_out",
            "output_limited", "stdout", "stderr", "command", "step_digest",
        ],
        "properties": {
            "name": {"type": "string", "minLength": 1, "maxLength": 128},
            "classification": {"enum": ["executed-pass", "executed-fail", "blocked"]},
            "returncode": {"type": ["integer", "null"]},
            "duration_ns": {"type": "integer", "minimum": 0},
            "timed_out": {"type": "boolean"},
            "output_limited": {"type": "boolean"},
            "stdout": {"type": "object", "additionalProperties": False,
                       "required": ["path", "size", "sha256"],
                       "properties": {"path": {"type": "string"}, "size": {"type": "integer", "minimum": 0}, "sha256": sha}},
            "stderr": {"type": "object", "additionalProperties": False,
                       "required": ["path", "size", "sha256"],
                       "properties": {"path": {"type": "string"}, "size": {"type": "integer", "minimum": 0}, "sha256": sha}},
            "command": {"type": "array", "items": {"type": "string"}, "minItems": 1},
            "step_digest": sha,
        },
    }
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://securityops.co/schemas/guix-center/phase45-execution-report.schema.json",
        "title": "Security Ops Phase 45 concrete execution report",
        "type": "object",
        "additionalProperties": False,
        "required": [
            "format", "status", "contract_digest", "created_unix", "completed_unix",
            "runtime_identity", "securityops_os_identity", "capability_attestation",
            "portable_steps", "portable_checks_passed", "production_gates",
            "blockers", "production_gates_approved", "production_dispatch_allowed",
            "iso_release_allowed", "iso_bytes_present", "report_digest",
        ],
        "properties": {
            "format": {"const": REPORT_FORMAT},
            "status": {"enum": [STATUS, BLOCKED_STATUS]},
            "contract_digest": sha,
            "created_unix": {"type": "integer", "minimum": 1},
            "completed_unix": {"type": "integer", "minimum": 1},
            "runtime_identity": {"type": "object"},
            "securityops_os_identity": {"type": "object"},
            "capability_attestation": {"type": "object"},
            "portable_steps": {"type": "array", "items": step, "minItems": len(PORTABLE_STEP_NAMES)},
            "portable_checks_passed": {"type": "boolean"},
            "production_gates": {"type": "array", "minItems": len(PRODUCTION_GATE_NAMES), "maxItems": len(PRODUCTION_GATE_NAMES)},
            "blockers": {"type": "array", "items": {"type": "string"}, "minItems": 1},
            "production_gates_approved": {"const": 0},
            "production_dispatch_allowed": {"const": False},
            "iso_release_allowed": {"const": False},
            "iso_bytes_present": {"const": False},
            "report_digest": sha,
        },
    }


def _bounded_environment(extra: Mapping[str, str] | None = None) -> dict[str, str]:
    environment = {
        "PATH": "/usr/bin:/bin",
        "HOME": "/nonexistent",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PYTHONNOUSERSITE": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONSAFEPATH": "1",
        "TERM": "dumb",
        "SOURCE_DATE_EPOCH": "0",
    }
    if extra:
        environment.update(extra)
    return environment


@dataclass(frozen=True)
class StepResult:
    document: dict[str, Any]


def _process_group_exists(pgid: int) -> bool:
    try:
        os.killpg(pgid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _wait_group_exit(process: subprocess.Popen[bytes], timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    while _process_group_exists(process.pid):
        process.poll()
        # Reap reparented orphan descendants (see process_groups) so a
        # lingering zombie cannot outlive the bounded grace period.
        process_groups.reap_exited_children()
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.01)
    process.poll()
    return True


def _terminate_group(process: subprocess.Popen[bytes]) -> None:
    """Unconditionally terminate, reap, and verify an isolated process group."""

    cleanup_error: BaseException | None = None
    try:
        if _process_group_exists(process.pid):
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            except PermissionError as exc:
                cleanup_error = PolicyError("cannot terminate Phase 45 process group")
                cleanup_error.__cause__ = exc
            if cleanup_error is None and not _wait_group_exit(
                process, _PROCESS_GROUP_TERM_GRACE
            ):
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                except PermissionError as exc:
                    cleanup_error = PolicyError("cannot kill Phase 45 process group")
                    cleanup_error.__cause__ = exc
                if cleanup_error is None and not _wait_group_exit(
                    process, _PROCESS_GROUP_KILL_GRACE
                ):
                    cleanup_error = PolicyError(
                        "Phase 45 process group did not terminate"
                    )
    finally:
        try:
            process.wait(timeout=_PROCESS_GROUP_KILL_GRACE)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            except PermissionError as exc:
                if cleanup_error is None:
                    cleanup_error = PolicyError("cannot kill Phase 45 process group")
                    cleanup_error.__cause__ = exc
            try:
                process.wait(timeout=_PROCESS_GROUP_KILL_GRACE)
            except subprocess.TimeoutExpired:
                if cleanup_error is None:
                    cleanup_error = PolicyError("Phase 45 process leader was not reaped")
    if _process_group_exists(process.pid) and cleanup_error is None:
        cleanup_error = PolicyError("Phase 45 process group survived cleanup")
    if process.poll() is None and cleanup_error is None:
        cleanup_error = PolicyError("Phase 45 process leader was not reaped")
    if cleanup_error is not None:
        raise cleanup_error


class _RunnerSignalGuard:
    """Deliver process-control signals only at cleanup-safe checkpoints."""

    def __init__(self) -> None:
        self._previous: dict[signal.Signals, Any] = {}
        self._pending_signal: int | None = None
        self._delivered = False
        self._spawn_in_flight = False

    def _handler(self, signum: int, _frame: Any) -> None:
        # Raising from a Python signal handler while Popen has created a child
        # but has not returned its object loses the only cleanup handle.  Record
        # the first signal and raise synchronously after Popen returns instead.
        if not self._delivered and self._pending_signal is None:
            self._pending_signal = signum

    def install(self) -> None:
        try:
            for signum in _RUNNER_SIGNALS:
                self._previous[signum] = signal.getsignal(signum)
                signal.signal(signum, self._handler)
        except ValueError:
            # signal.signal is restricted to the main thread.  No child exists
            # yet, and exception-safe cleanup still applies to threaded calls.
            for signum, handler in self._previous.items():
                try:
                    signal.signal(signum, handler)
                except ValueError:
                    pass
            self._previous.clear()
        except BaseException:
            self.restore()
            raise

    def begin_spawn(self) -> None:
        self._spawn_in_flight = True

    def finish_spawn(self) -> None:
        self._spawn_in_flight = False

    def raise_if_pending(self) -> None:
        if self._spawn_in_flight or self._delivered or self._pending_signal is None:
            return
        signum = self._pending_signal
        self._pending_signal = None
        self._delivered = True
        raise SystemExit(128 + signum)

    @property
    def pending_signal(self) -> int | None:
        return None if self._delivered else self._pending_signal

    def restore(self) -> None:
        previous = tuple(self._previous.items())
        self._previous.clear()
        for signum, handler in previous:
            signal.signal(signum, handler)


def _install_runner_signal_guard() -> _RunnerSignalGuard:
    guard = _RunnerSignalGuard()
    guard.install()
    return guard


def _write_all(descriptor: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise PolicyError("Phase 45 log write made no progress")
        view = view[written:]


def _run_command(
    *, name: str, command: Sequence[str], cwd: Path, output_root: Path,
    timeout_seconds: int = 120, environment: Mapping[str, str] | None = None,
) -> StepResult:
    if not command or not os.path.isabs(command[0]):
        raise PolicyError("Phase 45 commands require an absolute executable")
    if timeout_seconds < 1 or timeout_seconds > MAX_STEP_SECONDS:
        raise PolicyError("Phase 45 command timeout is outside the bounded range")
    cwd = cwd.resolve(strict=True)
    if not cwd.is_dir():
        raise PolicyError("Phase 45 command working directory is invalid")
    safe_name = "".join(character if character.isalnum() or character in "-_." else "_" for character in name)
    stdout_path = output_root / f"{safe_name}.stdout.log"
    stderr_path = output_root / f"{safe_name}.stderr.log"
    stdout_fd = os.open(stdout_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0), 0o600)
    try:
        stderr_fd = os.open(stderr_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0), 0o600)
    except BaseException as open_error:
        try:
            os.close(stdout_fd)
        except BaseException as close_error:
            add_note = getattr(open_error, "add_note", None)
            if add_note is not None:
                add_note(f"Phase 45 partial log cleanup failure: {close_error}")
        raise
    started = time.monotonic_ns()
    timed_out = False
    output_limited = False
    process_tree_leaked = False
    process: subprocess.Popen[bytes] | None = None
    selector: selectors.BaseSelector | None = None
    signal_guard: _RunnerSignalGuard | None = None
    returncode: int | None = None
    try:
        process_groups.become_child_subreaper()
        signal_guard = _install_runner_signal_guard()
        signal_guard.raise_if_pending()
        signal_guard.begin_spawn()
        try:
            process = subprocess.Popen(
                list(command), cwd=cwd, env=dict(environment or _bounded_environment()),
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                shell=False, close_fds=True, start_new_session=True,
            )
        finally:
            signal_guard.finish_spawn()
        signal_guard.raise_if_pending()
        assert process.stdout is not None and process.stderr is not None
        os.set_blocking(process.stdout.fileno(), False)
        os.set_blocking(process.stderr.fileno(), False)
        selector = selectors.DefaultSelector()
        selector.register(process.stdout, selectors.EVENT_READ, (stdout_fd, "stdout"))
        selector.register(process.stderr, selectors.EVENT_READ, (stderr_fd, "stderr"))
        total = 0
        deadline = time.monotonic() + timeout_seconds
        leader_exit_cleaned = False
        while selector.get_map():
            signal_guard.raise_if_pending()
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                timed_out = True
                break
            if process.poll() is not None and not leader_exit_cleaned:
                # poll() reaps the leader.  A remaining process group is an
                # unauthorized descendant, not a reason to block on inherited
                # stdout/stderr pipes.
                process_tree_leaked = _process_group_exists(process.pid)
                _terminate_group(process)
                leader_exit_cleaned = True
            events = selector.select(timeout=min(0.25, remaining))
            signal_guard.raise_if_pending()
            for key, _mask in events:
                target_fd, _stream_name = key.data
                try:
                    block = os.read(key.fileobj.fileno(), 64 * 1024)
                except BlockingIOError:
                    continue
                if not block:
                    selector.unregister(key.fileobj)
                    key.fileobj.close()
                    continue
                total += len(block)
                if total > MAX_STEP_OUTPUT:
                    output_limited = True
                    break
                _write_all(target_fd, block)
            if output_limited:
                break
        while process.poll() is None and not timed_out and not output_limited:
            signal_guard.raise_if_pending()
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                timed_out = True
                break
            try:
                process.wait(timeout=min(0.25, remaining))
            except subprocess.TimeoutExpired:
                continue
        returncode = process.returncode
        if returncode is not None and _process_group_exists(process.pid):
            process_tree_leaked = True
            _write_all(
                stderr_fd,
                b"PolicyError: process leader exited with live process-group descendants\n",
            )
        signal_guard.raise_if_pending()
    except OSError as exc:
        if signal_guard is not None:
            signal_guard.raise_if_pending()
        _write_all(stderr_fd, f"{type(exc).__name__}: {exc}\n".encode("utf-8", errors="replace"))
        returncode = None
    finally:
        active_error = sys.exc_info()[1]
        cleanup_errors: list[BaseException] = []
        try:
            if process is not None:
                _terminate_group(process)
                if returncode is None:
                    returncode = process.returncode
        except BaseException as exc:
            cleanup_errors.append(exc)
        if selector is not None:
            try:
                selector.close()
            except BaseException as exc:
                cleanup_errors.append(exc)
        if process is not None:
            for stream in (process.stdout, process.stderr):
                if stream is not None and not stream.closed:
                    try:
                        stream.close()
                    except BaseException as exc:
                        cleanup_errors.append(exc)
        for descriptor in (stdout_fd, stderr_fd):
            try:
                os.fsync(descriptor)
            except BaseException as exc:
                cleanup_errors.append(exc)
            try:
                os.close(descriptor)
            except BaseException as exc:
                cleanup_errors.append(exc)
        if signal_guard is not None:
            try:
                signal_guard.restore()
            except BaseException as exc:
                cleanup_errors.append(exc)
            pending_signal = signal_guard.pending_signal
        else:
            pending_signal = None
        if pending_signal is not None:
            pending_error = SystemExit(128 + pending_signal)
            if active_error is None and not cleanup_errors:
                raise pending_error
            target_error = active_error or cleanup_errors[0]
            add_note = getattr(target_error, "add_note", None)
            if add_note is not None:
                add_note(f"Phase 45 cleanup observed signal {pending_signal}")
        if cleanup_errors:
            if active_error is None:
                primary = cleanup_errors[0]
                add_note = getattr(primary, "add_note", None)
                if add_note is not None:
                    for extra in cleanup_errors[1:]:
                        add_note(f"Additional Phase 45 cleanup failure: {extra}")
                raise primary
            add_note = getattr(active_error, "add_note", None)
            if add_note is not None:
                for error in cleanup_errors:
                    add_note(f"Phase 45 cleanup failure: {error}")
    duration = time.monotonic_ns() - started
    stdout_measure = _sha256_path(stdout_path, maximum=MAX_STEP_OUTPUT)
    stderr_measure = _sha256_path(stderr_path, maximum=MAX_STEP_OUTPUT)
    classification = (
        "executed-pass"
        if returncode == 0
        and not timed_out
        and not output_limited
        and not process_tree_leaked
        else "executed-fail"
    )
    unsigned = {
        "name": name,
        "classification": classification,
        "returncode": returncode,
        "duration_ns": duration,
        "timed_out": timed_out,
        "output_limited": output_limited,
        "stdout": {"path": stdout_path.name, "size": stdout_measure["size"], "sha256": stdout_measure["sha256"]},
        "stderr": {"path": stderr_path.name, "size": stderr_measure["size"], "sha256": stderr_measure["sha256"]},
        "command": list(command),
    }
    return StepResult({**unsigned, "step_digest": _digest(STEP_DOMAIN, unsigned)})


def _blocked_step(name: str, reason: str, output_root: Path) -> StepResult:
    stdout_path = output_root / f"{name}.stdout.log"
    stderr_path = output_root / f"{name}.stderr.log"
    stdout_path.write_bytes(b"")
    stderr_path.write_text(reason + "\n", encoding="utf-8")
    os.chmod(stdout_path, 0o600); os.chmod(stderr_path, 0o600)
    stdout_measure = _sha256_path(stdout_path)
    stderr_measure = _sha256_path(stderr_path)
    unsigned = {
        "name": name, "classification": "blocked", "returncode": None,
        "duration_ns": 0, "timed_out": False, "output_limited": False,
        "stdout": {"path": stdout_path.name, "size": stdout_measure["size"], "sha256": stdout_measure["sha256"]},
        "stderr": {"path": stderr_path.name, "size": stderr_measure["size"], "sha256": stderr_measure["sha256"]},
        "command": ["/usr/bin/false", reason],
    }
    return StepResult({**unsigned, "step_digest": _digest(STEP_DOMAIN, unsigned)})


def _git_identity(root: Path, expected_commit: str, expected_tree: str) -> dict[str, Any]:
    git = shutil.which("git")
    if git is None:
        raise PolicyError("git is unavailable for Phase 45 source identity verification")
    root = root.resolve(strict=True)
    def run(*arguments: str) -> str:
        result = subprocess.run(
            [git, "-C", os.fspath(root), *arguments], stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False,
            timeout=30, env=_bounded_environment(), shell=False,
        )
        if result.returncode != 0:
            raise PolicyError(f"git identity command failed: {' '.join(arguments)}")
        return result.stdout.strip()
    base_tree = run("rev-parse", f"{expected_commit}^{{tree}}")
    if base_tree != expected_tree:
        raise PolicyError("Phase 45 sealed Phase 44 base tree is unavailable or changed")
    ancestor = subprocess.run(
        [git, "-C", os.fspath(root), "merge-base", "--is-ancestor", expected_commit, "HEAD"],
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        check=False, timeout=30, env=_bounded_environment(), shell=False,
    )
    if ancestor.returncode != 0:
        raise PolicyError("Phase 45 source does not descend from the sealed Phase 44 base")
    commit = run("rev-parse", "HEAD")
    tree = run("rev-parse", "HEAD^{tree}")
    status = run("status", "--porcelain=v1", "--untracked-files=all")
    return {
        "base_commit": expected_commit, "base_tree": expected_tree,
        "commit": commit, "tree": tree, "clean": status == "",
        "status_sha256": hashlib.sha256(status.encode()).hexdigest(),
    }


def _write_native_probe_source(path: Path) -> None:
    path.write_text(
        "#include <stdio.h>\n"
        "#include <string.h>\n"
        "int main(void) {\n"
        "  static const char marker[] = \"securityops-phase45-native-probe/1\";\n"
        "  if (strlen(marker) != 34u) return 70;\n"
        "  return puts(marker) < 0 ? 71 : 0;\n"
        "}\n",
        encoding="utf-8",
    )
    path.chmod(0o600)


def _measure_native_tool(name: str) -> dict[str, Any]:
    if name not in _NATIVE_TOOL_NAMES:
        raise PolicyError(f"unexpected Phase 45 native tool: {name}")
    candidate = shutil.which(name, path=_NATIVE_DISCOVERY_PATH)
    if candidate is None:
        raise PolicyError(f"native tool unavailable: {name}")
    try:
        requested = Path(candidate).absolute()
        resolved = requested.resolve(strict=True)
        resolved.relative_to("/gnu/store")
    except (OSError, ValueError) as exc:
        raise PolicyError(f"native tool is not an immutable Guix Store object: {name}") from exc
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(resolved, flags)
    try:
        before = os.fstat(descriptor)
        mode = stat.S_IMODE(before.st_mode)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != 0
            or before.st_gid != 0
            or before.st_nlink < 1
            or not 1 <= before.st_size <= MAX_FILE_BYTES
            or mode & 0o7022
            or not mode & 0o111
        ):
            raise PolicyError(f"native tool has unsafe identity: {name}")
        digest = hashlib.sha256()
        remaining = before.st_size
        while remaining:
            block = os.read(descriptor, min(1024 * 1024, remaining))
            if not block:
                raise PolicyError(f"native tool was truncated while measuring: {name}")
            digest.update(block)
            remaining -= len(block)
        if os.read(descriptor, 1):
            raise PolicyError(f"native tool grew while measuring: {name}")
        after = os.fstat(descriptor)
        identity = lambda item: (
            item.st_dev, item.st_ino, item.st_mode, item.st_uid, item.st_gid,
            item.st_nlink, item.st_size, item.st_mtime_ns, item.st_ctime_ns,
        )
        if identity(before) != identity(after):
            raise PolicyError(f"native tool changed while measuring: {name}")
    finally:
        os.close(descriptor)
    return {
        "candidate": os.fspath(requested),
        "resolved": os.fspath(resolved),
        "sha256": digest.hexdigest(),
        "size": before.st_size,
        "mode": mode,
        "uid": before.st_uid,
        "gid": before.st_gid,
        "device": before.st_dev,
        "inode": before.st_ino,
        "link_count": before.st_nlink,
        "in_guix_store": True,
    }


def _native_runpath_evidence(
    text: str,
) -> tuple[tuple[str, ...], list[str], bool, int]:
    runpath_matches = re.findall(r"Library runpath: \[([^\]]*)\]", text)
    runpath_entries = (
        tuple(runpath_matches[0].split(":")) if len(runpath_matches) == 1 else ()
    )
    resolved_runpath_entries: list[str] = []
    immutable_store_runpath = len(runpath_matches) == 1 and bool(runpath_entries)
    for entry in runpath_entries:
        path = Path(entry)
        parts = path.parts
        if (
            len(parts) < 5
            or parts[:3] != ("/", "gnu", "store")
            or "//" in entry
            or "/./" in entry
            or "$" in entry
            or "\\" in entry
        ):
            immutable_store_runpath = False
            break
        store_item = Path(*parts[:4])
        try:
            canonical = path.resolve(strict=True)
            canonical.relative_to(store_item)
        except (OSError, ValueError):
            immutable_store_runpath = False
            break
        resolved_runpath_entries.append(os.fspath(canonical))
    return (
        runpath_entries,
        resolved_runpath_entries,
        immutable_store_runpath,
        len(runpath_matches),
    )


def _native_probe(output_root: Path) -> StepResult:
    try:
        tools = {name: _measure_native_tool(name) for name in _NATIVE_TOOL_NAMES}
    except (OSError, PolicyError) as exc:
        return _blocked_step("native-reproducibility-probe", str(exc), output_root)
    helper_directories = tuple(dict.fromkeys((
        os.fspath(Path(tools["ld"]["resolved"]).parent),
        os.fspath(Path(tools["as"]["resolved"]).parent),
        os.fspath(Path(tools["gcc"]["resolved"]).parent),
    )))
    helper_path = os.pathsep.join(helper_directories)
    for helper in ("ld", "as"):
        located = shutil.which(helper, path=helper_path)
        if located is None or Path(located).resolve(strict=True) != Path(tools[helper]["resolved"]):
            return _blocked_step(
                "native-reproducibility-probe",
                f"closed native helper path does not resolve measured {helper}",
                output_root,
            )
    native_environment = _bounded_environment({"PATH": helper_path})
    gcc = os.fspath(tools["gcc"]["resolved"])
    readelf = os.fspath(tools["readelf"]["resolved"])
    native_root = output_root / "native"
    native_root.mkdir(mode=0o700)
    binaries: list[Path] = []
    command_records: list[dict[str, Any]] = []
    started = time.monotonic_ns()
    for label in ("a", "b"):
        build = native_root / label
        build.mkdir(mode=0o700)
        source = build / "probe.c"
        binary = build / "securityops-phase45-native-probe"
        _write_native_probe_source(source)
        command = [
            os.path.realpath(gcc), "-std=c17", "-O2", "-fPIE", "-pie",
            "-fstack-protector-strong", "-D_FORTIFY_SOURCE=3",
            "-Wformat", "-Werror=format-security",
            f"-ffile-prefix-map={build}=/usr/src/securityops-phase45",
            f"-fdebug-prefix-map={build}=/usr/src/securityops-phase45",
            "-Wl,-z,relro,-z,now", "-Wl,--build-id=sha1",
            os.fspath(source), "-o", os.fspath(binary),
        ]
        result = _run_command(
            name=f"native-build-{label}", command=command, cwd=build,
            output_root=output_root, timeout_seconds=120,
            environment=native_environment,
        ).document
        command_records.append({"label": label, **result})
        if result["classification"] != "executed-pass":
            reason = (output_root / result["stderr"]["path"]).read_text(
                encoding="utf-8", errors="replace"
            )[:4096]
            return _blocked_step("native-reproducibility-probe", f"native compile failed: {reason}", output_root)
        binary.chmod(0o500)
        binaries.append(binary)
    first = _sha256_path(binaries[0]); second = _sha256_path(binaries[1])
    if first["sha256"] != second["sha256"] or first["size"] != second["size"]:
        return _blocked_step("native-reproducibility-probe", "independent native builds differ", output_root)
    execution = _run_command(
        name="native-execute", command=[os.fspath(binaries[0])], cwd=native_root,
        output_root=output_root, timeout_seconds=10,
        environment=_bounded_environment({"PATH": ""}),
    ).document
    metadata = _run_command(
        name="native-readelf",
        command=[readelf, "-h", "-l", "-d", "-n", os.fspath(binaries[0])],
        cwd=native_root, output_root=output_root, timeout_seconds=30,
        environment=_bounded_environment({"PATH": ""}),
    ).document
    execution_stdout = (output_root / execution["stdout"]["path"]).read_bytes()
    execution_stderr = (output_root / execution["stderr"]["path"]).read_bytes()
    metadata_stdout = (output_root / metadata["stdout"]["path"]).read_bytes()
    metadata_stderr = (output_root / metadata["stderr"]["path"]).read_bytes()
    text = metadata_stdout.decode("utf-8", errors="replace")
    (
        runpath_entries,
        resolved_runpath_entries,
        immutable_store_runpath,
        runpath_record_count,
    ) = _native_runpath_evidence(text)
    hardening = {
        "pie": "Type:                              DYN" in text or "Type:                              DYN (Position-Independent Executable file)" in text,
        "relro": "GNU_RELRO" in text,
        "bind_now": "BIND_NOW" in text or "FLAGS" in text and "NOW" in text,
        "non_executable_stack": "GNU_STACK" in text and "RWE" not in "\n".join(line for line in text.splitlines() if "GNU_STACK" in line),
        "build_id": "Build ID:" in text,
        "no_rpath": "RPATH" not in text,
        "no_runpath": "RUNPATH" not in text,
        "runpath_immutable_guix_store_only": immutable_store_runpath,
    }
    passed = (
        execution["classification"] == "executed-pass"
        and execution_stdout == b"securityops-phase45-native-probe/1\n"
        and metadata["classification"] == "executed-pass"
        and all(hardening[key] for key in (
            "pie", "relro", "bind_now", "non_executable_stack", "build_id", "no_rpath",
        ))
        and (hardening["no_runpath"] or hardening["runpath_immutable_guix_store_only"])
    )
    evidence = {
        "format": "securityops-phase45-native-probe-evidence/1",
        "independent_builds": 2,
        "byte_identical": True,
        "binary": first,
        "commands": command_records,
        "execution_returncode": execution["returncode"],
        "execution_stdout_sha256": hashlib.sha256(execution_stdout).hexdigest(),
        "readelf_sha256": hashlib.sha256(metadata_stdout).hexdigest(),
        "hardening": hardening,
        "runpath_entries": list(runpath_entries),
        "runpath_record_count": runpath_record_count,
        "resolved_runpath_entries": resolved_runpath_entries,
        "ambient_path_used": False,
        "helper_search_path": list(helper_directories),
        "tool_identities": tools,
        "toolchain_authenticated": False,
        "scope": "portable-native-build-runner-only",
        "is_rust_runtime_evidence": False,
        "is_linux_7_2_evidence": False,
        "production_gate_approved": False,
    }
    _atomic_json(output_root / "native-probe-evidence.json", evidence)
    stdout_path = output_root / "native-reproducibility-probe.stdout.log"
    stderr_path = output_root / "native-reproducibility-probe.stderr.log"
    stdout_path.write_bytes(canonical_json_bytes(evidence) + b"\n")
    stderr_path.write_bytes(metadata_stderr + execution_stderr)
    os.chmod(stdout_path, 0o600); os.chmod(stderr_path, 0o600)
    stdout_measure = _sha256_path(stdout_path); stderr_measure = _sha256_path(stderr_path)
    unsigned = {
        "name": "native-reproducibility-probe",
        "classification": "executed-pass" if passed else "executed-fail",
        "returncode": 0 if passed else 1,
        "duration_ns": time.monotonic_ns() - started,
        "timed_out": False, "output_limited": False,
        "stdout": {"path": stdout_path.name, "size": stdout_measure["size"], "sha256": stdout_measure["sha256"]},
        "stderr": {"path": stderr_path.name, "size": stderr_measure["size"], "sha256": stderr_measure["sha256"]},
        "command": [gcc, "<two-independent-hardened-builds>"],
    }
    return StepResult({**unsigned, "step_digest": _digest(STEP_DOMAIN, unsigned)})


def _production_gate_observations(capabilities: Mapping[str, Any]) -> list[dict[str, Any]]:
    derived = capabilities["derived_capabilities"]
    results: list[dict[str, Any]] = []
    for index, spec in enumerate(phase38.GATE_SPECS, 1):
        state = "blocked" if index == 1 else "skipped-prerequisite"
        observations: list[str] = []
        if index == 1:
            observations.extend([
                "real-phase44-final-gate1-receipt-not-supplied",
                "authenticated-35-artifact-closure-not-supplied",
                "guix-store-candidate-present"
                if derived["store_resident_guix_candidate"]
                else "guix-store-candidate-absent",
                "guix-store-residency-is-not-authentication",
                "pyside6-runtime-present" if derived["qt_runtime"] else "pyside6-runtime-absent",
            ])
        else:
            observations.append("ordered-predecessor-receipt-not-approved")
        results.append({
            "index": index,
            "name": spec.name,
            "state": state,
            "prerequisites": list(spec.prerequisites),
            "observations": observations,
            "production_gate_approved": False,
        })
    return results


def execute_phase45(
    *, runtime_root: Path, securityops_os_root: Path, output_root: Path,
    matrix_rows: int = 50_000, soak_seconds: float = 5.0,
) -> dict[str, Any]:
    if type(matrix_rows) is not int or not 1_000 <= matrix_rows <= 200_000:
        raise PolicyError("Phase 45 matrix row count is outside the bounded range")
    if not isinstance(soak_seconds, (int, float)) or not 1.0 <= float(soak_seconds) <= 3600.0:
        raise PolicyError("Phase 45 soak duration is outside the bounded range")
    runtime_root = runtime_root.resolve(strict=True)
    securityops_os_root = securityops_os_root.resolve(strict=True)
    output_root = _secure_directory(output_root, create=True)
    created_unix = int(time.time())

    capabilities = phase38.capability_attestation(include_versions=True)
    phase38.parse_capability_attestation(capabilities, verify_current_environment=True)
    _atomic_json(output_root / "capability-attestation.json", capabilities)

    runtime_identity = _git_identity(
        runtime_root, PHASE44_IDENTITIES["runtime_commit"], PHASE44_IDENTITIES["runtime_tree"],
    )
    os_identity = _git_identity(
        securityops_os_root,
        PHASE44_IDENTITIES["securityops_os_commit"], PHASE44_IDENTITIES["securityops_os_tree"],
    )
    identity_evidence = {"runtime": runtime_identity, "securityops_os": os_identity}
    _atomic_json(output_root / "source-identities.json", identity_evidence)
    identity_stdout = output_root / "source-identities.stdout.log"
    identity_stderr = output_root / "source-identities.stderr.log"
    identity_stdout.write_bytes(canonical_json_bytes(identity_evidence) + b"\n")
    identity_stderr.write_bytes(b"")
    os.chmod(identity_stdout, 0o600); os.chmod(identity_stderr, 0o600)
    identity_out_measure = _sha256_path(identity_stdout); identity_err_measure = _sha256_path(identity_stderr)
    identity_unsigned = {
        "name": "source-identities", "classification": "executed-pass",
        "returncode": 0, "duration_ns": 0, "timed_out": False, "output_limited": False,
        "stdout": {"path": identity_stdout.name, "size": identity_out_measure["size"], "sha256": identity_out_measure["sha256"]},
        "stderr": {"path": identity_stderr.name, "size": identity_err_measure["size"], "sha256": identity_err_measure["sha256"]},
        "command": ["/usr/bin/git", "rev-parse", "<sealed-phase44-identities>"],
    }
    steps: list[dict[str, Any]] = [{**identity_unsigned, "step_digest": _digest(STEP_DOMAIN, identity_unsigned)}]

    python = Path(os.sys.executable).resolve(strict=True)
    matrix_script = securityops_os_root / "securityops/guix-center/phase37_matrix.py"
    matrix_output = output_root / "guix-center-portable-matrix.json"
    if matrix_script.is_file():
        matrix_step = _run_command(
            name="guix-center-portable-matrix",
            command=[
                os.fspath(python), os.fspath(matrix_script),
                "--os-root", os.fspath(securityops_os_root),
                "--output", os.fspath(matrix_output),
                "--rows", str(matrix_rows),
                "--soak-seconds", str(float(soak_seconds)),
            ],
            cwd=securityops_os_root, output_root=output_root,
            timeout_seconds=min(MAX_STEP_SECONDS, max(120, int(soak_seconds) + 180)),
            environment=_bounded_environment({"HOME": os.fspath(output_root / "matrix-home")}),
        ).document
    else:
        matrix_step = _blocked_step("guix-center-portable-matrix", "Phase 37 matrix source is absent", output_root).document
    steps.append(matrix_step)

    steps.append(_native_probe(output_root).document)

    pycache = output_root / "pycache"
    pycache.mkdir(mode=0o700)
    compile_step = _run_command(
        name="python-bytecode-validation",
        command=[
            os.fspath(python), "-m", "compileall", "-q", "-f",
            os.fspath(securityops_os_root / "securityops/guix-center"),
        ],
        cwd=runtime_root, output_root=output_root, timeout_seconds=180,
        environment=_bounded_environment({"PYTHONPYCACHEPREFIX": os.fspath(pycache)}),
    ).document
    steps.append(compile_step)

    git = Path(shutil.which("git") or "/usr/bin/git").resolve(strict=True)
    diff_runtime = _run_command(
        name="git-diff-check-runtime",
        command=[os.fspath(git), "-C", os.fspath(runtime_root), "diff", "--check"],
        cwd=runtime_root, output_root=output_root, timeout_seconds=60,
    ).document
    diff_os = _run_command(
        name="git-diff-check-os",
        command=[os.fspath(git), "-C", os.fspath(securityops_os_root), "diff", "--check"],
        cwd=securityops_os_root, output_root=output_root, timeout_seconds=60,
    ).document
    combined_ok = diff_runtime["classification"] == "executed-pass" and diff_os["classification"] == "executed-pass"
    combined_payload = canonical_json_bytes({"runtime": diff_runtime, "securityops_os": diff_os}) + b"\n"
    combined_stdout = output_root / "git-diff-check.stdout.log"
    combined_stderr = output_root / "git-diff-check.stderr.log"
    combined_stdout.write_bytes(combined_payload); combined_stderr.write_bytes(b"")
    os.chmod(combined_stdout, 0o600); os.chmod(combined_stderr, 0o600)
    combined_out = _sha256_path(combined_stdout); combined_err = _sha256_path(combined_stderr)
    combined_unsigned = {
        "name": "git-diff-check", "classification": "executed-pass" if combined_ok else "executed-fail",
        "returncode": 0 if combined_ok else 1,
        "duration_ns": diff_runtime["duration_ns"] + diff_os["duration_ns"],
        "timed_out": diff_runtime["timed_out"] or diff_os["timed_out"],
        "output_limited": diff_runtime["output_limited"] or diff_os["output_limited"],
        "stdout": {"path": combined_stdout.name, "size": combined_out["size"], "sha256": combined_out["sha256"]},
        "stderr": {"path": combined_stderr.name, "size": combined_err["size"], "sha256": combined_err["sha256"]},
        "command": [os.fspath(git), "diff", "--check", "<both-trees>"],
    }
    steps.append({**combined_unsigned, "step_digest": _digest(STEP_DOMAIN, combined_unsigned)})

    portable_checks_passed = all(step["classification"] == "executed-pass" for step in steps)
    gates = _production_gate_observations(capabilities)
    completed_unix = max(created_unix, int(time.time()))
    unsigned_report: dict[str, Any] = {
        "format": REPORT_FORMAT,
        "status": STATUS if portable_checks_passed else BLOCKED_STATUS,
        "contract_digest": phase45_contract_digest(),
        "created_unix": created_unix,
        "completed_unix": completed_unix,
        "runtime_identity": runtime_identity,
        "securityops_os_identity": os_identity,
        "capability_attestation": capabilities,
        "portable_steps": steps,
        "portable_checks_passed": portable_checks_passed,
        "production_gates": gates,
        "blockers": list(PHASE45_BLOCKERS),
        "production_gates_approved": 0,
        "production_dispatch_allowed": False,
        "iso_release_allowed": False,
        "iso_bytes_present": False,
    }
    report = {**unsigned_report, "report_digest": _digest(REPORT_DOMAIN, unsigned_report)}
    _atomic_json(output_root / "PHASE45_EXECUTION_REPORT.json", report)
    return report


def parse_execution_report(value: Mapping[str, Any]) -> dict[str, Any]:
    fields = {
        "format", "status", "contract_digest", "created_unix", "completed_unix",
        "runtime_identity", "securityops_os_identity", "capability_attestation",
        "portable_steps", "portable_checks_passed", "production_gates", "blockers",
        "production_gates_approved", "production_dispatch_allowed", "iso_release_allowed",
        "iso_bytes_present", "report_digest",
    }
    if type(value) is not dict or set(value) != fields:
        raise PolicyError("Phase 45 execution report fields are not closed")
    candidate = json.loads(canonical_json_bytes(value))
    if candidate["format"] != REPORT_FORMAT:
        raise PolicyError("Phase 45 execution report format is invalid")
    if candidate["contract_digest"] != phase45_contract_digest():
        raise PolicyError("Phase 45 execution report contract digest is invalid")
    if candidate["status"] not in (STATUS, BLOCKED_STATUS):
        raise PolicyError("Phase 45 execution report status is invalid")
    if type(candidate["created_unix"]) is not int or candidate["created_unix"] < 1:
        raise PolicyError("Phase 45 execution report creation time is invalid")
    if type(candidate["completed_unix"]) is not int or candidate["completed_unix"] < candidate["created_unix"]:
        raise PolicyError("Phase 45 execution report completion time is invalid")
    phase38.parse_capability_attestation(candidate["capability_attestation"])
    identity_fields = {
        "base_commit", "base_tree", "commit", "tree", "clean", "status_sha256",
    }
    for name, identity, expected_commit, expected_tree in (
        ("runtime", candidate["runtime_identity"], PHASE44_IDENTITIES["runtime_commit"], PHASE44_IDENTITIES["runtime_tree"]),
        ("securityops-os", candidate["securityops_os_identity"], PHASE44_IDENTITIES["securityops_os_commit"], PHASE44_IDENTITIES["securityops_os_tree"]),
    ):
        if type(identity) is not dict or set(identity) != identity_fields:
            raise PolicyError(f"Phase 45 {name} identity fields are not closed")
        if identity["base_commit"] != expected_commit or identity["base_tree"] != expected_tree:
            raise PolicyError(f"Phase 45 {name} sealed base identity is invalid")
        for field in ("base_commit", "base_tree", "commit", "tree"):
            value = identity[field]
            if not isinstance(value, str) or len(value) != 40 or any(ch not in "0123456789abcdef" for ch in value):
                raise PolicyError(f"Phase 45 {name} Git identity is invalid")
        if type(identity["clean"]) is not bool:
            raise PolicyError(f"Phase 45 {name} cleanliness flag is invalid")
        if not isinstance(identity["status_sha256"], str) or len(identity["status_sha256"]) != 64:
            raise PolicyError(f"Phase 45 {name} status digest is invalid")

    if [step.get("name") for step in candidate["portable_steps"]] != list(PORTABLE_STEP_NAMES):
        raise PolicyError("Phase 45 portable execution step order is invalid")
    step_fields = {
        "name", "classification", "returncode", "duration_ns", "timed_out",
        "output_limited", "stdout", "stderr", "command", "step_digest",
    }
    for step in candidate["portable_steps"]:
        if type(step) is not dict or set(step) != step_fields:
            raise PolicyError("Phase 45 execution step fields are not closed")
        if step["classification"] not in ("executed-pass", "executed-fail", "blocked"):
            raise PolicyError("Phase 45 execution step classification is invalid")
        if not isinstance(step["command"], list) or not step["command"] or not all(isinstance(item, str) for item in step["command"]):
            raise PolicyError("Phase 45 execution step command is invalid")
        if not os.path.isabs(step["command"][0]):
            raise PolicyError("Phase 45 execution step command is not absolute")
        for stream_name in ("stdout", "stderr"):
            stream = step[stream_name]
            if type(stream) is not dict or set(stream) != {"path", "size", "sha256"}:
                raise PolicyError("Phase 45 execution stream fields are not closed")
            if not isinstance(stream["path"], str) or not stream["path"] or "/" in stream["path"] or "\\" in stream["path"]:
                raise PolicyError("Phase 45 execution stream path is invalid")
            if type(stream["size"]) is not int or stream["size"] < 0 or stream["size"] > MAX_STEP_OUTPUT:
                raise PolicyError("Phase 45 execution stream size is invalid")
            if not isinstance(stream["sha256"], str) or len(stream["sha256"]) != 64:
                raise PolicyError("Phase 45 execution stream digest is invalid")
        supplied = step.get("step_digest")
        unsigned = dict(step); unsigned.pop("step_digest", None)
        if not isinstance(supplied, str) or supplied != _digest(STEP_DOMAIN, unsigned):
            raise PolicyError("Phase 45 execution step digest is invalid")
    derived_portable = all(step["classification"] == "executed-pass" for step in candidate["portable_steps"])
    if candidate["portable_checks_passed"] is not derived_portable:
        raise PolicyError("Phase 45 portable execution summary is inconsistent")
    expected_status = STATUS if derived_portable else BLOCKED_STATUS
    if candidate["status"] != expected_status:
        raise PolicyError("Phase 45 execution report status does not match its steps")

    gate_fields = {
        "index", "name", "state", "prerequisites", "observations",
        "production_gate_approved",
    }
    if [gate.get("name") for gate in candidate["production_gates"]] != list(PRODUCTION_GATE_NAMES):
        raise PolicyError("Phase 45 production gate order is invalid")
    for index, (gate, spec) in enumerate(zip(candidate["production_gates"], phase38.GATE_SPECS, strict=True), 1):
        if type(gate) is not dict or set(gate) != gate_fields:
            raise PolicyError("Phase 45 production gate fields are not closed")
        if gate["index"] != index or gate["prerequisites"] != list(spec.prerequisites):
            raise PolicyError("Phase 45 production gate identity or prerequisites drifted")
        expected_state = "blocked" if index == 1 else "skipped-prerequisite"
        if gate["state"] != expected_state:
            raise PolicyError("Phase 45 local gate state attempted prerequisite bypass")
        if not isinstance(gate["observations"], list) or not gate["observations"] or not all(isinstance(item, str) and item for item in gate["observations"]):
            raise PolicyError("Phase 45 gate observations are invalid")
        if gate["production_gate_approved"] is not False:
            raise PolicyError("Phase 45 local report attempted production gate promotion")
    if candidate["blockers"] != list(PHASE45_BLOCKERS):
        raise PolicyError("Phase 45 blocker inventory is invalid")
    if candidate["production_gates_approved"] != 0 or candidate["production_dispatch_allowed"] or candidate["iso_release_allowed"] or candidate["iso_bytes_present"]:
        raise PolicyError("Phase 45 local report attempted release promotion")
    supplied_report = candidate.pop("report_digest")
    if not isinstance(supplied_report, str) or supplied_report != _digest(REPORT_DOMAIN, candidate):
        raise PolicyError("Phase 45 execution report digest is invalid")
    candidate["report_digest"] = supplied_report
    return candidate


def blocked_observation() -> dict[str, Any]:
    capabilities = phase38.capability_attestation(include_versions=False)
    return {
        "format": "securityops-phase45-blocked-observation/1",
        "status": BLOCKED_STATUS,
        "contract_digest": phase45_contract_digest(),
        "capability_attestation_digest": capabilities["attestation_digest"],
        "blockers": list(PHASE45_BLOCKERS),
        "production_gates_approved": 0,
        "production_dispatch_allowed": False,
        "iso_release_allowed": False,
        "iso_bytes_present": False,
    }


def phase45_selftest() -> dict[str, Any]:
    contract = phase45_contract()
    parse_phase45_contract(contract)
    mutations = (
        lambda value: value["mission"].__setitem__("new_trust_protocol_added", True),
        lambda value: value["mission"].__setitem__("external_authority_may_not_be_generated_by_executor", False),
        lambda value: value["portable_execution"].__setitem__("shell_execution_allowed", True),
        lambda value: value["portable_execution"].__setitem__("portable_result_is_production_gate_evidence", True),
        lambda value: value["real_gate_execution"].__setitem__("real_kvm_required", False),
        lambda value: value["real_gate_execution"].__setitem__("real_af_vsock_required", False),
        lambda value: value["truth_boundary"].__setitem__("headless_model_is_qt_execution", True),
        lambda value: value["truth_boundary"].__setitem__("tcg_is_kvm", True),
        lambda value: value["truth_boundary"].__setitem__("archive_is_bootable_iso", True),
        lambda value: value["real_gate_execution"]["gate_order"].pop(),
        lambda value: value["blockers"].pop(),
        lambda value: value.__setitem__("production_gates_approved", 1),
        lambda value: value.__setitem__("production_dispatch_allowed", True),
        lambda value: value.__setitem__("iso_release_allowed", True),
        lambda value: value.__setitem__("iso_bytes_present", True),
    )
    rejected = 0
    for mutate in mutations:
        candidate = json.loads(json.dumps(contract))
        mutate(candidate)
        try:
            parse_phase45_contract(candidate)
        except PolicyError:
            rejected += 1
    if rejected != len(mutations):
        raise PolicyError("Phase 45 contract mutation self-test did not reject every downgrade")
    return {
        "format": "securityops-phase45-selftest/1",
        "status": STATUS,
        "contract_digest": phase45_contract_digest(),
        "negative_cases": len(mutations),
        "negative_cases_rejected": rejected,
        "production_gates_approved": 0,
        "production_dispatch_allowed": False,
        "iso_release_allowed": False,
        "iso_bytes_present": False,
    }
