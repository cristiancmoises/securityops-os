# CodeMark v1 project=4c63e0fe-589c-4944-8449-97e211a38b72 file=8c6464ea1380579a9809e9708ce2cf4b owner="Cristian Cezar Mois\u00e9s"
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-SecurityOps-Commercial
"""Phase 37 execution, recovery, accessibility, and capability boundary.

This module is intentionally portable. It provides fail-closed transaction
lifecycle state, descriptor-bound execution integration, accessibility
contracts, and exact capability reporting without promoting portable tests to
Guix, Qt, KVM, AF_VSOCK, boot, or ISO evidence.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tempfile
import time
from typing import Any, Final, Mapping

try:  # In-tree sibling module.
    from . import phase36_guix_center as phase36
except ImportError:  # Installed Guix Center sibling module.
    import guix_backend as phase36  # type: ignore[no-redef]

PolicyError = phase36.PolicyError
canonical_json_bytes = phase36.canonical_json_bytes

CONTRACT_FORMAT: Final[str] = "securityops-phase37-execution-contract/1"
JOURNAL_FORMAT: Final[str] = "securityops-phase37-operation-journal/1"
CAPABILITY_FORMAT: Final[str] = "securityops-phase37-capability-report/1"
STATUS: Final[str] = "PASS_PHASE37_PORTABLE_EXECUTION_RECOVERY_AND_DESCRIPTOR_BOUNDARY"
CONTRACT_DOMAIN: Final[bytes] = b"SECURITYOPS-PHASE37-EXECUTION-CONTRACT-V1\x00"
JOURNAL_DOMAIN: Final[bytes] = b"SECURITYOPS-PHASE37-OPERATION-JOURNAL-V1\x00"
CAPABILITY_DOMAIN: Final[bytes] = b"SECURITYOPS-PHASE37-CAPABILITY-REPORT-V1\x00"

PAGES: Final[tuple[str, ...]] = tuple(phase36.PAGES)
PAGE_STATES: Final[tuple[str, ...]] = (
    "loading", "ready", "empty", "stale", "offline", "error",
)
JOURNAL_STATES: Final[tuple[str, ...]] = (
    "prepared", "running", "succeeded", "failed", "cancelled", "interrupted",
)
_TRANSITIONS: Final[dict[str, frozenset[str]]] = {
    "prepared": frozenset({"running", "cancelled", "interrupted"}),
    "running": frozenset({"succeeded", "failed", "cancelled", "interrupted"}),
    "interrupted": frozenset({"running", "failed", "cancelled"}),
    "succeeded": frozenset(),
    "failed": frozenset(),
    "cancelled": frozenset(),
}

BLOCKERS: Final[tuple[str, ...]] = (
    "BLOCKED_PHASE37_AUTHENTICATED_GUIX_ENVIRONMENT_REQUIRED",
    "BLOCKED_PHASE37_REPRODUCIBLE_GUIX_CENTER_DERIVATION_REQUIRED",
    "BLOCKED_PHASE37_QT_OFFSCREEN_AND_GRAPHICAL_EXECUTION_REQUIRED",
    "BLOCKED_PHASE37_REAL_GUIX_TRANSACTION_MATRIX_REQUIRED",
    "BLOCKED_PHASE37_FOREIGN_DISTRO_MATRIX_REQUIRED",
    "BLOCKED_PHASE37_ACCESSIBILITY_HIDPI_LAYOUT_MATRIX_REQUIRED",
    "BLOCKED_PHASE37_EIGHT_HOUR_STABILITY_SOAK_REQUIRED",
    "BLOCKED_PHASE37_LINUX_7_2_GUIX_BUILD_AND_BOOT_REQUIRED",
    "BLOCKED_PHASE37_PERSONAL_VM_KVM_EXECUTION_REQUIRED",
    "BLOCKED_PHASE37_GAMING_VM_KVM_GPU_AUDIO_EXECUTION_REQUIRED",
    "BLOCKED_PHASE37_INSTALLER2_DISK_MATRIX_REQUIRED",
    "BLOCKED_PHASE37_DESKTOP_BOOT_AND_GNOME_ABSENCE_REQUIRED",
    "BLOCKED_PHASE37_KVM_MICROVM_AF_VSOCK_REQUIRED",
    "BLOCKED_PHASE37_REPRODUCIBLE_BOOTABLE_ISO_REQUIRED",
)

ACCESSIBILITY_MANIFEST: Final[dict[str, tuple[str, ...]]] = {
    "discover": (
        "discover-page", "package-search", "package-results", "package-details",
        "install-selected-package",
    ),
    "installed": (
        "installed-page", "installed-package-table", "remove-selected-package",
    ),
    "updates": ("updates-page", "available-updates", "apply-profile-upgrades"),
    "generations": (
        "generations-page", "generation-history", "rollback-generation",
        "switch-generation", "delete-generations",
    ),
    "profiles": ("profiles-page", "profile-selector", "profile-location"),
    "channels-and-trust": (
        "channels-and-trust-page", "channels-file", "channel-description",
        "pull-channels",
    ),
    "storage": ("storage-page", "gc-preview", "gc-delete"),
    "activity": (
        "activity-page", "transaction-activity", "activity-output",
        "cancel-active-transaction",
    ),
}

_COMMANDS: Final[tuple[str, ...]] = (
    "guix", "guile", "guild", "qemu-system-x86_64", "qemu-img", "rustc",
    "cargo", "gpgv", "readelf", "gcc", "git", "xvfb-run", "dbus-run-session",
)
_DEVICES: Final[tuple[str, ...]] = ("/dev/kvm", "/dev/vhost-vsock", "/dev/vsock")
_MODULES: Final[tuple[str, ...]] = ("PySide6", "psutil", "jsonschema")
_HEX32 = re.compile(r"^[0-9a-f]{32}$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_TOKEN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
MAX_JOURNAL_RECORDS: Final[int] = 10_000
MAX_JOURNAL_BYTES: Final[int] = 1024 * 1024
MAX_PLAN_AGE_SECONDS: Final[int] = 15 * 60
MAX_PLAN_FUTURE_SKEW_SECONDS: Final[int] = 60
HISTORICAL_DISABLED_REASON: Final[str] = (
    "historical-action-disabled-after-controller-death"
)


def _digest(domain: bytes, value: Mapping[str, Any]) -> str:
    return hashlib.sha256(domain + canonical_json_bytes(value)).hexdigest()


def phase37_contract() -> dict[str, Any]:
    return {
        "format": CONTRACT_FORMAT,
        "status": STATUS,
        "guix_center": {
            "toolkit": "Qt 6 / PySide 6",
            "architecture_count": 1,
            "pages": list(PAGES),
            "page_states": list(PAGE_STATES),
            "accessibility_manifest": {
                page: list(values) for page, values in ACCESSIBILITY_MANIFEST.items()
            },
            "keyboard_navigation_required": True,
            "screen_reader_traversal_required": True,
            "hidpi_scale_factors": [1.0, 1.25, 1.5, 2.0],
            "layout_widths": [640, 1080, 1920],
            "frontend_arbitrary_execution_allowed": False,
            "root_escalation_allowed": False,
            "system_reconfigure_available": False,
            "disabled_action_widgets": list(phase36.DISABLED_ACTIONS),
        },
        "execution": {
            "actions": list(phase36.ACTIONS),
            "executable_actions": list(phase36.EXECUTABLE_ACTIONS),
            "disabled_actions": list(phase36.DISABLED_ACTIONS),
            "guix_exec_descriptor_bound": True,
            "proc_fd_execution_required": True,
            "path_reopen_after_measurement_allowed": False,
            "shell_allowed": False,
            "ambient_path_lookup_allowed": False,
            "caller_supplied_argv_allowed": False,
            "exact_plan_confirmation_required": True,
            "plan_max_age_seconds": MAX_PLAN_AGE_SECONDS,
            "plan_max_future_skew_seconds": MAX_PLAN_FUTURE_SKEW_SECONDS,
            "stale_or_future_plan_execution_allowed": False,
            "journal_replay_prevention": True,
            "receipt_and_log_authentication_before_display": True,
            "transaction_journal": True,
            "journal_states": list(JOURNAL_STATES),
            "journal_receipt_digest_binding": True,
            "receipt_digest_same_uid_integrity_only": True,
            "receipt_origin_authentication_provided": False,
            "journal_receipt_normal_cross_binding_fields": [
                "plan_id", "action", "profile_name", "profile_path",
                "guix_sha256", "fixture_mode",
            ],
            "journal_receipt_recovery_cross_binding_fields": [
                "plan_id", "action", "profile_name",
            ],
            "historical_disabled_action_records_readable": True,
            "disabled_action_journal_creation_allowed": False,
            "disabled_action_running_transition_allowed": False,
            "disabled_action_receipt_recovery_promotion_allowed": False,
            "dead_disabled_action_recovery_terminal_state": "interrupted",
            "user_cancellation_supported": True,
            "authenticated_cancellation_marker_required": True,
            "cancelled_worker_receipt_binding_required": True,
            "journal_live_controller_identity": True,
            "prepared_controller_identity_required": True,
            "live_prepared_state_preserved": True,
            "dead_prepared_state_recovers_as_interrupted": True,
            "dead_running_state_recovers_as_interrupted": True,
            "authenticated_receipt_recovery_after_controller_death": True,
            "untrusted_receipt_cannot_complete_recovery": True,
            "live_running_state_preserved": True,
            "per_profile_mutation_serialization": True,
            "concurrent_profile_mutations_queued": True,
            "bounded_lock_wait_seconds": 30,
            "global_mutation_barrier": True,
        },
        "performance_and_stability": {
            "catalog_rows": [50_000, 100_000],
            "startup_cold_and_warm": True,
            "search_percentiles": [50, 95, 99],
            "memory_measurement": True,
            "concurrent_read_matrix": True,
            "sqlite_wal_concurrent_reads": True,
            "power_loss_fault_injection": True,
            "daemon_and_network_loss_classification": True,
            "required_soak_seconds": 28_800,
            "portable_measurements_are_not_gui_or_guix_evidence": True,
        },
        "capability_gates": {
            "guix_derivation_builds_required": 2,
            "guix_derivation_outputs_must_match": True,
            "qt_offscreen_required": True,
            "real_graphical_session_required": True,
            "foreign_distributions_required": 2,
            "linux_version": "7.2",
            "linux_guix_builds_required": 2,
            "linux_boot_required": True,
            "personal_vm_kvm_required": True,
            "gaming_vm_kvm_required": True,
            "gaming_gpu_iommu_required_for_passthrough": True,
            "vfio_noiommu_allowed": False,
            "installer_uefi_and_bios_required": True,
            "desktop_sessions": ["sway", "xmonad-xlibre", "plasma", "xfce", "lxde"],
            "gnome_selectable_session_allowed": False,
            "real_af_vsock_required": True,
            "iso_builds_required": 2,
            "iso_byte_identity_required": True,
        },
        "blockers": list(BLOCKERS),
        "production_gates_approved": 0,
        "production_dispatch_allowed": False,
        "iso_release_allowed": False,
    }


def phase37_contract_digest() -> str:
    return _digest(CONTRACT_DOMAIN, phase37_contract())


def parse_phase37_contract(value: Mapping[str, Any]) -> dict[str, Any]:
    candidate = json.loads(canonical_json_bytes(value))
    if candidate != phase37_contract():
        raise PolicyError("Phase 37 execution contract differs from the closed contract")
    return candidate


def accessibility_manifest() -> dict[str, list[str]]:
    return {page: list(values) for page, values in ACCESSIBILITY_MANIFEST.items()}


@dataclass(frozen=True)
class PageState:
    page: str
    state: str
    message: str
    revision: int
    updated_unix: int

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class PageStateMachine:
    """Toolkit-independent page state model used by headless and Qt tests."""

    def __init__(self, *, now_unix: int | None = None) -> None:
        now = int(time.time()) if now_unix is None else now_unix
        if type(now) is not int or now < 0:
            raise PolicyError("page-state time is invalid")
        self._states = {
            page: PageState(page, "loading", "Loading", 0, now) for page in PAGES
        }

    def transition(
        self, page: str, state: str, message: str, *, now_unix: int | None = None
    ) -> PageState:
        if page not in PAGES:
            raise PolicyError("unknown Guix Center page")
        if state not in PAGE_STATES:
            raise PolicyError("unknown Guix Center page state")
        if not isinstance(message, str) or not message.strip() or len(message) > 4096:
            raise PolicyError("page-state message is invalid")
        now = int(time.time()) if now_unix is None else now_unix
        if type(now) is not int or now < self._states[page].updated_unix:
            raise PolicyError("page-state time regressed")
        previous = self._states[page]
        current = PageState(page, state, message.strip(), previous.revision + 1, now)
        self._states[page] = current
        return current

    def snapshot(self) -> dict[str, Any]:
        return {
            "format": "securityops-phase37-page-state-snapshot/1",
            "pages": [self._states[page].to_dict() for page in PAGES],
            "production_dispatch_allowed": False,
            "iso_release_allowed": False,
        }


def validate_accessibility_snapshot(value: Mapping[str, Any]) -> dict[str, Any]:
    required = {
        "format", "toolkit", "application_id", "widgets", "page_count",
        "viewport", "production_dispatch_allowed", "iso_release_allowed",
    }
    if not isinstance(value, Mapping) or set(value) != required:
        raise PolicyError("accessibility snapshot fields are not closed")
    if value["format"] != "securityops-phase37-qt-accessibility-snapshot/1":
        raise PolicyError("accessibility snapshot format is invalid")
    if value["toolkit"] != "Qt 6 / PySide 6":
        raise PolicyError("accessibility snapshot toolkit is invalid")
    if value["application_id"] != "co.securityops.GuixCenter":
        raise PolicyError("accessibility snapshot application ID is invalid")
    if value["page_count"] != len(PAGES):
        raise PolicyError("accessibility snapshot page count is incomplete")
    viewport = value["viewport"]
    if not isinstance(viewport, Mapping) or set(viewport) != {
        "width_px", "height_px", "scale_factor", "logical_width", "layout"
    }:
        raise PolicyError("accessibility snapshot viewport is invalid")
    width = viewport["width_px"]
    height = viewport["height_px"]
    scale = viewport["scale_factor"]
    if type(width) is not int or not 640 <= width <= 7680:
        raise PolicyError("accessibility snapshot width is outside policy")
    if type(height) is not int or not 480 <= height <= 4320:
        raise PolicyError("accessibility snapshot height is outside policy")
    if type(scale) not in (int, float) or float(scale) not in (1.0, 1.25, 1.5, 2.0):
        raise PolicyError("accessibility snapshot scale is outside policy")
    logical = round(width / float(scale), 3)
    expected_layout = "compact" if logical <= 899 else (
        "regular" if logical <= 1439 else "wide"
    )
    if viewport["logical_width"] != logical or viewport["layout"] != expected_layout:
        raise PolicyError("accessibility snapshot responsive layout is inconsistent")
    if value["production_dispatch_allowed"] or value["iso_release_allowed"]:
        raise PolicyError("accessibility snapshot attempts production promotion")
    widgets = value["widgets"]
    if not isinstance(widgets, list) or len(widgets) > 4096:
        raise PolicyError("accessibility widget inventory is invalid")
    present: set[str] = set()
    for widget in widgets:
        if not isinstance(widget, Mapping) or set(widget) != {
            "id", "accessible_name", "visible", "enabled", "class"
        }:
            raise PolicyError("accessibility widget record is invalid")
        identifier = widget["id"]
        name = widget["accessible_name"]
        if not isinstance(identifier, str) or not _TOKEN.fullmatch(identifier):
            raise PolicyError("accessibility widget ID is invalid")
        if identifier in present:
            raise PolicyError("duplicate accessibility widget ID")
        present.add(identifier)
        if not isinstance(name, str) or not name.strip() or len(name) > 512:
            raise PolicyError("accessible name is missing or invalid")
        if type(widget["visible"]) is not bool or type(widget["enabled"]) is not bool:
            raise PolicyError("accessibility widget state is invalid")
        if not isinstance(widget["class"], str) or not widget["class"]:
            raise PolicyError("accessibility widget class is invalid")
    expected = {identifier for values in ACCESSIBILITY_MANIFEST.values() for identifier in values}
    missing = sorted(expected - present)
    if missing:
        raise PolicyError(
            "accessibility snapshot is missing required widgets: " + ", ".join(missing)
        )
    return json.loads(canonical_json_bytes(value))


def _strict_json_loads(payload: bytes) -> Any:
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            if key in result:
                raise PolicyError("duplicate JSON key")
            result[key] = value
        return result

    try:
        return json.loads(
            payload.decode("utf-8"), object_pairs_hook=pairs,
            parse_constant=lambda value: (_ for _ in ()).throw(
                PolicyError(f"non-finite JSON number: {value}")
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise PolicyError("journal JSON is invalid") from error


def _secure_private_dir(path: Path) -> None:
    if not path.is_absolute():
        raise PolicyError("journal root must be absolute")
    current = Path(path.anchor)
    for component in path.parts[1:]:
        current /= component
        try:
            metadata = current.lstat()
        except FileNotFoundError:
            try:
                current.mkdir(mode=0o700)
            except FileExistsError:
                # Concurrent workers may establish the same private directory.
                # The lstat validation below still rejects symlinks and files.
                pass
            metadata = current.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            raise PolicyError("journal path contains a non-directory component")
    metadata = path.lstat()
    if metadata.st_uid != os.geteuid():
        raise PolicyError("journal root must be owned by the current user")
    if metadata.st_mode & 0o077:
        os.chmod(path, 0o700)


def _atomic_private_json(path: Path, value: Mapping[str, Any]) -> None:
    _secure_private_dir(path.parent)
    if path.exists() or path.is_symlink():
        raise PolicyError("journal destination already exists")
    payload = canonical_json_bytes(value) + b"\n"
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(descriptor, 0o600)
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            view = view[written:]
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        # link() is no-replace publication; os.replace could overwrite a raced path.
        os.link(temporary, path, follow_symlinks=False)
        os.unlink(temporary)
        temporary = ""
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except FileExistsError as error:
        raise PolicyError("journal destination was concurrently created") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if temporary:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass


def _read_private_json(path: Path) -> dict[str, Any]:
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0))
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_uid != os.geteuid()
            or before.st_mode & 0o077
            or before.st_size > MAX_JOURNAL_BYTES
        ):
            raise PolicyError("journal record identity, mode, or size is unsafe")
        payload = bytearray()
        while len(payload) <= MAX_JOURNAL_BYTES:
            chunk = os.read(descriptor, min(65536, MAX_JOURNAL_BYTES + 1 - len(payload)))
            if not chunk:
                break
            payload.extend(chunk)
        if len(payload) > MAX_JOURNAL_BYTES:
            raise PolicyError("journal record exceeds the size bound")
        after = os.fstat(descriptor)
        if (
            before.st_dev, before.st_ino, before.st_mode, before.st_nlink,
            before.st_size, before.st_mtime_ns
        ) != (
            after.st_dev, after.st_ino, after.st_mode, after.st_nlink,
            after.st_size, after.st_mtime_ns
        ):
            raise PolicyError("journal record changed during measurement")
    finally:
        os.close(descriptor)
    value = _strict_json_loads(bytes(payload))
    if not isinstance(value, dict):
        raise PolicyError("journal record must be a JSON object")
    return value


def _process_start_ticks(pid: int) -> int | None:
    if type(pid) is not int or pid <= 0:
        return None
    try:
        text = Path(f"/proc/{pid}/stat").read_text(encoding="ascii")
        close = text.rfind(")")
        if close < 0:
            return None
        fields = text[close + 2:].split()
        # fields begins at Linux proc stat field 3; starttime is field 22.
        value = int(fields[19])
        return value if value > 0 else None
    except (OSError, UnicodeError, ValueError, IndexError):
        return None


def _process_identity_alive(pid: int | None, start_ticks: int | None) -> bool | None:
    if type(pid) is not int or pid <= 0 or type(start_ticks) is not int or start_ticks <= 0:
        return False
    observed = _process_start_ticks(pid)
    if observed is None:
        # Unknown is not dead. Recovery must not interrupt an unmeasured live job.
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return False
        except PermissionError:
            return None
        return None
    return observed == start_ticks


def _validate_journal_record(value: Mapping[str, Any]) -> dict[str, Any]:
    fields = {
        "format", "operation_id", "plan_id", "sequence", "state", "action",
        "profile", "created_unix", "updated_unix", "previous_digest", "reason",
        "controller_pid", "controller_start_ticks", "receipt_digest",
        "production_dispatch_allowed", "iso_release_allowed", "record_digest",
    }
    if not isinstance(value, Mapping) or set(value) != fields:
        raise PolicyError("journal record fields are not closed")
    record = dict(value)
    if record["format"] != JOURNAL_FORMAT:
        raise PolicyError("journal record format is invalid")
    if not isinstance(record["operation_id"], str) or not _HEX32.fullmatch(record["operation_id"]):
        raise PolicyError("journal operation ID is invalid")
    if not isinstance(record["plan_id"], str) or not _HEX64.fullmatch(record["plan_id"]):
        raise PolicyError("journal plan ID is invalid")
    if type(record["sequence"]) is not int or not 0 <= record["sequence"] < MAX_JOURNAL_RECORDS:
        raise PolicyError("journal sequence is invalid")
    if record["state"] not in JOURNAL_STATES:
        raise PolicyError("journal state is invalid")
    for field in ("action", "profile"):
        if not isinstance(record[field], str) or not _TOKEN.fullmatch(record[field]):
            raise PolicyError(f"journal {field} is invalid")
    if record["action"] not in phase36.ACTIONS:
        raise PolicyError("journal action is unsupported")
    for field in ("created_unix", "updated_unix"):
        if type(record[field]) is not int or record[field] < 0:
            raise PolicyError(f"journal {field} is invalid")
    if record["updated_unix"] < record["created_unix"]:
        raise PolicyError("journal time regressed")
    previous = record["previous_digest"]
    if previous is not None and (not isinstance(previous, str) or not _HEX64.fullmatch(previous)):
        raise PolicyError("journal previous digest is invalid")
    reason = record["reason"]
    if reason is not None and (
        not isinstance(reason, str) or not reason.strip() or len(reason) > 4096
    ):
        raise PolicyError("journal reason is invalid")
    pid = record["controller_pid"]
    ticks = record["controller_start_ticks"]
    if (pid is None) != (ticks is None):
        raise PolicyError("journal controller identity is partial")
    if pid is not None and (
        type(pid) is not int or pid <= 0 or type(ticks) is not int or ticks <= 0
    ):
        raise PolicyError("journal controller identity is invalid")
    receipt_digest = record["receipt_digest"]
    if receipt_digest is not None and (
        not isinstance(receipt_digest, str) or not _HEX64.fullmatch(receipt_digest)
    ):
        raise PolicyError("journal receipt digest is invalid")
    state = record["state"]
    if state == "prepared":
        if reason is not None or receipt_digest is not None or pid is None:
            raise PolicyError(
                "prepared journal state requires controller identity and no outcome"
            )
    elif state == "running":
        if reason is not None or pid is None or receipt_digest is not None:
            raise PolicyError("running journal state is incomplete or contains an outcome")
    elif state == "succeeded":
        if reason is not None or pid is None or receipt_digest is None:
            raise PolicyError("successful journal state lacks an authenticated receipt")
    elif state == "failed":
        if reason is None or pid is None:
            raise PolicyError("failed journal state lacks controller identity or reason")
    elif state == "cancelled":
        if reason is None:
            raise PolicyError("cancelled journal state requires a reason")
        # Cancellation before worker start has no controller or receipt. Once a
        # controller is recorded, a completed cancellation may bind the exact
        # authenticated receipt; a pre-exec cancellation may still have no receipt.
        if pid is None and receipt_digest is not None:
            raise PolicyError("pre-start cancellation cannot bind a receipt")
    elif state == "interrupted":
        if reason is None or receipt_digest is not None:
            raise PolicyError("interrupted journal state is invalid")
    if type(record["production_dispatch_allowed"]) is not bool or type(record["iso_release_allowed"]) is not bool:
        raise PolicyError("journal authorization fields are invalid")
    if record["production_dispatch_allowed"] or record["iso_release_allowed"]:
        raise PolicyError("journal record attempts production promotion")
    supplied = record.pop("record_digest")
    if not isinstance(supplied, str) or not _HEX64.fullmatch(supplied):
        raise PolicyError("journal digest is invalid")
    if supplied != _digest(JOURNAL_DOMAIN, record):
        raise PolicyError("journal digest does not match the record")
    record["record_digest"] = supplied
    return record


class OperationJournal:
    """Crash-safe append-only, digest-chained transaction lifecycle journal."""

    _FILE_RE = re.compile(r"^([0-9a-f]{32})-([0-9]{20})\.json$")

    def __init__(self, root: Path) -> None:
        self.root = Path(root)
        _secure_private_dir(self.root)
        self.lock_path = self.root / ".journal.lock"

    def _lock(self) -> int:
        descriptor = os.open(
            self.lock_path,
            os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1
            or metadata.st_uid != os.geteuid() or metadata.st_mode & 0o077
        ):
            os.close(descriptor)
            raise PolicyError("journal lock identity or mode is unsafe")
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        return descriptor

    @staticmethod
    def _unlock(descriptor: int) -> None:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)

    @staticmethod
    def _validate_operation_id(operation_id: str) -> str:
        if not isinstance(operation_id, str) or not _HEX32.fullmatch(operation_id):
            raise PolicyError("operation ID is invalid")
        return operation_id

    def _path(self, operation_id: str, sequence: int) -> Path:
        operation_id = self._validate_operation_id(operation_id)
        if type(sequence) is not int or not 0 <= sequence < MAX_JOURNAL_RECORDS:
            raise PolicyError("journal sequence is outside the bound")
        return self.root / f"{operation_id}-{sequence:020d}.json"

    def _paths(self, operation_id: str) -> list[Path]:
        operation_id = self._validate_operation_id(operation_id)
        paths = sorted(self.root.glob(f"{operation_id}-*.json"))
        if len(paths) > MAX_JOURNAL_RECORDS:
            raise PolicyError("journal history exceeds the record bound")
        return paths

    def create(
        self, *, plan_id: str, action: str, profile: str,
        operation_id: str | None = None, now_unix: int | None = None,
        controller_pid: int | None = None,
        controller_start_ticks: int | None = None,
    ) -> dict[str, Any]:
        operation_id = os.urandom(16).hex() if operation_id is None else operation_id
        self._validate_operation_id(operation_id)
        if not isinstance(plan_id, str) or not _HEX64.fullmatch(plan_id):
            raise PolicyError("plan ID is invalid")
        if action not in phase36.EXECUTABLE_ACTIONS:
            if action in phase36.DISABLED_ACTIONS:
                raise PolicyError(phase36.GC_DELETE_BLOCKER)
            raise PolicyError("journal action is unsupported")
        if not isinstance(profile, str) or not _TOKEN.fullmatch(profile):
            raise PolicyError("journal profile is invalid")
        now = int(time.time()) if now_unix is None else now_unix
        if type(now) is not int or now < 0:
            raise PolicyError("journal creation time is invalid")
        pid = os.getpid() if controller_pid is None else controller_pid
        ticks = (
            _process_start_ticks(pid)
            if controller_start_ticks is None else controller_start_ticks
        )
        if type(pid) is not int or pid <= 0 or type(ticks) is not int or ticks <= 0:
            raise PolicyError("prepared journal state cannot establish controller identity")
        record: dict[str, Any] = {
            "format": JOURNAL_FORMAT,
            "operation_id": operation_id,
            "plan_id": plan_id,
            "sequence": 0,
            "state": "prepared",
            "action": action,
            "profile": profile,
            "created_unix": now,
            "updated_unix": now,
            "previous_digest": None,
            "reason": None,
            "controller_pid": pid,
            "controller_start_ticks": ticks,
            "receipt_digest": None,
            "production_dispatch_allowed": False,
            "iso_release_allowed": False,
        }
        record["record_digest"] = _digest(JOURNAL_DOMAIN, record)
        descriptor = self._lock()
        try:
            if self._paths(operation_id):
                raise PolicyError("journal operation already exists")
            _atomic_private_json(self._path(operation_id, 0), record)
        finally:
            self._unlock(descriptor)
        return _validate_journal_record(record)

    def load_history(self, operation_id: str) -> list[dict[str, Any]]:
        paths = self._paths(operation_id)
        if not paths:
            raise PolicyError("journal operation does not exist")
        history: list[dict[str, Any]] = []
        for expected_sequence, path in enumerate(paths):
            match = self._FILE_RE.fullmatch(path.name)
            if match is None or match.group(1) != operation_id:
                raise PolicyError("journal filename is invalid")
            sequence = int(match.group(2))
            if sequence != expected_sequence:
                raise PolicyError("journal sequence is not contiguous")
            record = _validate_journal_record(_read_private_json(path))
            if record["operation_id"] != operation_id or record["sequence"] != sequence:
                raise PolicyError("journal filename and record identity differ")
            if not history:
                if record["state"] != "prepared" or record["previous_digest"] is not None:
                    raise PolicyError("journal history does not begin with prepared state")
            else:
                previous = history[-1]
                if record["previous_digest"] != previous["record_digest"]:
                    raise PolicyError("journal digest chain is broken")
                if record["state"] not in _TRANSITIONS[previous["state"]]:
                    raise PolicyError("journal history contains an invalid transition")
                for field in ("plan_id", "action", "profile", "created_unix"):
                    if record[field] != previous[field]:
                        raise PolicyError("journal immutable identity changed")
                if record["updated_unix"] < previous["updated_unix"]:
                    raise PolicyError("journal history time regressed")
            history.append(record)
        return history

    def load(self, operation_id: str) -> dict[str, Any]:
        return self.load_history(operation_id)[-1]

    def transition(
        self, operation_id: str, state: str, *, reason: str | None = None,
        receipt_digest: str | None = None, now_unix: int | None = None,
        controller_pid: int | None = None,
        controller_start_ticks: int | None = None,
    ) -> dict[str, Any]:
        if state not in JOURNAL_STATES:
            raise PolicyError("journal target state is invalid")
        descriptor = self._lock()
        try:
            current = self.load(operation_id)
            if current["action"] in phase36.DISABLED_ACTIONS:
                permitted_terminalization = (
                    state == "interrupted"
                    and current["state"] in {"prepared", "running"}
                    and reason == HISTORICAL_DISABLED_REASON
                    and receipt_digest is None
                    and _process_identity_alive(
                        current["controller_pid"], current["controller_start_ticks"]
                    ) is False
                )
                if not permitted_terminalization:
                    raise PolicyError(phase36.GC_DELETE_BLOCKER)
            if state not in _TRANSITIONS[current["state"]]:
                raise PolicyError("journal state transition is not allowed")
            now = int(time.time()) if now_unix is None else now_unix
            if type(now) is not int or now < current["updated_unix"]:
                raise PolicyError("journal transition time regressed")
            pid = current["controller_pid"]
            ticks = current["controller_start_ticks"]
            if state == "running":
                requested_pid = current["controller_pid"] if controller_pid is None else controller_pid
                requested_ticks = (
                    current["controller_start_ticks"]
                    if controller_start_ticks is None else controller_start_ticks
                )
                if (requested_pid, requested_ticks) != (
                    current["controller_pid"], current["controller_start_ticks"]
                ):
                    raise PolicyError("journal controller identity cannot change after prepare")
                pid = requested_pid
                ticks = requested_ticks
                if type(pid) is not int or pid <= 0 or type(ticks) is not int or ticks <= 0:
                    raise PolicyError("running transition cannot establish controller identity")
                normalized_reason = None
                normalized_receipt = None
            elif state == "succeeded":
                if reason is not None:
                    raise PolicyError("successful transition cannot contain a reason")
                if not isinstance(receipt_digest, str) or not _HEX64.fullmatch(receipt_digest):
                    raise PolicyError("successful transition requires an authenticated receipt digest")
                normalized_reason = None
                normalized_receipt = receipt_digest
            elif state == "failed":
                if not isinstance(reason, str) or not reason.strip() or len(reason) > 4096:
                    raise PolicyError("failed transition requires a bounded reason")
                if receipt_digest is not None and (
                    not isinstance(receipt_digest, str) or not _HEX64.fullmatch(receipt_digest)
                ):
                    raise PolicyError("failed transition receipt digest is invalid")
                normalized_reason = reason.strip()
                normalized_receipt = receipt_digest
            elif state == "cancelled":
                if not isinstance(reason, str) or not reason.strip() or len(reason) > 4096:
                    raise PolicyError("cancelled transition requires a bounded reason")
                if receipt_digest is not None and (
                    not isinstance(receipt_digest, str) or not _HEX64.fullmatch(receipt_digest)
                ):
                    raise PolicyError("cancelled transition receipt digest is invalid")
                if pid is None and receipt_digest is not None:
                    raise PolicyError("pre-start cancellation cannot bind a receipt")
                normalized_reason = reason.strip()
                normalized_receipt = receipt_digest
            else:  # interrupted
                if not isinstance(reason, str) or not reason.strip() or len(reason) > 4096:
                    raise PolicyError("interrupted transition requires a bounded reason")
                if receipt_digest is not None:
                    raise PolicyError("interrupted transition cannot bind a receipt")
                normalized_reason = reason.strip()
                normalized_receipt = None
            record: dict[str, Any] = {
                "format": JOURNAL_FORMAT,
                "operation_id": current["operation_id"],
                "plan_id": current["plan_id"],
                "sequence": current["sequence"] + 1,
                "state": state,
                "action": current["action"],
                "profile": current["profile"],
                "created_unix": current["created_unix"],
                "updated_unix": now,
                "previous_digest": current["record_digest"],
                "reason": normalized_reason,
                "controller_pid": pid,
                "controller_start_ticks": ticks,
                "receipt_digest": normalized_receipt,
                "production_dispatch_allowed": False,
                "iso_release_allowed": False,
            }
            record["record_digest"] = _digest(JOURNAL_DOMAIN, record)
            _atomic_private_json(self._path(operation_id, record["sequence"]), record)
        finally:
            self._unlock(descriptor)
        return _validate_journal_record(record)

    def recover_interrupted(
        self, *, state_root: Path | None = None, now_unix: int | None = None
    ) -> list[dict[str, Any]]:
        """Recover dead controllers without trusting unauthenticated outcomes.

        A dead running controller may have durably published a Phase 36 receipt
        immediately before it exited.  When a matching state root is supplied,
        recovery authenticates that receipt and its exact logs before closing
        the journal.  Missing or untrusted receipts remain interrupted.
        """
        root: Path | None = None
        if state_root is not None:
            root = Path(state_root)
            if not root.is_absolute() or root != self.root.parent:
                raise PolicyError("recovery state root does not match journal root")
        recovered: list[dict[str, Any]] = []
        for entry in self.list_records():
            alive = _process_identity_alive(
                entry["controller_pid"], entry["controller_start_ticks"]
            )
            if alive is not False:
                # True or unknown is preserved: never overwrite a potentially
                # live controller merely because recovery cannot inspect it.
                continue
            if entry["action"] in phase36.DISABLED_ACTIONS:
                if entry["state"] in {"prepared", "running"}:
                    recovered.append(self.transition(
                        entry["operation_id"], "interrupted",
                        reason=HISTORICAL_DISABLED_REASON,
                        now_unix=now_unix,
                    ))
                continue
            if entry["state"] == "prepared":
                recovered.append(self.transition(
                    entry["operation_id"], "interrupted",
                    reason="prepared-controller-identity-no-longer-alive",
                    now_unix=now_unix,
                ))
                continue
            if entry["state"] != "running":
                continue
            if root is not None:
                receipt_path = root / "receipts" / f"{entry['plan_id']}.json"
                try:
                    receipt_value = _read_private_json(receipt_path)
                    trusted = phase36.parse_transaction_receipt(
                        receipt_value, state_root=root
                    )
                    _require_receipt_binding(trusted, {
                        "plan_id": entry["plan_id"],
                        "action": entry["action"],
                        "profile_name": entry["profile"],
                    })
                except FileNotFoundError:
                    trusted = None
                except (OSError, PolicyError, ValueError, TypeError):
                    recovered.append(self.transition(
                        entry["operation_id"], "interrupted",
                        reason="untrusted-receipt-after-controller-death",
                        now_unix=now_unix,
                    ))
                    continue
                if trusted is not None:
                    receipt_digest = trusted["receipt_digest"]
                    if trusted["success"]:
                        recovered.append(self.transition(
                            entry["operation_id"], "succeeded",
                            receipt_digest=receipt_digest, now_unix=now_unix,
                        ))
                    elif phase36.receipt_was_cancelled(trusted, state_root=root):
                        recovered.append(self.transition(
                            entry["operation_id"], "cancelled",
                            reason="recovered-authenticated-cancellation",
                            receipt_digest=receipt_digest, now_unix=now_unix,
                        ))
                    else:
                        stderr = _read_authenticated_log(
                            Path(trusted["stderr_path"]),
                            expected_size=trusted["stderr_bytes"],
                            expected_sha256=trusted["stderr_sha256"],
                        )
                        recovered.append(self.transition(
                            entry["operation_id"], "failed",
                            reason=classify_failure(trusted, stderr),
                            receipt_digest=receipt_digest, now_unix=now_unix,
                        ))
                    continue
            recovered.append(self.transition(
                entry["operation_id"], "interrupted",
                reason="controller-process-identity-no-longer-alive",
                now_unix=now_unix,
            ))
        return recovered

    def list_records(self) -> list[dict[str, Any]]:
        try:
            metadata = self.root.lstat()
        except OSError as error:
            raise PolicyError("journal root is unavailable") from error
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            raise PolicyError("journal root identity is unsafe")
        operation_ids: set[str] = set()
        file_count = 0
        for path in self.root.glob("*.json"):
            file_count += 1
            if file_count > MAX_JOURNAL_RECORDS:
                raise PolicyError("journal record count exceeds the bound")
            match = self._FILE_RE.fullmatch(path.name)
            if match is None:
                raise PolicyError("journal directory contains an unknown JSON record")
            operation_ids.add(match.group(1))
        records = [self.load(operation_id) for operation_id in sorted(operation_ids)]
        records.sort(
            key=lambda item: (item["updated_unix"], item["operation_id"]), reverse=True
        )
        return records


def _bounded_reason(error: BaseException) -> str:
    text = f"{type(error).__name__}: {error}".replace("\x00", "").strip()
    return (text or type(error).__name__)[:4096]


def _require_receipt_binding(
    receipt: Mapping[str, Any], expected: Mapping[str, Any]
) -> None:
    """Bind same-UID receipt integrity evidence to its transaction identity."""
    mismatched = [field for field, value in expected.items() if receipt.get(field) != value]
    if mismatched:
        raise PolicyError(
            "receipt identity differs from transaction: " + ", ".join(mismatched)
        )


def _read_authenticated_log(
    path: Path, *, expected_size: int, expected_sha256: str
) -> str:
    """Read the exact receipt-bound log bytes through one stable descriptor.

    Phase 36 authenticates the receipt and logs before this call.  Classification
    must nevertheless avoid reopening a pathname after that measurement, because
    an attacker could replace the log between authentication and classification.
    """
    if type(expected_size) is not int or not 0 <= expected_size <= phase36.MAX_OUTPUT_BYTES:
        raise PolicyError("authenticated log size is invalid")
    if not isinstance(expected_sha256, str) or not _HEX64.fullmatch(expected_sha256):
        raise PolicyError("authenticated log digest is invalid")
    descriptor = os.open(
        path, os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    )
    payload = bytearray()
    digest = hashlib.sha256()
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_uid != os.geteuid()
            or stat.S_IMODE(before.st_mode) != 0o600
            or before.st_size != expected_size
        ):
            raise PolicyError("authenticated log identity, mode, or size is unsafe")
        while len(payload) <= expected_size:
            chunk = os.read(descriptor, min(65536, expected_size + 1 - len(payload)))
            if not chunk:
                break
            payload.extend(chunk)
            digest.update(chunk)
        if len(payload) != expected_size:
            raise PolicyError("authenticated log length changed during read")
        after = os.fstat(descriptor)
        identity = lambda item: (
            item.st_dev, item.st_ino, item.st_mode, item.st_uid, item.st_nlink,
            item.st_size, item.st_mtime_ns, item.st_ctime_ns,
        )
        if identity(before) != identity(after):
            raise PolicyError("authenticated log changed during descriptor read")
    finally:
        os.close(descriptor)
    if digest.hexdigest() != expected_sha256:
        raise PolicyError("authenticated log digest changed before classification")
    return bytes(payload).decode("utf-8", errors="replace")


def validate_plan_freshness(
    plan: Any, *, now_unix: int | None = None
) -> Any:
    """Authenticate and bound the lifetime of one reviewed transaction plan."""
    parsed = phase36.parse_transaction_plan(
        plan.to_dict() if hasattr(plan, "to_dict") else plan
    )
    now = int(time.time()) if now_unix is None else now_unix
    if type(now) is not int or now < 0:
        raise PolicyError("transaction execution time is invalid")
    if parsed.created_unix - now > MAX_PLAN_FUTURE_SKEW_SECONDS:
        raise PolicyError("transaction plan was created too far in the future")
    if now - parsed.created_unix > MAX_PLAN_AGE_SECONDS:
        raise PolicyError("transaction plan expired before execution")
    return parsed


def execute_transaction_plan_journaled(
    plan: Any, *, home: Path, state_root: Path,
    confirmation_plan_id: str | None = None, now_unix: int | None = None,
    cancel_event: Any | None = None,
) -> dict[str, Any]:
    """Execute through Phase 36 while binding lifecycle to an append-only journal.

    Phase 36 owns the exact command, locks, bounded process, logs, and receipt.
    This wrapper records prepared/running state before entry and only records
    success after the receipt and exact logs authenticate through the Phase 36
    parser. The operation nonce is reused as the unique journal identity.
    """
    parsed = validate_plan_freshness(plan, now_unix=now_unix)
    state_root = Path(state_root)
    journal = OperationJournal(state_root / "journal")
    operation_id = parsed.operation_nonce
    journal.create(
        plan_id=parsed.plan_id, action=parsed.action, profile=parsed.profile_name,
        operation_id=operation_id, now_unix=now_unix,
    )
    if cancel_event is not None:
        is_set = getattr(cancel_event, "is_set", None)
        if not callable(is_set):
            journal.transition(
                operation_id, "failed", reason="invalid-cancellation-token",
                now_unix=now_unix,
            )
            raise PolicyError("transaction cancellation token is invalid")
        if is_set():
            journal.transition(
                operation_id, "cancelled", reason="cancelled-before-worker-start",
                now_unix=now_unix,
            )
            raise phase36.TransactionCancelled(
                "transaction was cancelled before worker start"
            )
    journal.transition(operation_id, "running", now_unix=now_unix)
    try:
        receipt = phase36.execute_transaction_plan(
            parsed, home=Path(home), state_root=state_root,
            confirmation_plan_id=confirmation_plan_id, now_unix=now_unix,
            cancel_event=cancel_event,
        )
        trusted = phase36.parse_transaction_receipt(receipt, state_root=state_root)
        _require_receipt_binding(trusted, {
            "plan_id": parsed.plan_id,
            "action": parsed.action,
            "profile_name": parsed.profile_name,
            "profile_path": parsed.profile_path,
            "guix_sha256": parsed.guix_sha256,
            "fixture_mode": parsed.fixture_mode,
        })
    except phase36.TransactionCancelled as error:
        try:
            journal.transition(
                operation_id, "cancelled", reason=_bounded_reason(error),
                now_unix=now_unix,
            )
        except Exception:
            pass
        raise
    except BaseException as error:
        try:
            # Without an authenticated receipt, a set cancellation event is not
            # sufficient evidence that cancellation caused the failure.
            journal.transition(
                operation_id, "failed", reason=_bounded_reason(error),
                now_unix=now_unix,
            )
        except Exception:
            # Never mask the original transaction failure with journal failure.
            pass
        raise
    cancellation_requested = bool(
        cancel_event is not None
        and callable(getattr(cancel_event, "is_set", None))
        and cancel_event.is_set()
    )
    if cancellation_requested and phase36.receipt_was_cancelled(
        trusted, state_root=state_root
    ):
        journal.transition(
            operation_id, "cancelled", reason="cancelled-by-user",
            receipt_digest=trusted["receipt_digest"], now_unix=now_unix,
        )
    elif trusted["success"]:
        journal.transition(
            operation_id, "succeeded", receipt_digest=trusted["receipt_digest"],
            now_unix=now_unix,
        )
    else:
        stderr = _read_authenticated_log(
            Path(trusted["stderr_path"]),
            expected_size=trusted["stderr_bytes"],
            expected_sha256=trusted["stderr_sha256"],
        )
        journal.transition(
            operation_id, "failed",
            reason=classify_failure(trusted, stderr),
            receipt_digest=trusted["receipt_digest"], now_unix=now_unix,
        )
    return trusted


def classify_failure(receipt: Mapping[str, Any], stderr: str) -> str:
    """Classify bounded Guix failures without treating text as authority."""
    if not isinstance(stderr, str) or len(stderr.encode("utf-8")) > phase36.MAX_OUTPUT_BYTES:
        raise PolicyError("failure text exceeds the bounded size")
    if type(receipt.get("timed_out")) is not bool or type(receipt.get("output_limit_exceeded")) is not bool:
        raise PolicyError("receipt failure flags are invalid")
    if receipt["timed_out"]:
        return "timeout"
    if receipt["output_limit_exceeded"]:
        return "output-limit"
    lower = stderr.lower()
    patterns = (
        ("guix-daemon-unavailable", (
            "guix daemon", "failed to connect to guix-daemon", "daemon is not running",
        )),
        ("network-unavailable", (
            "temporary failure in name resolution", "network is unreachable",
            "connection timed out",
        )),
        ("trust-or-signature", (
            "signature", "unauthorized public key", "substitute has an invalid signature",
        )),
        ("disk-full", ("no space left on device", "disk quota exceeded")),
        ("permission", ("permission denied", "operation not permitted")),
    )
    for label, needles in patterns:
        if any(needle in lower for needle in needles):
            return label
    return "command-failed"


def _bounded_version(path: str) -> dict[str, Any]:
    try:
        result = subprocess.run(
            [path, "--version"], stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, check=False, timeout=3,
            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C", "LANG": "C"},
        )
        output = result.stdout[:4096].strip().splitlines()
        return {"returncode": result.returncode, "first_line": output[0] if output else ""}
    except (OSError, subprocess.SubprocessError) as error:
        return {"returncode": None, "first_line": "", "error": type(error).__name__}


def capability_report(*, include_versions: bool = True) -> dict[str, Any]:
    commands: dict[str, Any] = {}
    for name in _COMMANDS:
        path = shutil.which(name)
        record: dict[str, Any] = {"available": path is not None, "path": path}
        if path is not None and include_versions:
            record["version"] = _bounded_version(path)
        commands[name] = record
    modules = {name: importlib.util.find_spec(name) is not None for name in _MODULES}
    devices: dict[str, Any] = {}
    for name in _DEVICES:
        path = Path(name)
        try:
            metadata = path.stat()
            devices[name] = {
                "available": True,
                "character_device": stat.S_ISCHR(metadata.st_mode),
                "readable": os.access(path, os.R_OK),
                "writable": os.access(path, os.W_OK),
            }
        except OSError:
            devices[name] = {
                "available": False, "character_device": False,
                "readable": False, "writable": False,
            }
    gates = {
        "guix_environment": all(commands[name]["available"] for name in ("guix", "guile", "guild")),
        "qt_runtime": bool(modules["PySide6"]),
        "qt_offscreen_harness": bool(
            modules["PySide6"] and commands["xvfb-run"]["available"]
            and commands["dbus-run-session"]["available"]
        ),
        "kvm": bool(
            devices["/dev/kvm"]["available"] and devices["/dev/kvm"]["character_device"]
            and devices["/dev/kvm"]["readable"] and devices["/dev/kvm"]["writable"]
            and commands["qemu-system-x86_64"]["available"]
        ),
        "af_vsock": bool(
            (devices["/dev/vhost-vsock"]["available"] or devices["/dev/vsock"]["available"])
            and commands["qemu-system-x86_64"]["available"]
        ),
        "rust": all(commands[name]["available"] for name in ("rustc", "cargo")),
    }
    report: dict[str, Any] = {
        "format": CAPABILITY_FORMAT,
        "status": "PASS_PHASE37_CAPABILITY_PROBE_FAIL_CLOSED",
        "commands": commands,
        "python_modules": modules,
        "devices": devices,
        "gates_observed": gates,
        "blockers": list(BLOCKERS),
        "production_gates_approved": 0,
        "production_dispatch_allowed": False,
        "iso_release_allowed": False,
    }
    report["report_digest"] = _digest(CAPABILITY_DOMAIN, report)
    return report


def parse_capability_report(value: Mapping[str, Any]) -> dict[str, Any]:
    fields = {
        "format", "status", "commands", "python_modules", "devices",
        "gates_observed", "blockers", "production_gates_approved",
        "production_dispatch_allowed", "iso_release_allowed", "report_digest",
    }
    if not isinstance(value, Mapping) or set(value) != fields:
        raise PolicyError("capability report fields are not closed")
    report = json.loads(canonical_json_bytes(value))
    if report["format"] != CAPABILITY_FORMAT or report["status"] != "PASS_PHASE37_CAPABILITY_PROBE_FAIL_CLOSED":
        raise PolicyError("capability report identity is invalid")
    if set(report["commands"]) != set(_COMMANDS):
        raise PolicyError("capability command inventory is incomplete")
    if set(report["python_modules"]) != set(_MODULES):
        raise PolicyError("capability Python-module inventory is incomplete")
    if set(report["devices"]) != set(_DEVICES):
        raise PolicyError("capability device inventory is incomplete")
    expected_gates = {
        "guix_environment", "qt_runtime", "qt_offscreen_harness", "kvm", "af_vsock", "rust"
    }
    if set(report["gates_observed"]) != expected_gates or any(
        type(item) is not bool for item in report["gates_observed"].values()
    ):
        raise PolicyError("capability gate observations are invalid")
    if report["blockers"] != list(BLOCKERS):
        raise PolicyError("capability blocker inventory is invalid")
    if report["production_gates_approved"] != 0:
        raise PolicyError("capability report approves production gates")
    if report["production_dispatch_allowed"] or report["iso_release_allowed"]:
        raise PolicyError("capability report attempts production promotion")
    supplied = report.pop("report_digest")
    if not isinstance(supplied, str) or not _HEX64.fullmatch(supplied):
        raise PolicyError("capability report digest is invalid")
    if supplied != _digest(CAPABILITY_DOMAIN, report):
        raise PolicyError("capability report digest does not match")
    report["report_digest"] = supplied
    return report


def phase37_selftest() -> dict[str, Any]:
    contract = phase37_contract()
    parse_phase37_contract(contract)
    mutations = (
        lambda value: value["execution"].__setitem__("guix_exec_descriptor_bound", False),
        lambda value: value["execution"].__setitem__("shell_allowed", True),
        lambda value: value["execution"].__setitem__("journal_receipt_digest_binding", False),
        lambda value: value["execution"].__setitem__("user_cancellation_supported", False),
        lambda value: value["execution"].__setitem__("authenticated_cancellation_marker_required", False),
        lambda value: value["execution"].__setitem__("cancelled_worker_receipt_binding_required", False),
        lambda value: value["execution"].__setitem__("live_running_state_preserved", False),
        lambda value: value["execution"].__setitem__("concurrent_profile_mutations_queued", False),
        lambda value: value["execution"].__setitem__("bounded_lock_wait_seconds", 0),
        lambda value: value["execution"].__setitem__("plan_max_age_seconds", 0),
        lambda value: value["execution"].__setitem__("stale_or_future_plan_execution_allowed", True),
        lambda value: value["execution"].__setitem__("authenticated_receipt_recovery_after_controller_death", False),
        lambda value: value["guix_center"].__setitem__("architecture_count", 2),
        lambda value: value["guix_center"].__setitem__("root_escalation_allowed", True),
        lambda value: value["performance_and_stability"].__setitem__("sqlite_wal_concurrent_reads", False),
        lambda value: value["performance_and_stability"].__setitem__("required_soak_seconds", 60),
        lambda value: value["capability_gates"].__setitem__("vfio_noiommu_allowed", True),
        lambda value: value["capability_gates"].__setitem__("gnome_selectable_session_allowed", True),
        lambda value: value["capability_gates"].__setitem__("real_af_vsock_required", False),
        lambda value: value.__setitem__("production_dispatch_allowed", True),
        lambda value: value.__setitem__("iso_release_allowed", True),
    )
    rejected = 0
    for mutate in mutations:
        candidate = json.loads(json.dumps(contract))
        mutate(candidate)
        try:
            parse_phase37_contract(candidate)
        except PolicyError:
            rejected += 1
        else:
            raise AssertionError("Phase 37 contract mutation unexpectedly accepted")
    state = PageStateMachine(now_unix=1)
    for index, page in enumerate(PAGES, start=2):
        state.transition(page, "ready", f"{page} ready", now_unix=index)
    with tempfile.TemporaryDirectory(prefix="phase37-journal-selftest-") as raw:
        journal = OperationJournal(Path(raw) / "journal")
        operation = "01" * 16
        journal.create(
            plan_id="02" * 32, action="search", profile="default",
            operation_id=operation, now_unix=1,
        )
        journal.transition(operation, "running", now_unix=2)
        journal.transition(operation, "succeeded", receipt_digest="03" * 32, now_unix=3)
        if len(journal.load_history(operation)) != 3:
            raise AssertionError("Phase 37 journal self-test did not preserve its chain")
    report = capability_report(include_versions=False)
    parse_capability_report(report)
    return {
        "status": STATUS,
        "contract_digest": phase37_contract_digest(),
        "negative_cases_rejected": rejected,
        "pages": list(PAGES),
        "page_states": list(PAGE_STATES),
        "journal_states": list(JOURNAL_STATES),
        "accessibility_widget_count": sum(
            len(values) for values in ACCESSIBILITY_MANIFEST.values()
        ),
        "capability_report_digest": report["report_digest"],
        "production_gates_approved": 0,
        "production_dispatch_allowed": False,
        "iso_release_allowed": False,
        "blockers": list(BLOCKERS),
    }
