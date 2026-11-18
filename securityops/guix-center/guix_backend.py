# CodeMark v1 project=4c63e0fe-589c-4944-8449-97e211a38b72 file=d8d3eede581b5f26b74e72e6db0dd6de owner="Cristian Cezar Mois\u00e9s"
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-SecurityOps-Commercial
"""Security Ops Guix Center backend and fail-closed execution contract.

The backend is UI-toolkit independent.  A Qt/PySide front-end consumes these
plans but cannot construct arbitrary commands.  Every Guix operation uses an
admitted immutable executable, an exact argv allowlist, a bounded environment,
per-profile serialization, bounded logs, atomic receipts, and no shell.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import contextlib
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import selectors
import signal
import sqlite3
import stat
import subprocess
import tempfile
import threading
import time
from typing import Any, Final, Iterable, Mapping, Sequence


class PolicyError(ValueError):
    """Fail-closed validation error exposed to the graphical client."""


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"),
        ensure_ascii=True, allow_nan=False,
    ).encode("utf-8")

CONTRACT_FORMAT: Final[str] = "securityops-phase36-guix-center-contract/1"
PLAN_FORMAT: Final[str] = "securityops-phase36-guix-transaction-plan/1"
RECEIPT_FORMAT: Final[str] = "securityops-phase36-guix-transaction-receipt/1"
STATUS: Final[str] = "PASS_PHASE36_GUIX_CENTER_BACKEND_AND_UI_SOURCE_CONTRACT"
DOMAIN: Final[bytes] = b"SECURITYOPS-PHASE36-GUIX-CENTER-CONTRACT-V1\x00"
PLAN_DOMAIN: Final[bytes] = b"SECURITYOPS-PHASE36-GUIX-CENTER-PLAN-V1\x00"
RECEIPT_DOMAIN: Final[bytes] = b"SECURITYOPS-PHASE36-GUIX-CENTER-RECEIPT-V1\x00"

PAGES: Final[tuple[str, ...]] = (
    "discover",
    "installed",
    "updates",
    "generations",
    "profiles",
    "channels-and-trust",
    "storage",
    "activity",
)
READ_ACTIONS: Final[tuple[str, ...]] = (
    "search",
    "show",
    "list-installed",
    "list-upgrades",
    "list-generations",
    "gc-dry-run",
    "describe",
)
MUTATING_ACTIONS: Final[tuple[str, ...]] = (
    "install",
    "remove",
    "upgrade",
    "rollback",
    "switch-generation",
    "delete-generations",
    "gc-delete",
    "pull",
)
ACTIONS: Final[tuple[str, ...]] = READ_ACTIONS + MUTATING_ACTIONS
DISABLED_ACTIONS: Final[tuple[str, ...]] = ("gc-delete",)
EXECUTABLE_ACTIONS: Final[tuple[str, ...]] = tuple(
    action for action in ACTIONS if action not in DISABLED_ACTIONS
)
NETWORK_ACTIONS: Final[tuple[str, ...]] = (
    "search", "show", "list-upgrades", "install", "upgrade", "pull",
)
GC_DELETE_BLOCKER: Final[str] = (
    "gc-delete is unavailable until execution is bound to a private disposable "
    "Guix daemon/store and a fresh digest-bound --list-dead inventory"
)
if (
    set(EXECUTABLE_ACTIONS) & set(DISABLED_ACTIONS)
    or tuple(action for action in ACTIONS if action in EXECUTABLE_ACTIONS)
       != EXECUTABLE_ACTIONS
    or set(EXECUTABLE_ACTIONS) | set(DISABLED_ACTIONS) != set(ACTIONS)
    or not set(NETWORK_ACTIONS) <= set(EXECUTABLE_ACTIONS)
):  # pragma: no cover - constant construction invariant
    raise RuntimeError("Guix Center action policy constants are inconsistent")
BLOCKERS: Final[tuple[str, ...]] = (
    "BLOCKED_PHASE36_GUIX_PYSIDE6_PACKAGE_BUILD_REQUIRED",
    "BLOCKED_PHASE36_BOOTED_GUIX_CENTER_TRANSACTION_MATRIX_REQUIRED",
    "BLOCKED_PHASE36_FOREIGN_DISTRO_GUIX_ONBOARDING_MATRIX_REQUIRED",
    "BLOCKED_PHASE36_GUIX_CENTER_ACCESSIBILITY_AND_HIDPI_VALIDATION_REQUIRED",
    "BLOCKED_PHASE36_GC_DELETE_PRIVATE_DAEMON_AND_FRESH_PREVIEW_REQUIRED",
)

MAX_QUERY_CHARS: Final[int] = 256
MAX_PACKAGE_SPECS: Final[int] = 256
MAX_OUTPUT_BYTES: Final[int] = 16 * 1024 * 1024
MAX_TIMEOUT_SECONDS: Final[int] = 4 * 60 * 60
MAX_CACHE_ROWS: Final[int] = 2_000_000
CANCELLED_RETURNCODE: Final[int] = 130
LOCK_WAIT_SECONDS: Final[float] = 30.0

class TransactionCancelled(PolicyError):
    """A user-requested cancellation that occurred before worker execution."""


_PACKAGE_SPEC = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9+._-]{0,127}"
    r"(?:@[A-Za-z0-9][A-Za-z0-9+._~-]{0,63})?"
    r"(?::[A-Za-z0-9][A-Za-z0-9+._-]{0,63})?$"
)
_PROFILE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_QUERY = re.compile(r"^[^\x00-\x1f\x7f]{1,256}$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_GENERATION = re.compile(r"^[1-9][0-9]{0,17}$")


def _digest(domain: bytes, value: Mapping[str, Any]) -> str:
    return hashlib.sha256(domain + canonical_json_bytes(value)).hexdigest()


def guix_center_contract() -> dict[str, Any]:
    return {
        "format": CONTRACT_FORMAT,
        "status": STATUS,
        "product": {
            "name": "Security Ops Guix Center",
            "binary": "securityops-guix-center",
            "toolkit": "Qt 6 / PySide 6",
            "gnome_session_dependency_required": False,
            "pages": list(PAGES),
            "onboarding_for_foreign_distributions": True,
            "foreign_distribution_entry_points": [
                "/usr/local/bin/guix",
                "/usr/bin/guix",
                "$HOME/.config/guix/current/bin/guix",
                "/var/guix/profiles/per-user/$USER/current-guix/bin/guix",
            ],
            "keyboard_navigation_required": True,
            "screen_reader_labels_required": True,
            "hidpi_required": True,
        },
        "guix_semantics": {
            "per_user_profiles": True,
            "transaction_preview_required": True,
            "exact_argv_review_required": True,
            "typed_confirmation_required_for_mutations": True,
            "generation_history_visible": True,
            "rollback_supported": True,
            "explicit_profile_selection": True,
            "channel_and_trust_visibility": True,
            "garbage_collection_dry_run": False,
            "garbage_collection_preview_command": "list-dead",
            "garbage_collection_preview_is_shared_store_inventory": True,
            "garbage_collection_preview_authorizes_deletion": False,
            "garbage_collection_delete_available": False,
            "garbage_collection_private_disposable_daemon_required": True,
            "garbage_collection_fresh_digest_bound_preview_required": True,
            "root_escalation_allowed": False,
            "system_reconfigure_available_in_gui": False,
        },
        "execution": {
            "actions": list(ACTIONS),
            "executable_actions": list(EXECUTABLE_ACTIONS),
            "disabled_actions": list(DISABLED_ACTIONS),
            "disabled_action_blockers": {"gc-delete": GC_DELETE_BLOCKER},
            "shell_allowed": False,
            "ambient_path_lookup_allowed": False,
            "immutable_store_target_required": True,
            "close_fds": True,
            "new_process_session": True,
            "bounded_environment": True,
            "bounded_output": True,
            "bounded_timeout": True,
            "per_profile_single_flight_lock": True,
            "global_mutation_barrier": True,
            "concurrent_read_actions": True,
            "channels_file_private_snapshot": True,
            "atomic_receipts": True,
            "receipt_mode": "0600",
            "unique_operation_nonce": True,
            "receipt_content_digest": True,
            "receipt_log_sha256_required": True,
            "network_actions": list(NETWORK_ACTIONS),
            "caller_supplied_argv_allowed": False,
        },
        "performance_and_stability": {
            "sqlite_catalog_cache": True,
            "sqlite_journal_mode": "WAL",
            "sqlite_synchronous": "FULL",
            "background_workers": True,
            "search_debounce_ms": 250,
            "result_page_size": 100,
            "stale_cache_must_be_visible": True,
            "transaction_queue_is_per_profile": True,
            "crash_safe_activity_receipts": True,
        },
        "production_dispatch_allowed": False,
        "iso_release_allowed": False,
        "production_gates_approved": 0,
        "blockers": list(BLOCKERS),
    }


def guix_center_contract_digest() -> str:
    return _digest(DOMAIN, guix_center_contract())


def parse_guix_center_contract(value: Mapping[str, Any]) -> dict[str, Any]:
    if type(value) is not dict or value != guix_center_contract():
        raise PolicyError("Guix Center contract differs from the sealed Phase 36 policy")
    return dict(value)


def validate_package_spec(specification: str) -> str:
    if not isinstance(specification, str) or not _PACKAGE_SPEC.fullmatch(specification):
        raise PolicyError(f"invalid Guix package specification: {specification!r}")
    if specification.startswith("-") or ".." in specification:
        raise PolicyError("unsafe Guix package specification")
    return specification


def validate_query(query: str) -> str:
    if not isinstance(query, str) or not _QUERY.fullmatch(query):
        raise PolicyError("search query contains control characters or has an invalid length")
    stripped = query.strip()
    if not stripped:
        raise PolicyError("search query cannot be blank")
    if stripped.startswith("-"):
        raise PolicyError("search query may not begin with a Guix option prefix")
    return stripped


def _validate_absolute_path(path: Path, *, name: str) -> Path:
    if not path.is_absolute():
        raise PolicyError(f"{name} must be absolute")
    if any(part in ("", ".", "..") for part in path.parts[1:]):
        raise PolicyError(f"{name} contains an unsafe path component")
    return path


@dataclass(frozen=True)
class AdmittedGuix:
    requested_path: str
    resolved_path: str
    device: int
    inode: int
    mode: int
    size: int
    sha256: str
    fixture_mode: bool
    immutable_store_target: bool
    production_dispatch_allowed: bool = False


def admit_guix_executable(path: Path, *, fixture_mode: bool = False) -> AdmittedGuix:
    requested = _validate_absolute_path(Path(path), name="Guix executable")
    try:
        resolved = requested.resolve(strict=True)
        descriptor = os.open(
            resolved, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | os.O_CLOEXEC
        )
    except (FileNotFoundError, RuntimeError, OSError) as error:
        raise PolicyError("Guix executable cannot be resolved") from error
    digest = hashlib.sha256()
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or not before.st_mode & 0o111:
            raise PolicyError("Guix executable must resolve to an executable regular file")
        if before.st_mode & 0o022:
            raise PolicyError("Guix executable cannot be group/other writable")
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
        after = os.fstat(descriptor)
        if (
            before.st_dev, before.st_ino, before.st_mode, before.st_size, before.st_mtime_ns
        ) != (
            after.st_dev, after.st_ino, after.st_mode, after.st_size, after.st_mtime_ns
        ):
            raise PolicyError("Guix executable changed during measurement")
    finally:
        os.close(descriptor)
    immutable = str(resolved).startswith("/gnu/store/") and resolved.name == "guix"
    if not immutable and not fixture_mode:
        raise PolicyError("Guix executable must resolve to an immutable /gnu/store target")
    return AdmittedGuix(
        requested_path=str(requested),
        resolved_path=str(resolved),
        device=before.st_dev,
        inode=before.st_ino,
        mode=stat.S_IMODE(before.st_mode),
        size=before.st_size,
        sha256=digest.hexdigest(),
        fixture_mode=fixture_mode,
        immutable_store_target=immutable,
        production_dispatch_allowed=False,
    )


def discover_guix_candidates(home: Path, user: str) -> tuple[Path, ...]:
    home = _validate_absolute_path(Path(home), name="home directory")
    if not _PROFILE_NAME.fullmatch(user):
        raise PolicyError("user name has an invalid form")
    return (
        Path("/run/current-system/profile/bin/guix"),
        home / ".config/guix/current/bin/guix",
        Path(f"/var/guix/profiles/per-user/{user}/current-guix/bin/guix"),
        Path("/usr/local/bin/guix"),
        Path("/usr/bin/guix"),
    )


def profile_path(home: Path, profile: str) -> Path:
    home = _validate_absolute_path(Path(home), name="home directory")
    if not _PROFILE_NAME.fullmatch(profile):
        raise PolicyError("profile name has an invalid form")
    if profile == "default":
        return home / ".guix-profile"
    return home / ".guix-extra-profiles/securityops" / profile / profile


def _validate_channel_file(path: Path, *, owner_uid: int) -> tuple[str, str, int, int, int]:
    path = _validate_absolute_path(path, name="channels file")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | os.O_CLOEXEC)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise PolicyError("channels file must be a single-linked regular file")
        if metadata.st_uid != owner_uid:
            raise PolicyError("channels file must be owned by the current user")
        if metadata.st_mode & 0o022:
            raise PolicyError("channels file cannot be group/other writable")
        if metadata.st_size > 4 * 1024 * 1024:
            raise PolicyError("channels file exceeds the bounded size")
        digest = hashlib.sha256()
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
        after = os.fstat(descriptor)
        if (metadata.st_dev, metadata.st_ino, metadata.st_size, metadata.st_mtime_ns) != (
            after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns
        ):
            raise PolicyError("channels file changed during measurement")
    finally:
        os.close(descriptor)
    return str(path), digest.hexdigest(), metadata.st_dev, metadata.st_ino, metadata.st_size


@dataclass(frozen=True)
class TransactionPlan:
    format: str
    plan_id: str
    operation_nonce: str
    created_unix: int
    action: str
    profile_name: str
    profile_path: str
    guix_path: str
    guix_sha256: str
    guix_device: int
    guix_inode: int
    guix_mode: int
    guix_size: int
    argv: tuple[str, ...]
    package_specs: tuple[str, ...]
    query: str | None
    generation: int | None
    delete_generations: str | None
    channels_path: str | None
    channels_sha256: str | None
    channels_device: int | None
    channels_inode: int | None
    channels_size: int | None
    network_expected: bool
    mutating: bool
    confirmation_required: bool
    timeout_seconds: int
    maximum_output_bytes: int
    fixture_mode: bool
    shell_allowed: bool
    root_escalation_allowed: bool
    production_dispatch_allowed: bool
    iso_release_allowed: bool

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["argv"] = list(self.argv)
        value["package_specs"] = list(self.package_specs)
        return value


def create_transaction_plan(
    *,
    admitted: AdmittedGuix,
    home: Path,
    profile: str,
    action: str,
    package_specs: Sequence[str] = (),
    query: str | None = None,
    generation: int | None = None,
    channels_file: Path | None = None,
    owner_uid: int | None = None,
    delete_generations: str | None = None,
    timeout_seconds: int = 3600,
    operation_nonce: str | None = None,
    created_unix: int | None = None,
) -> TransactionPlan:
    if action not in ACTIONS:
        raise PolicyError("unsupported Guix Center action")
    if action in DISABLED_ACTIONS:
        if (
            package_specs or query is not None or generation is not None
            or channels_file is not None or owner_uid is not None
            or delete_generations is not None
        ):
            raise PolicyError("gc-delete accepts no extra arguments")
        raise PolicyError(GC_DELETE_BLOCKER)
    _validate_absolute_path(home, name="home directory")
    selected_profile = profile_path(home, profile)
    if type(timeout_seconds) is not int or not 1 <= timeout_seconds <= MAX_TIMEOUT_SECONDS:
        raise PolicyError("timeout is outside the bounded range")
    if len(package_specs) > MAX_PACKAGE_SPECS:
        raise PolicyError("too many package specifications")
    if operation_nonce is None:
        operation_nonce = secrets.token_hex(16)
    if not isinstance(operation_nonce, str) or not re.fullmatch(r"[0-9a-f]{32}", operation_nonce):
        raise PolicyError("operation nonce must be 128 bits of lowercase hexadecimal")
    if created_unix is None:
        created_unix = int(time.time())
    if type(created_unix) is not int or created_unix < 0:
        raise PolicyError("transaction creation time is invalid")
    specs = tuple(validate_package_spec(spec) for spec in package_specs)
    if len(set(specs)) != len(specs):
        raise PolicyError("duplicate package specification")

    guix = admitted.resolved_path
    profile_args = [f"--profile={selected_profile}"]
    argv: list[str]
    network_expected = action in NETWORK_ACTIONS
    normalized_query: str | None = None
    normalized_delete: str | None = None
    normalized_channels: str | None = None
    channels_sha256: str | None = None
    channels_device: int | None = None
    channels_inode: int | None = None
    channels_size: int | None = None
    if action == "search":
        if specs or generation is not None or channels_file is not None or delete_generations is not None:
            raise PolicyError("search accepts only a query")
        normalized_query = validate_query(query or "")
        argv = [guix, "search", normalized_query]
    elif action == "show":
        if len(specs) != 1 or query is not None or generation is not None or channels_file is not None or delete_generations is not None:
            raise PolicyError("show requires exactly one package specification")
        argv = [guix, "show", specs[0]]
    elif action == "list-installed":
        if specs or query is not None or generation is not None or channels_file is not None or delete_generations is not None:
            raise PolicyError("list-installed accepts no package or generation")
        argv = [guix, "package", *profile_args, "--list-installed"]
    elif action == "list-upgrades":
        if specs or query is not None or generation is not None or channels_file is not None or delete_generations is not None:
            raise PolicyError("list-upgrades accepts no package or generation")
        argv = [guix, "package", *profile_args, "--dry-run", "--upgrade"]
    elif action == "list-generations":
        if specs or query is not None or generation is not None or channels_file is not None or delete_generations is not None:
            raise PolicyError("list-generations accepts no extra arguments")
        argv = [guix, "package", *profile_args, "--list-generations"]
    elif action == "install":
        if not specs or query is not None or generation is not None or channels_file is not None or delete_generations is not None:
            raise PolicyError("install requires at least one package")
        argv = [guix, "package", *profile_args, "--install", *specs]
    elif action == "remove":
        if not specs or query is not None or generation is not None or channels_file is not None or delete_generations is not None:
            raise PolicyError("remove requires at least one package")
        argv = [guix, "package", *profile_args, "--remove", *specs]
    elif action == "upgrade":
        if query is not None or generation is not None or channels_file is not None or delete_generations is not None:
            raise PolicyError("upgrade accepts only optional package specifications")
        argv = [guix, "package", *profile_args, "--upgrade", *specs]
    elif action == "rollback":
        if specs or query is not None or generation is not None or channels_file is not None or delete_generations is not None:
            raise PolicyError("rollback accepts no package or generation")
        argv = [guix, "package", *profile_args, "--roll-back"]
    elif action == "switch-generation":
        if specs or query is not None or channels_file is not None or delete_generations is not None or type(generation) is not int or not _GENERATION.fullmatch(str(generation)):
            raise PolicyError("switch-generation requires a positive canonical generation")
        argv = [guix, "package", *profile_args, f"--switch-generation={generation}"]
    elif action == "delete-generations":
        if specs or query is not None or generation is not None or channels_file is not None or not delete_generations or len(delete_generations) > 64:
            raise PolicyError("delete-generations requires a bounded selector")
        if not re.fullmatch(r"(?:[1-9][0-9]*(?:\.\.[1-9][0-9]*)?|[1-9][0-9]*[dwmy]|old)", delete_generations):
            raise PolicyError("unsafe generation deletion selector")
        normalized_delete = delete_generations
        argv = [guix, "package", *profile_args, f"--delete-generations={normalized_delete}"]
    elif action == "gc-dry-run":
        if specs or query is not None or generation is not None or channels_file is not None or delete_generations is not None:
            raise PolicyError("gc-dry-run accepts no extra arguments")
        argv = [guix, "gc", "--list-dead"]
    elif action == "pull":
        if specs or query is not None or generation is not None or delete_generations is not None or channels_file is None or owner_uid is None:
            raise PolicyError("pull requires an owned explicit channels file")
        (normalized_channels, channels_sha256, channels_device,
         channels_inode, channels_size) = _validate_channel_file(
            channels_file, owner_uid=owner_uid
        )
        argv = [guix, "pull", f"--channels={normalized_channels}"]
    elif action == "describe":
        if specs or query is not None or generation is not None or channels_file is not None or delete_generations is not None:
            raise PolicyError("describe accepts no extra arguments")
        argv = [guix, "describe", "--format=json"]
    else:  # pragma: no cover - ACTIONS is closed above
        raise PolicyError("unreachable action")

    descriptor = {
        "operation_nonce": operation_nonce,
        "created_unix": created_unix,
        "action": action,
        "profile_name": profile,
        "profile_path": str(selected_profile),
        "guix_path": guix,
        "guix_sha256": admitted.sha256,
        "guix_device": admitted.device,
        "guix_inode": admitted.inode,
        "guix_mode": admitted.mode,
        "guix_size": admitted.size,
        "argv": argv,
        "package_specs": list(specs),
        "query": normalized_query,
        "generation": generation,
        "delete_generations": normalized_delete,
        "channels_path": normalized_channels,
        "channels_sha256": channels_sha256,
        "channels_device": channels_device,
        "channels_inode": channels_inode,
        "channels_size": channels_size,
        "network_expected": network_expected,
        "mutating": action in MUTATING_ACTIONS,
        "timeout_seconds": timeout_seconds,
        "fixture_mode": admitted.fixture_mode,
    }
    return TransactionPlan(
        format=PLAN_FORMAT,
        plan_id=_digest(PLAN_DOMAIN, descriptor),
        operation_nonce=operation_nonce,
        created_unix=created_unix,
        action=action,
        profile_name=profile,
        profile_path=str(selected_profile),
        guix_path=guix,
        guix_sha256=admitted.sha256,
        guix_device=admitted.device,
        guix_inode=admitted.inode,
        guix_mode=admitted.mode,
        guix_size=admitted.size,
        argv=tuple(argv),
        package_specs=specs,
        query=normalized_query,
        generation=generation,
        delete_generations=normalized_delete,
        channels_path=normalized_channels,
        channels_sha256=channels_sha256,
        channels_device=channels_device,
        channels_inode=channels_inode,
        channels_size=channels_size,
        network_expected=network_expected,
        mutating=action in MUTATING_ACTIONS,
        confirmation_required=action in MUTATING_ACTIONS,
        timeout_seconds=timeout_seconds,
        maximum_output_bytes=MAX_OUTPUT_BYTES,
        fixture_mode=admitted.fixture_mode,
        shell_allowed=False,
        root_escalation_allowed=False,
        production_dispatch_allowed=False,
        iso_release_allowed=False,
    )


def _transaction_descriptor(plan: TransactionPlan) -> dict[str, Any]:
    return {
        "operation_nonce": plan.operation_nonce,
        "created_unix": plan.created_unix,
        "action": plan.action,
        "profile_name": plan.profile_name,
        "profile_path": plan.profile_path,
        "guix_path": plan.guix_path,
        "guix_sha256": plan.guix_sha256,
        "guix_device": plan.guix_device,
        "guix_inode": plan.guix_inode,
        "guix_mode": plan.guix_mode,
        "guix_size": plan.guix_size,
        "argv": list(plan.argv),
        "package_specs": list(plan.package_specs),
        "query": plan.query,
        "generation": plan.generation,
        "delete_generations": plan.delete_generations,
        "channels_path": plan.channels_path,
        "channels_sha256": plan.channels_sha256,
        "channels_device": plan.channels_device,
        "channels_inode": plan.channels_inode,
        "channels_size": plan.channels_size,
        "network_expected": plan.network_expected,
        "mutating": plan.mutating,
        "timeout_seconds": plan.timeout_seconds,
        "fixture_mode": plan.fixture_mode,
    }


def _expected_transaction_argv(plan: TransactionPlan) -> tuple[str, ...]:
    if plan.action in DISABLED_ACTIONS:
        raise PolicyError(GC_DELETE_BLOCKER)
    if plan.action not in EXECUTABLE_ACTIONS:
        raise PolicyError("unsupported transaction action")
    if not _PROFILE_NAME.fullmatch(plan.profile_name):
        raise PolicyError("transaction profile name has an invalid form")
    selected_profile = _validate_absolute_path(Path(plan.profile_path), name="profile path")
    if plan.profile_name == "default":
        if selected_profile.name != ".guix-profile":
            raise PolicyError("default profile path is not canonical")
    else:
        suffix = (".guix-extra-profiles", "securityops", plan.profile_name, plan.profile_name)
        if tuple(selected_profile.parts[-4:]) != suffix:
            raise PolicyError("named profile path is not canonical")
    guix = str(_validate_absolute_path(Path(plan.guix_path), name="Guix executable"))
    specs = tuple(validate_package_spec(spec) for spec in plan.package_specs)
    if len(specs) > MAX_PACKAGE_SPECS or len(set(specs)) != len(specs):
        raise PolicyError("transaction package closure is invalid")
    profile_args = (f"--profile={selected_profile}",)

    no_channel = (
        plan.channels_path is None
        and plan.channels_sha256 is None
        and plan.channels_device is None
        and plan.channels_inode is None
        and plan.channels_size is None
    )
    no_selector = plan.delete_generations is None
    no_generation = plan.generation is None
    no_query = plan.query is None

    if plan.action == "search":
        if specs or no_query or not no_generation or not no_selector or not no_channel:
            raise PolicyError("search transaction fields are not canonical")
        return (guix, "search", validate_query(plan.query or ""))
    if plan.action == "show":
        if len(specs) != 1 or not no_query or not no_generation or not no_selector or not no_channel:
            raise PolicyError("show transaction fields are not canonical")
        return (guix, "show", specs[0])
    if plan.action in {"list-installed", "list-generations"}:
        if specs or not no_query or not no_generation or not no_selector or not no_channel:
            raise PolicyError(f"{plan.action} transaction fields are not canonical")
        option = {
            "list-installed": "--list-installed",
            "list-generations": "--list-generations",
        }[plan.action]
        return (guix, "package", *profile_args, option)
    if plan.action == "list-upgrades":
        if specs or not no_query or not no_generation or not no_selector or not no_channel:
            raise PolicyError("list-upgrades transaction fields are not canonical")
        return (guix, "package", *profile_args, "--dry-run", "--upgrade")
    if plan.action in {"install", "remove"}:
        if not specs or not no_query or not no_generation or not no_selector or not no_channel:
            raise PolicyError(f"{plan.action} transaction fields are not canonical")
        option = "--install" if plan.action == "install" else "--remove"
        return (guix, "package", *profile_args, option, *specs)
    if plan.action == "upgrade":
        if not no_query or not no_generation or not no_selector or not no_channel:
            raise PolicyError("upgrade transaction fields are not canonical")
        return (guix, "package", *profile_args, "--upgrade", *specs)
    if plan.action == "rollback":
        if specs or not no_query or not no_generation or not no_selector or not no_channel:
            raise PolicyError("rollback transaction fields are not canonical")
        return (guix, "package", *profile_args, "--roll-back")
    if plan.action == "switch-generation":
        if specs or not no_query or not no_selector or not no_channel:
            raise PolicyError("switch-generation transaction fields are not canonical")
        if type(plan.generation) is not int or not _GENERATION.fullmatch(str(plan.generation)):
            raise PolicyError("switch-generation has an invalid generation")
        return (guix, "package", *profile_args, f"--switch-generation={plan.generation}")
    if plan.action == "delete-generations":
        if specs or not no_query or not no_generation or not no_channel:
            raise PolicyError("delete-generations transaction fields are not canonical")
        selector = plan.delete_generations or ""
        if not re.fullmatch(r"(?:[1-9][0-9]*(?:\.\.[1-9][0-9]*)?|[1-9][0-9]*[dwmy]|old)", selector):
            raise PolicyError("delete-generations has an unsafe selector")
        return (guix, "package", *profile_args, f"--delete-generations={selector}")
    if plan.action in {"gc-dry-run", "describe"}:
        if specs or not no_query or not no_generation or not no_selector or not no_channel:
            raise PolicyError(f"{plan.action} transaction fields are not canonical")
        return {
            "gc-dry-run": (guix, "gc", "--list-dead"),
            "describe": (guix, "describe", "--format=json"),
        }[plan.action]
    if plan.action == "pull":
        if specs or not no_query or not no_generation or not no_selector:
            raise PolicyError("pull transaction fields are not canonical")
        if not isinstance(plan.channels_path, str):
            raise PolicyError("pull transaction lacks a channels path")
        _validate_absolute_path(Path(plan.channels_path), name="channels file")
        if not isinstance(plan.channels_sha256, str) or not _HEX64.fullmatch(plan.channels_sha256):
            raise PolicyError("pull transaction lacks a channels digest")
        if any(type(value) is not int or value < 0 for value in (
            plan.channels_device, plan.channels_inode, plan.channels_size
        )):
            raise PolicyError("pull transaction has invalid channel-file identity")
        return (guix, "pull", f"--channels={plan.channels_path}")
    raise PolicyError("unsupported transaction action")


def parse_transaction_plan(value: Mapping[str, Any]) -> TransactionPlan:
    if type(value) is not dict or set(value) != set(TransactionPlan.__dataclass_fields__):
        raise PolicyError("transaction plan has missing or unknown fields")
    argv = value.get("argv")
    specs = value.get("package_specs")
    if type(argv) is not list or any(type(item) is not str for item in argv):
        raise PolicyError("transaction argv must be a string array")
    if type(specs) is not list or any(type(item) is not str for item in specs):
        raise PolicyError("package specs must be a string array")
    try:
        plan = TransactionPlan(**{**value, "argv": tuple(argv), "package_specs": tuple(specs)})
    except TypeError as error:
        raise PolicyError("invalid transaction plan") from error
    if plan.format != PLAN_FORMAT or plan.action not in ACTIONS:
        raise PolicyError("invalid transaction plan identity")
    if plan.action in DISABLED_ACTIONS:
        raise PolicyError(GC_DELETE_BLOCKER)
    if tuple(plan.argv) != _expected_transaction_argv(plan):
        raise PolicyError("transaction argv differs from the exact action allowlist")
    forbidden = {"sh", "bash", "sudo", "doas", "pkexec", "su", "env"}
    if any(Path(item).name in forbidden for item in plan.argv):
        raise PolicyError("transaction plan contains a forbidden launcher")
    if plan.shell_allowed or plan.root_escalation_allowed:
        raise PolicyError("transaction plan attempts shell or root escalation")
    if plan.production_dispatch_allowed or plan.iso_release_allowed:
        raise PolicyError("transaction plan attempts production promotion")
    if not _HEX64.fullmatch(plan.plan_id) or not _HEX64.fullmatch(plan.guix_sha256):
        raise PolicyError("transaction plan digest is invalid")
    if not isinstance(plan.operation_nonce, str) or not re.fullmatch(r"[0-9a-f]{32}", plan.operation_nonce):
        raise PolicyError("transaction operation nonce is invalid")
    if type(plan.created_unix) is not int or plan.created_unix < 0:
        raise PolicyError("transaction creation time is invalid")
    if any(type(value) is not int or value < 0 for value in (
        plan.guix_device, plan.guix_inode, plan.guix_mode, plan.guix_size
    )):
        raise PolicyError("transaction Guix identity is invalid")
    if plan.maximum_output_bytes != MAX_OUTPUT_BYTES:
        raise PolicyError("transaction output bound differs from policy")
    if type(plan.timeout_seconds) is not int or not 1 <= plan.timeout_seconds <= MAX_TIMEOUT_SECONDS:
        raise PolicyError("transaction timeout differs from policy")
    expected_network = plan.action in NETWORK_ACTIONS
    expected_mutating = plan.action in MUTATING_ACTIONS
    if plan.network_expected is not expected_network:
        raise PolicyError("transaction network declaration differs from action policy")
    if plan.mutating is not expected_mutating or plan.confirmation_required is not expected_mutating:
        raise PolicyError("transaction mutation/confirmation flags differ from action policy")
    if type(plan.fixture_mode) is not bool:
        raise PolicyError("transaction fixture mode must be boolean")
    expected_plan_id = _digest(PLAN_DOMAIN, _transaction_descriptor(plan))
    if plan.plan_id != expected_plan_id:
        raise PolicyError("transaction plan digest does not match its exact contents")
    return plan



def _measure_private_log(
    path: Path, *, expected_size: int, expected_sha256: str
) -> str:
    """Measure one private activity log through a stable no-follow descriptor."""
    path = _validate_absolute_path(path, name="transaction activity log")
    descriptor = os.open(
        path, os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    )
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
            raise PolicyError("transaction activity log identity or size is unsafe")
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
        after = os.fstat(descriptor)
        identity = lambda item: (
            item.st_dev, item.st_ino, item.st_mode, item.st_uid, item.st_nlink,
            item.st_size, item.st_mtime_ns, item.st_ctime_ns,
        )
        if identity(before) != identity(after):
            raise PolicyError("transaction activity log changed during measurement")
    finally:
        os.close(descriptor)
    measured = digest.hexdigest()
    if measured != expected_sha256:
        raise PolicyError("transaction activity log digest does not match its receipt")
    return measured


def parse_transaction_receipt(
    value: Mapping[str, Any], *, state_root: Path
) -> dict[str, Any]:
    """Authenticate the closed receipt shape before the GUI displays its logs."""
    expected_fields = {
        "format", "plan_id", "action", "profile_name", "profile_path",
        "guix_sha256", "channels_snapshot_path", "channels_snapshot_sha256",
        "started_unix", "finished_unix", "returncode",
        "timed_out", "output_limit_exceeded", "cancelled", "stdout_path", "stdout_bytes",
        "stdout_sha256", "stderr_path", "stderr_bytes", "stderr_sha256",
        "success", "fixture_mode",
        "production_dispatch_allowed", "iso_release_allowed", "receipt_digest",
    }
    if type(value) is not dict or set(value) != expected_fields:
        raise PolicyError("transaction receipt has missing or unknown fields")
    receipt = dict(value)
    if receipt["format"] != RECEIPT_FORMAT:
        raise PolicyError("transaction receipt format is invalid")
    if not isinstance(receipt["plan_id"], str) or not _HEX64.fullmatch(receipt["plan_id"]):
        raise PolicyError("transaction receipt plan ID is invalid")
    if receipt["action"] not in ACTIONS:
        raise PolicyError("transaction receipt action is invalid")
    if not isinstance(receipt["profile_name"], str) or not _PROFILE_NAME.fullmatch(receipt["profile_name"]):
        raise PolicyError("transaction receipt profile name is invalid")
    _validate_absolute_path(Path(receipt["profile_path"]), name="receipt profile path")
    if not isinstance(receipt["guix_sha256"], str) or not _HEX64.fullmatch(receipt["guix_sha256"]):
        raise PolicyError("transaction receipt Guix digest is invalid")
    if receipt["action"] == "pull":
        if (
            not isinstance(receipt["channels_snapshot_path"], str)
            or not isinstance(receipt["channels_snapshot_sha256"], str)
            or not _HEX64.fullmatch(receipt["channels_snapshot_sha256"])
        ):
            raise PolicyError("pull receipt lacks a private channels snapshot")
        expected_snapshot = (
            _validate_absolute_path(state_root, name="receipt state root")
            / "channels-snapshots" / f"{receipt['plan_id']}.scm"
        )
        if receipt["channels_snapshot_path"] != str(expected_snapshot):
            raise PolicyError("pull receipt channels snapshot path is not canonical")
    elif receipt["channels_snapshot_path"] is not None or receipt["channels_snapshot_sha256"] is not None:
        raise PolicyError("non-pull receipt unexpectedly contains a channels snapshot")
    for field in ("stdout_sha256", "stderr_sha256"):
        if not isinstance(receipt[field], str) or not _HEX64.fullmatch(receipt[field]):
            raise PolicyError(f"transaction receipt {field} is invalid")
    for field in ("started_unix", "finished_unix", "returncode", "stdout_bytes", "stderr_bytes"):
        if type(receipt[field]) is not int:
            raise PolicyError(f"transaction receipt {field} is not an integer")
    if receipt["started_unix"] < 0 or receipt["finished_unix"] < receipt["started_unix"]:
        raise PolicyError("transaction receipt timestamps are invalid")
    if receipt["stdout_bytes"] < 0 or receipt["stderr_bytes"] < 0:
        raise PolicyError("transaction receipt output size is invalid")
    if receipt["stdout_bytes"] + receipt["stderr_bytes"] > MAX_OUTPUT_BYTES:
        raise PolicyError("transaction receipt exceeds the output bound")
    for field in (
        "timed_out", "output_limit_exceeded", "cancelled", "success", "fixture_mode",
        "production_dispatch_allowed", "iso_release_allowed",
    ):
        if type(receipt[field]) is not bool:
            raise PolicyError(f"transaction receipt {field} is not boolean")
    if receipt["production_dispatch_allowed"] or receipt["iso_release_allowed"]:
        raise PolicyError("transaction receipt attempts production promotion")
    expected_success = (
        receipt["returncode"] == 0
        and not receipt["timed_out"]
        and not receipt["output_limit_exceeded"]
        and not receipt["cancelled"]
    )
    if receipt["success"] is not expected_success:
        raise PolicyError("transaction receipt success flag is inconsistent")
    state_root = _validate_absolute_path(state_root, name="receipt state root")
    log_root = state_root / "logs"
    expected_stdout = log_root / f"{receipt['plan_id']}.stdout"
    expected_stderr = log_root / f"{receipt['plan_id']}.stderr"
    if receipt["stdout_path"] != str(expected_stdout) or receipt["stderr_path"] != str(expected_stderr):
        raise PolicyError("transaction receipt log paths are not canonical")
    # Authenticate the closed receipt fields before using their size/digest claims to
    # measure activity logs. The logs are then remeasured through no-follow file
    # descriptors, so neither receipt-field mutation nor post-receipt log mutation
    # can reach the UI unnoticed.
    supplied_digest = receipt.pop("receipt_digest")
    if not isinstance(supplied_digest, str) or not _HEX64.fullmatch(supplied_digest):
        raise PolicyError("transaction receipt digest is invalid")
    if supplied_digest != _digest(RECEIPT_DOMAIN, receipt):
        raise PolicyError("transaction receipt digest does not match its contents")
    receipt["receipt_digest"] = supplied_digest
    _measure_private_log(
        expected_stdout,
        expected_size=receipt["stdout_bytes"],
        expected_sha256=receipt["stdout_sha256"],
    )
    _measure_private_log(
        expected_stderr,
        expected_size=receipt["stderr_bytes"],
        expected_sha256=receipt["stderr_sha256"],
    )
    return receipt

def _bounded_environment(home: Path, state_root: Path) -> dict[str, str]:
    return {
        "HOME": str(home),
        "USER": str(home.name),
        "LOGNAME": str(home.name),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "TZ": "UTC",
        "PATH": "/run/current-system/profile/bin",
        "GUIX_LOCPATH": "/run/current-system/locale",
        "XDG_CACHE_HOME": str(state_root / "cache"),
        "XDG_CONFIG_HOME": str(home / ".config"),
        "XDG_DATA_HOME": str(home / ".local/share"),
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_TERMINAL_PROMPT": "0",
    }


def _secure_dir(path: Path, *, mode: int = 0o700) -> None:
    _validate_absolute_path(path, name="state directory")
    current = Path(path.anchor)
    for component in path.parts[1:]:
        current /= component
        try:
            metadata = current.lstat()
        except FileNotFoundError:
            try:
                current.mkdir(mode=mode)
            except FileExistsError:
                # A concurrent worker may have safely created the component.
                # Re-open it with lstat and still reject symlinks or files.
                pass
            metadata = current.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            raise PolicyError(f"state path component is not a real directory: {current}")
    metadata = path.lstat()
    if metadata.st_uid != os.geteuid():
        raise PolicyError("state directory must be owned by the current user")
    if metadata.st_mode & 0o077:
        os.chmod(path, mode)


def _atomic_json(path: Path, value: Mapping[str, Any]) -> None:
    _secure_dir(path.parent)
    payload = canonical_json_bytes(value) + b"\n"
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb", closefd=True) as stream:
            descriptor = -1
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass



def _acquire_lock(
    path: Path, *, exclusive: bool, conflict: str,
    wait_seconds: float = LOCK_WAIT_SECONDS,
    cancel_event: threading.Event | None = None,
) -> int:
    """Acquire one private lock with bounded queuing and cancellation.

    A non-blocking probe loop prevents unbounded GUI worker stalls while still
    serializing same-profile mutations instead of racing or silently dropping
    a user request.  Cancellation is checked before every retry.
    """
    if type(wait_seconds) not in (int, float) or not 0 <= float(wait_seconds) <= LOCK_WAIT_SECONDS:
        raise PolicyError("transaction lock wait is outside the bounded policy")
    descriptor = os.open(
        path,
        os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_uid != os.geteuid()
            or metadata.st_mode & 0o077
        ):
            raise PolicyError("transaction lock identity or mode is unsafe")
        operation = fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH
        deadline = time.monotonic() + float(wait_seconds)
        while True:
            if cancel_event is not None and cancel_event.is_set():
                raise TransactionCancelled("transaction was cancelled while waiting for a lock")
            try:
                fcntl.flock(descriptor, operation | fcntl.LOCK_NB)
                return descriptor
            except BlockingIOError as error:
                if time.monotonic() >= deadline:
                    raise PolicyError(conflict) from error
                time.sleep(0.05)
    except Exception:
        os.close(descriptor)
        raise


def _release_lock(descriptor: int | None) -> None:
    if descriptor is None:
        return
    try:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
    finally:
        os.close(descriptor)


def _materialize_channels_snapshot(
    *,
    source: Path,
    expected: tuple[str, str | None, int | None, int | None, int | None],
    owner_uid: int,
    snapshot_root: Path,
    plan_id: str,
) -> tuple[Path, str]:
    """Copy the exact validated channels bytes into a private immutable snapshot."""
    _secure_dir(snapshot_root)
    source = _validate_absolute_path(source, name="channels file")
    source_fd = os.open(source, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | os.O_CLOEXEC)
    temporary_fd = -1
    temporary_path = ""
    destination = snapshot_root / f"{plan_id}.scm"
    digest = hashlib.sha256()
    try:
        before = os.fstat(source_fd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise PolicyError("channels file must be a single-linked regular file")
        if before.st_uid != owner_uid or before.st_mode & 0o022:
            raise PolicyError("channels file ownership or mode is unsafe")
        if before.st_size > 4 * 1024 * 1024:
            raise PolicyError("channels file exceeds the bounded size")
        temporary_fd, temporary_path = tempfile.mkstemp(
            prefix=f".{plan_id}.", suffix=".scm", dir=snapshot_root
        )
        os.fchmod(temporary_fd, 0o400)
        while True:
            chunk = os.read(source_fd, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
            view = memoryview(chunk)
            while view:
                written = os.write(temporary_fd, view)
                view = view[written:]
        after = os.fstat(source_fd)
        if (
            before.st_dev, before.st_ino, before.st_mode, before.st_size, before.st_mtime_ns
        ) != (
            after.st_dev, after.st_ino, after.st_mode, after.st_size, after.st_mtime_ns
        ):
            raise PolicyError("channels file changed during private snapshot creation")
        measured = (
            str(source), digest.hexdigest(), before.st_dev, before.st_ino, before.st_size
        )
        if measured != expected:
            raise PolicyError("channels file changed before execution")
        os.fsync(temporary_fd)
        os.close(temporary_fd)
        temporary_fd = -1
        os.link(temporary_path, destination, follow_symlinks=False)
        os.unlink(temporary_path)
        temporary_path = ""
        directory = os.open(snapshot_root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        os.close(source_fd)
        if temporary_fd >= 0:
            os.close(temporary_fd)
        if temporary_path:
            try:
                os.unlink(temporary_path)
            except FileNotFoundError:
                pass
    snapshot = destination.lstat()
    if (
        not stat.S_ISREG(snapshot.st_mode)
        or snapshot.st_nlink != 1
        or stat.S_IMODE(snapshot.st_mode) != 0o400
        or snapshot.st_uid != os.geteuid()
        or snapshot.st_size != expected[4]
    ):
        raise PolicyError("private channels snapshot identity is unsafe")
    return destination, digest.hexdigest()


def _open_bound_guix_executable(plan: TransactionPlan) -> tuple[int, str]:
    """Open, measure, and retain the exact Guix executable through execve.

    The returned Linux procfd path is used as ``Popen(executable=...)`` while
    the original, reviewed argv remains unchanged.  Keeping the descriptor
    open and passing only that descriptor to the child closes the pathname
    replacement window between measurement and execve.
    """
    path = _validate_absolute_path(Path(plan.guix_path), name="Guix executable")
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise PolicyError("admitted Guix executable cannot be opened for execution") from error
    digest = hashlib.sha256()
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or not before.st_mode & 0o111
            or before.st_mode & 0o022
        ):
            raise PolicyError("admitted Guix executable identity is unsafe at execution")
        while True:
            block = os.read(descriptor, 1024 * 1024)
            if not block:
                break
            digest.update(block)
        after = os.fstat(descriptor)
        observed = (
            before.st_dev,
            before.st_ino,
            stat.S_IMODE(before.st_mode),
            before.st_size,
            digest.hexdigest(),
            before.st_mtime_ns,
        )
        stable = (
            after.st_dev,
            after.st_ino,
            stat.S_IMODE(after.st_mode),
            after.st_size,
            digest.hexdigest(),
            after.st_mtime_ns,
        )
        expected = (
            plan.guix_device,
            plan.guix_inode,
            plan.guix_mode,
            plan.guix_size,
            plan.guix_sha256,
            before.st_mtime_ns,
        )
        if observed != stable:
            raise PolicyError("admitted Guix executable changed during execution measurement")
        if observed != expected:
            raise PolicyError("admitted Guix executable changed before execution (descriptor-bound identity mismatch)")
        os.lseek(descriptor, 0, os.SEEK_SET)
        proc_path = f"/proc/self/fd/{descriptor}"
        try:
            proc_metadata = os.stat(proc_path)
        except OSError as error:
            raise PolicyError("Linux procfd execution is unavailable; refusing pathname fallback") from error
        if (proc_metadata.st_dev, proc_metadata.st_ino) != (before.st_dev, before.st_ino):
            raise PolicyError("procfd does not identify the measured Guix executable")
        return descriptor, proc_path
    except Exception:
        os.close(descriptor)
        raise

def execute_transaction_plan(
    plan: TransactionPlan,
    *,
    home: Path,
    state_root: Path,
    confirmation_plan_id: str | None = None,
    now_unix: int | None = None,
    cancel_event: threading.Event | None = None,
) -> dict[str, Any]:
    """Execute an already validated plan and return an atomic activity receipt."""
    parsed = parse_transaction_plan(plan.to_dict())
    home = _validate_absolute_path(home, name="home directory")
    state_root = _validate_absolute_path(state_root, name="state root")
    try:
        home_metadata = home.lstat()
    except OSError as error:
        raise PolicyError("home directory is unavailable") from error
    if stat.S_ISLNK(home_metadata.st_mode) or not stat.S_ISDIR(home_metadata.st_mode):
        raise PolicyError("home directory must be a real directory")
    if str(profile_path(home, parsed.profile_name)) != parsed.profile_path:
        raise PolicyError("transaction profile is not rooted in the selected home")
    if parsed.confirmation_required and confirmation_plan_id != parsed.plan_id:
        raise PolicyError("mutating transaction requires exact plan-id confirmation")
    if cancel_event is not None:
        is_set = getattr(cancel_event, "is_set", None)
        if not callable(is_set):
            raise PolicyError("transaction cancellation token is invalid")
        if is_set():
            raise TransactionCancelled("transaction was cancelled before execution")
    if os.geteuid() == 0 and not parsed.fixture_mode:
        raise PolicyError("Guix Center refuses to run per-user transactions as root")
    expected_channels = (
        parsed.channels_path,
        parsed.channels_sha256,
        parsed.channels_device,
        parsed.channels_inode,
        parsed.channels_size,
    )

    _secure_dir(state_root)
    lock_root = state_root / "locks"
    log_root = state_root / "logs"
    receipt_root = state_root / "receipts"
    snapshot_root = state_root / "channels-snapshots"
    for directory in (
        lock_root, log_root, receipt_root, snapshot_root, state_root / "cache"
    ):
        _secure_dir(directory)

    global_exclusive = parsed.action == "pull"
    global_lock_fd: int | None = _acquire_lock(
        lock_root / "global.lock",
        exclusive=global_exclusive,
        conflict=(
            "a global Guix mutation is active"
            if global_exclusive
            else "a global Guix mutation blocks this transaction"
        ),
        wait_seconds=min(float(parsed.timeout_seconds), LOCK_WAIT_SECONDS),
        cancel_event=cancel_event,
    )
    profile_lock_fd: int | None = None
    try:
        profile_actions = {
            "list-installed", "list-upgrades", "list-generations",
            "install", "remove", "upgrade", "rollback",
            "switch-generation", "delete-generations",
        }
        if parsed.action in profile_actions:
            profile_exclusive = parsed.action in MUTATING_ACTIONS
            lock_name = hashlib.sha256(parsed.profile_path.encode("utf-8")).hexdigest()
            profile_lock_fd = _acquire_lock(
                lock_root / f"profile-{lock_name}.lock",
                exclusive=profile_exclusive,
                conflict="another transaction conflicts with the selected profile",
                wait_seconds=min(float(parsed.timeout_seconds), LOCK_WAIT_SECONDS),
                cancel_event=cancel_event,
            )
        if parsed.profile_name != "default" and parsed.action in MUTATING_ACTIONS:
            _secure_dir(Path(parsed.profile_path).parent)
        if cancel_event is not None and cancel_event.is_set():
            raise TransactionCancelled("transaction was cancelled before worker start")

        channels_snapshot_path: str | None = None
        channels_snapshot_sha256: str | None = None
        execution_argv = list(parsed.argv)
        if parsed.channels_path is not None:
            snapshot, snapshot_digest = _materialize_channels_snapshot(
                source=Path(parsed.channels_path),
                expected=expected_channels,
                owner_uid=home_metadata.st_uid,
                snapshot_root=snapshot_root,
                plan_id=parsed.plan_id,
            )
            channels_snapshot_path = str(snapshot)
            channels_snapshot_sha256 = snapshot_digest
            execution_argv[-1] = f"--channels={snapshot}"
        if cancel_event is not None and cancel_event.is_set():
            raise TransactionCancelled("transaction was cancelled before worker start")

        started = int(time.time()) if now_unix is None else now_unix
        stdout_path = log_root / f"{parsed.plan_id}.stdout"
        stderr_path = log_root / f"{parsed.plan_id}.stderr"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
        stdout_fd = os.open(stdout_path, flags, 0o600)
        stderr_fd = os.open(stderr_path, flags, 0o600)
        timed_out = False
        output_limit_exceeded = False
        cancelled = False
        process: subprocess.Popen[bytes] | None = None
        stdout_size = 0
        stderr_size = 0
        stdout_digest = hashlib.sha256()
        stderr_digest = hashlib.sha256()
        selector = selectors.DefaultSelector()
        guix_execution_fd: int | None = None
        try:
            environment = _bounded_environment(home, state_root)
            guix_execution_fd, guix_execution_path = _open_bound_guix_executable(parsed)
            process = subprocess.Popen(
                execution_argv,
                executable=guix_execution_path,
                pass_fds=(guix_execution_fd,),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd="/",
                env=environment,
                close_fds=True,
                start_new_session=True,
                shell=False,
            )
            if process.stdout is None or process.stderr is None:
                raise PolicyError("Guix worker pipes were not created")
            streams = (
                (process.stdout, stdout_fd, "stdout"),
                (process.stderr, stderr_fd, "stderr"),
            )
            for stream, destination, label in streams:
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ, (destination, label))
            deadline = time.monotonic() + parsed.timeout_seconds
            termination_deadline: float | None = None
            total_output = 0

            def terminate_group(sig: int) -> None:
                try:
                    os.killpg(process.pid, sig)
                except ProcessLookupError:
                    pass

            while selector.get_map() or process.poll() is None:
                now = time.monotonic()
                if (
                    cancel_event is not None
                    and not cancelled
                    and process.poll() is None
                    and cancel_event.is_set()
                ):
                    cancelled = True
                    termination_deadline = now + 5.0
                    terminate_group(signal.SIGTERM)
                if now >= deadline and not timed_out and not cancelled:
                    timed_out = True
                    termination_deadline = now + 5.0
                    terminate_group(signal.SIGTERM)
                if termination_deadline is not None and now >= termination_deadline:
                    terminate_group(signal.SIGKILL)
                    termination_deadline = None
                events = selector.select(timeout=0.05)
                for key, _mask in events:
                    destination, label = key.data
                    try:
                        chunk = os.read(key.fd, 64 * 1024)
                    except BlockingIOError:
                        continue
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    remaining = parsed.maximum_output_bytes - total_output
                    if remaining <= 0:
                        output_limit_exceeded = True
                        terminate_group(signal.SIGKILL)
                        continue
                    accepted = chunk[:remaining]
                    view = memoryview(accepted)
                    while view:
                        written = os.write(destination, view)
                        view = view[written:]
                    total_output += len(accepted)
                    if label == "stdout":
                        stdout_size += len(accepted)
                        stdout_digest.update(accepted)
                    else:
                        stderr_size += len(accepted)
                        stderr_digest.update(accepted)
                    if len(chunk) > len(accepted):
                        output_limit_exceeded = True
                        terminate_group(signal.SIGKILL)
            returncode = process.wait(timeout=10)
            if cancelled:
                # POSIX shells conventionally expose SIGINT-style cancellation as
                # 128 + SIGINT.  The value is authenticated by the unchanged
                # Phase 36 receipt digest and remains an unsuccessful result.
                returncode = CANCELLED_RETURNCODE
            os.fsync(stdout_fd)
            os.fsync(stderr_fd)
        except BaseException:
            # Never leave an uncollected worker or descendant process when the
            # supervisor itself fails.  The worker was started in a fresh session.
            if process is not None and process.poll() is None:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    pass
            raise
        finally:
            selector.close()
            if guix_execution_fd is not None:
                os.close(guix_execution_fd)
            if process is not None:
                for stream in (process.stdout, process.stderr):
                    if stream is not None:
                        stream.close()
            os.close(stdout_fd)
            os.close(stderr_fd)
        finished = int(time.time()) if now_unix is None else max(now_unix, started)
        receipt = {
            "format": RECEIPT_FORMAT,
            "plan_id": parsed.plan_id,
            "action": parsed.action,
            "profile_name": parsed.profile_name,
            "profile_path": parsed.profile_path,
            "guix_sha256": parsed.guix_sha256,
            "channels_snapshot_path": channels_snapshot_path,
            "channels_snapshot_sha256": channels_snapshot_sha256,
            "started_unix": started,
            "finished_unix": finished,
            "returncode": returncode,
            "timed_out": timed_out,
            "output_limit_exceeded": output_limit_exceeded,
            "cancelled": cancelled,
            "stdout_path": str(stdout_path),
            "stdout_bytes": stdout_size,
            "stdout_sha256": stdout_digest.hexdigest(),
            "stderr_path": str(stderr_path),
            "stderr_bytes": stderr_size,
            "stderr_sha256": stderr_digest.hexdigest(),
            "success": (
                returncode == 0
                and not timed_out
                and not output_limit_exceeded
                and not cancelled
            ),
            "fixture_mode": parsed.fixture_mode,
            "production_dispatch_allowed": False,
            "iso_release_allowed": False,
        }
        receipt["receipt_digest"] = _digest(RECEIPT_DOMAIN, receipt)
        _atomic_json(receipt_root / f"{parsed.plan_id}.json", receipt)
        return receipt
    finally:
        _release_lock(profile_lock_fd)
        _release_lock(global_lock_fd)



def receipt_was_cancelled(
    value: Mapping[str, Any], *, state_root: Path
) -> bool:
    """Authenticate a receipt and identify an explicit user cancellation."""
    receipt = parse_transaction_receipt(value, state_root=state_root)
    return (
        receipt["cancelled"]
        and receipt["returncode"] == CANCELLED_RETURNCODE
        and not receipt["timed_out"]
        and not receipt["output_limit_exceeded"]
        and not receipt["success"]
    )


class CatalogCache:
    """Crash-safe, thread-safe local catalog cache for the asynchronous GUI."""

    def __init__(self, path: Path) -> None:
        self.path = _validate_absolute_path(path, name="catalog database")
        _secure_dir(self.path.parent)
        try:
            metadata = self.path.lstat()
        except FileNotFoundError:
            metadata = None
        if metadata is not None:
            if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
                raise PolicyError("catalog database must be a regular file")
            if metadata.st_uid != os.geteuid() or metadata.st_mode & 0o022:
                raise PolicyError("catalog database ownership or mode is unsafe")
        self._lock = threading.RLock()
        self._closed = False
        with contextlib.closing(self._connection()) as connection, connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS packages (
                    name TEXT NOT NULL,
                    version TEXT NOT NULL,
                    output TEXT NOT NULL,
                    synopsis TEXT NOT NULL,
                    description TEXT NOT NULL,
                    location TEXT NOT NULL,
                    updated_unix INTEGER NOT NULL,
                    PRIMARY KEY(name, version, output)
                );
                CREATE INDEX IF NOT EXISTS packages_name_idx ON packages(name);
                CREATE INDEX IF NOT EXISTS packages_synopsis_idx ON packages(synopsis);
                CREATE TABLE IF NOT EXISTS metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                """
            )
            connection.execute("PRAGMA user_version=1")
            connection.execute(
                "INSERT INTO metadata(key,value) VALUES('schema_version','1') "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value"
            )
            check = [row[0] for row in connection.execute("PRAGMA quick_check").fetchall()]
            if check != ["ok"]:
                raise PolicyError("catalog database failed SQLite quick_check")
        os.chmod(self.path, 0o600)

    def _connection(self) -> sqlite3.Connection:
        # Only lifecycle admission is serialized. Every operation receives a
        # short-lived SQLite connection so WAL-backed reads can run concurrently
        # while writes and checkpoints retain the explicit process-local lock.
        with self._lock:
            if self._closed:
                raise PolicyError("catalog cache is closed")
        connection = sqlite3.connect(self.path, timeout=5.0)
        try:
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("PRAGMA synchronous=FULL")
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute("PRAGMA trusted_schema=OFF")
            connection.execute("PRAGMA busy_timeout=5000")
            connection.execute("PRAGMA wal_autocheckpoint=1000")
            connection.execute("PRAGMA temp_store=MEMORY")
            return connection
        except BaseException:
            connection.close()
            raise

    def close(self) -> None:
        with self._lock:
            self._closed = True

    @staticmethod
    def _rows(records: Iterable[Mapping[str, Any]], *, updated_unix: int) -> list[tuple[Any, ...]]:
        if type(updated_unix) is not int or updated_unix < 0:
            raise PolicyError("catalog update timestamp is invalid")
        rows = []
        for record in records:
            name = str(record.get("name", ""))
            version = str(record.get("version", ""))
            output = str(record.get("output", "out"))
            validate_package_spec(f"{name}@{version}:{output}")
            rows.append((
                name, version, output,
                str(record.get("synopsis", ""))[:2048],
                str(record.get("description", ""))[:65536],
                str(record.get("location", ""))[:4096],
                updated_unix,
            ))
        if len(rows) > MAX_CACHE_ROWS:
            raise PolicyError("catalog exceeds the bounded row count")
        return rows

    def replace_packages(self, records: Iterable[Mapping[str, Any]], *, updated_unix: int) -> int:
        rows = self._rows(records, updated_unix=updated_unix)
        with self._lock, contextlib.closing(self._connection()) as connection, connection:
            connection.execute("DELETE FROM packages")
            connection.executemany(
                "INSERT INTO packages(name,version,output,synopsis,description,location,updated_unix) "
                "VALUES(?,?,?,?,?,?,?)", rows,
            )
            connection.execute(
                "INSERT INTO metadata(key,value) VALUES('updated_unix',?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (str(updated_unix),),
            )
        return len(rows)

    def upsert_packages(self, records: Iterable[Mapping[str, Any]], *, updated_unix: int) -> int:
        """Merge bounded query results without discarding other cached searches."""
        rows = self._rows(records, updated_unix=updated_unix)
        with self._lock, contextlib.closing(self._connection()) as connection, connection:
            connection.executemany(
                "INSERT INTO packages(name,version,output,synopsis,description,location,updated_unix) "
                "VALUES(?,?,?,?,?,?,?) "
                "ON CONFLICT(name,version,output) DO UPDATE SET "
                "synopsis=excluded.synopsis,description=excluded.description,"
                "location=excluded.location,updated_unix=excluded.updated_unix",
                rows,
            )
            connection.execute(
                "INSERT INTO metadata(key,value) VALUES('updated_unix',?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (str(updated_unix),),
            )
        return len(rows)

    @staticmethod
    def _like_escape(query: str) -> str:
        return query.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")

    def search(self, query: str, *, limit: int = 100, offset: int = 0) -> list[dict[str, Any]]:
        query = validate_query(query)
        if type(limit) is not int or not 1 <= limit <= 500:
            raise PolicyError("search limit is outside the bounded range")
        if type(offset) is not int or not 0 <= offset <= MAX_CACHE_ROWS:
            raise PolicyError("search offset is outside the bounded range")
        escaped = self._like_escape(query)
        pattern = f"%{escaped}%"
        prefix = f"{escaped}%"
        with contextlib.closing(self._connection()) as connection:
            rows = connection.execute(
                "SELECT name,version,output,synopsis,description,location,updated_unix "
                "FROM packages WHERE name LIKE ? ESCAPE '\\' OR synopsis LIKE ? ESCAPE '\\' "
                "ORDER BY CASE WHEN name = ? THEN 0 WHEN name LIKE ? ESCAPE '\\' THEN 1 ELSE 2 END, "
                "name, version LIMIT ? OFFSET ?",
                (pattern, pattern, query, prefix, limit, offset),
            ).fetchall()
        return [dict(row) for row in rows]

    def updated_unix(self) -> int | None:
        with contextlib.closing(self._connection()) as connection:
            row = connection.execute(
                "SELECT value FROM metadata WHERE key='updated_unix'"
            ).fetchone()
        return int(row[0]) if row else None


    def verify_integrity(self) -> dict[str, Any]:
        """Run bounded SQLite integrity checks and return cache statistics."""
        with contextlib.closing(self._connection()) as connection:
            check = [row[0] for row in connection.execute("PRAGMA quick_check").fetchall()]
            if check != ["ok"]:
                raise PolicyError("catalog database failed SQLite quick_check")
            user_version = int(connection.execute("PRAGMA user_version").fetchone()[0])
            if user_version != 1:
                raise PolicyError("catalog database schema version is unsupported")
            schema = connection.execute(
                "SELECT value FROM metadata WHERE key='schema_version'"
            ).fetchone()
            if schema is None or schema[0] != "1":
                raise PolicyError("catalog database schema metadata is missing")
            package_count = int(connection.execute("SELECT COUNT(*) FROM packages").fetchone()[0])
            if package_count > MAX_CACHE_ROWS:
                raise PolicyError("catalog database row count exceeds policy")
            updated = connection.execute(
                "SELECT value FROM metadata WHERE key='updated_unix'"
            ).fetchone()
        return {
            "quick_check": "ok",
            "schema_version": user_version,
            "package_count": package_count,
            "updated_unix": int(updated[0]) if updated else None,
        }

    def checkpoint(self) -> dict[str, int]:
        """Checkpoint WAL state, fsync the database, and fsync its directory."""
        with self._lock, contextlib.closing(self._connection()) as connection:
            row = connection.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
            if row is None or len(row) != 3:
                raise PolicyError("catalog WAL checkpoint did not return a canonical result")
            result = {
                "busy": int(row[0]),
                "log_frames": int(row[1]),
                "checkpointed_frames": int(row[2]),
            }
            if result["busy"] != 0:
                raise PolicyError("catalog WAL checkpoint is busy")
        descriptor = os.open(
            self.path, os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
        )
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                raise PolicyError("catalog database identity is unsafe during checkpoint")
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        directory = os.open(
            self.path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
        )
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        return result

    def statistics(self) -> dict[str, Any]:
        value = self.verify_integrity()
        try:
            value["database_bytes"] = self.path.stat().st_size
        except OSError as error:
            raise PolicyError("catalog database size cannot be measured") from error
        return value


def parse_guix_search_records(text: str) -> list[dict[str, str]]:
    if not isinstance(text, str) or len(text.encode("utf-8")) > MAX_OUTPUT_BYTES:
        raise PolicyError("Guix search output exceeds the bounded size")
    records: list[dict[str, str]] = []
    current: dict[str, str] = {}
    active_key: str | None = None
    for raw_line in text.splitlines() + [""]:
        if not raw_line.strip():
            if current:
                if "name" not in current or "version" not in current:
                    raise PolicyError("Guix search record lacks name or version")
                current.setdefault("output", "out")
                current.setdefault("synopsis", "")
                current.setdefault("description", "")
                current.setdefault("location", "")
                validate_package_spec(
                    f"{current['name']}@{current['version']}:{current['output']}"
                )
                records.append(current)
                current = {}
                active_key = None
            continue
        match = re.match(r"^([a-z][a-z-]*):\s?(.*)$", raw_line)
        if match:
            active_key = match.group(1)
            if active_key in current:
                raise PolicyError("duplicate field in Guix search record")
            current[active_key] = match.group(2)
        elif (raw_line.startswith(" ") or raw_line.startswith("+ ")) and active_key:
            # Real guix prefixes continuation lines with '+ '.
            current[active_key] += "\n" + raw_line.strip()
        else:
            raise PolicyError("unrecognized Guix search output")
    return records


def parse_installed_packages(text: str) -> list[dict[str, str]]:
    if not isinstance(text, str) or len(text.encode("utf-8")) > MAX_OUTPUT_BYTES:
        raise PolicyError("installed-package output exceeds the bounded size")
    records = []
    for line in text.splitlines():
        if not line.strip():
            continue
        parts = line.split("\t")
        if len(parts) != 4:
            raise PolicyError("installed-package row must have four tab-separated fields")
        name, version, output, path = parts
        validate_package_spec(f"{name}@{version}:{output}")
        if not path.startswith("/gnu/store/"):
            raise PolicyError("installed package path is outside the Guix Store")
        records.append({"name": name, "version": version, "output": output, "path": path})
    return records


def phase36_selftest() -> dict[str, Any]:
    contract = guix_center_contract()
    parse_guix_center_contract(contract)
    rejected = 0
    for mutate in (
        lambda value: value["execution"].__setitem__("shell_allowed", True),
        lambda value: value["guix_semantics"].__setitem__("root_escalation_allowed", True),
        lambda value: value["guix_semantics"].__setitem__("typed_confirmation_required_for_mutations", False),
        lambda value: value["execution"].__setitem__("receipt_log_sha256_required", False),
        lambda value: value.__setitem__("production_dispatch_allowed", True),
        lambda value: value["product"].__setitem__("gnome_session_dependency_required", True),
    ):
        value = json.loads(json.dumps(contract))
        mutate(value)
        try:
            parse_guix_center_contract(value)
        except PolicyError:
            rejected += 1
        else:
            raise AssertionError("Phase 36 contract mutation unexpectedly accepted")
    return {
        "status": STATUS,
        "contract_digest": guix_center_contract_digest(),
        "pages": list(PAGES),
        "actions": list(ACTIONS),
        "executable_actions": list(EXECUTABLE_ACTIONS),
        "disabled_actions": list(DISABLED_ACTIONS),
        "negative_cases_rejected": rejected,
        "production_gates_approved": 0,
        "production_dispatch_allowed": False,
        "iso_release_allowed": False,
        "blockers": list(BLOCKERS),
    }
