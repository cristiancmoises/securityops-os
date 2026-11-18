#!/usr/bin/env python3
# CodeMark v1 project=4c63e0fe-589c-4944-8449-97e211a38b72 file=5555536c215b5541b1f335e69971e7d9 owner="Cristian Cezar Mois\u00e9s"
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-SecurityOps-Commercial
"""Security Ops Installer 2 graphical plan/review front-end.

The GUI intentionally cannot execute a destructive installation until the
booted-image helper supports the signed plan format and the real-disk recovery
matrix has passed.  It provides the complete safe UX boundary now without
pretending that source code is disk-installation evidence.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
from pathlib import Path
import stat
import sys
from typing import Any

PLAN_FORMAT = "securityops-installer2-plan/3"
DISK_IDENTITY_DOMAIN = b"SECURITYOPS-INSTALLER2-DISK-IDENTITY-V2\0"
PLAN_DOMAIN = b"SECURITYOPS-INSTALLER2-PLAN-V3\0"
ALLOWED_DESKTOPS = ("sway", "river", "xmonad-xlibre", "kde-plasma", "xfce", "lxde")

# Human labels for the installer picker; the raw keys stay the validated
# plan values, so a label can never change what the plan accepts.
DESKTOP_LABELS = {
    "sway": "Sway — tiling Wayland (default)",
    "river": "River — dynamic-tiling Wayland",
    "xmonad-xlibre": "XMonad + XLibre — tiling X11",
    "kde-plasma": "KDE Plasma — full desktop (Wayland)",
    "xfce": "XFCE — lightweight X11",
    "lxde": "LXDE — very lightweight X11",
}
ALLOWED_FILESYSTEMS = ("ext4", "btrfs", "xfs")
BY_ID = Path("/dev/disk/by-id")
DEVICE_ROOT = Path("/dev")
SYS_DEV_BLOCK = Path("/sys/dev/block")
STABLE_DISK_PREFIXES = ("wwn-", "ata-", "nvme-", "scsi-", "virtio-")
IDENTITY_KEYS = frozenset({
    "stable_path",
    "symlink_target",
    "symlink_device",
    "symlink_inode",
    "symlink_uid",
    "symlink_gid",
    "symlink_mode",
    "symlink_ctime_ns",
    "resolved_target",
    "target_node_device",
    "target_node_inode",
    "target_node_uid",
    "target_node_gid",
    "target_node_mode",
    "target_node_ctime_ns",
    "block_major",
    "block_minor",
    "major_minor",
    "diskseq",
    "partition",
    "whole_disk",
    "kernel_512_byte_sectors",
    "size_bytes",
})
PLAN_KEYS = frozenset({
    "format",
    "disk",
    "disk_identity",
    "disk_identity_digest",
    "filesystem",
    "desktop",
    "encrypted",
    "destructive_operation",
    "stable_disk_identity_verified",
    "target_revalidation_required",
    "recovery_matrix_complete",
    "execution_allowed",
    "production_dispatch_allowed",
    "iso_release_allowed",
    "plan_id",
})


def _canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _bounded_decimal(path: Path, label: str) -> int:
    with path.open("r", encoding="ascii") as stream:
        value = stream.read(65)
    if len(value) > 64 or not value.strip().isascii() or not value.strip().isdigit():
        raise ValueError(f"invalid {label} in kernel block metadata")
    number = int(value.strip(), 10)
    if number > (1 << 64) - 1:
        raise ValueError(f"invalid {label} in kernel block metadata")
    return number


def _sysfs_block_identity(major: int, minor: int) -> dict[str, Any]:
    entry = SYS_DEV_BLOCK / f"{major}:{minor}"

    def entry_token(path: Path) -> tuple[int, ...]:
        metadata = path.stat()
        return (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_mode,
            metadata.st_uid,
            metadata.st_gid,
            metadata.st_ctime_ns,
        )

    def partition_number() -> int | None:
        try:
            return _bounded_decimal(entry / "partition", "partition number")
        except FileNotFoundError:
            return None

    try:
        resolved_before = entry.resolve(strict=True)
        token_before = entry_token(entry)
        if not resolved_before.is_dir():
            raise ValueError("kernel block metadata is not a directory")
        reported_device_before = (entry / "dev").read_text(encoding="ascii").strip()
        partition_before = partition_number()
        diskseq_before = (
            _bounded_decimal(entry / "diskseq", "block-device disk sequence")
            if partition_before is None
            else None
        )
        sectors_before = _bounded_decimal(entry / "size", "block-device size")
        partition_after = partition_number()
        sectors_after = _bounded_decimal(entry / "size", "block-device size")
        diskseq_after = (
            _bounded_decimal(entry / "diskseq", "block-device disk sequence")
            if partition_after is None
            else None
        )
        reported_device_after = (entry / "dev").read_text(encoding="ascii").strip()
        token_after = entry_token(entry)
        resolved_after = entry.resolve(strict=True)
        if reported_device_before != f"{major}:{minor}":
            raise ValueError("kernel block device identity mismatch")
    except (OSError, RuntimeError) as error:
        raise ValueError("kernel block metadata is unavailable") from error
    if (
        resolved_before != resolved_after
        or token_before != token_after
        or reported_device_before != reported_device_after
        or diskseq_before != diskseq_after
        or sectors_before != sectors_after
        or partition_before != partition_after
    ):
        raise ValueError("kernel block metadata changed during measurement")
    sectors = sectors_before
    diskseq = diskseq_before
    partition_number = partition_before
    if sectors <= 0:
        raise ValueError("installation target has no usable capacity")
    if diskseq is not None and diskseq <= 0:
        raise ValueError("installation target has no usable kernel disk sequence")
    if partition_number is not None and partition_number <= 0:
        raise ValueError("invalid partition number in kernel block metadata")
    is_partition = partition_number is not None
    return {
        "block_major": major,
        "block_minor": minor,
        "major_minor": f"{major}:{minor}",
        "diskseq": diskseq,
        "partition": is_partition,
        "whole_disk": not is_partition,
        "kernel_512_byte_sectors": sectors,
        "size_bytes": sectors * 512,
    }


def _metadata_token(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_rdev,
        metadata.st_ctime_ns,
    )


def _link_token(metadata: os.stat_result, target: str) -> tuple[Any, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_ctime_ns,
        target,
    )


def _by_id_directory_token(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_nlink,
        metadata.st_ctime_ns,
    )


def _validated_by_id_directory_metadata(metadata: os.stat_result) -> os.stat_result:
    mode = stat.S_IMODE(metadata.st_mode)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != 0
        or metadata.st_gid != 0
        or mode & 0o7022
    ):
        raise ValueError("/dev/disk/by-id must be a root-owned non-writable directory")
    return metadata


def _validated_by_id_link_metadata(metadata: os.stat_result) -> os.stat_result:
    if (
        not stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != 0
        or metadata.st_gid != 0
        or metadata.st_nlink != 1
        or stat.S_IMODE(metadata.st_mode) != 0o777
    ):
        raise ValueError("stable disk symlink metadata is unsafe")
    return metadata


def _validated_block_device_metadata(metadata: os.stat_result) -> os.stat_result:
    mode = stat.S_IMODE(metadata.st_mode)
    if (
        not stat.S_ISBLK(metadata.st_mode)
        or metadata.st_uid != 0
        or metadata.st_nlink != 1
        or mode & 0o7007
        or mode & 0o600 != 0o600
    ):
        raise ValueError("stable disk block-device metadata is unsafe")
    return metadata


def _open_by_id_directory() -> tuple[int, os.stat_result]:
    if not hasattr(os, "O_DIRECTORY") or not hasattr(os, "O_NOFOLLOW"):
        raise ValueError("descriptor-bound /dev/disk/by-id measurement is unavailable")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    flags |= getattr(os, "O_CLOEXEC", 0)
    try:
        directory_fd = os.open(BY_ID, flags)
    except OSError as error:
        raise ValueError("/dev/disk/by-id cannot be opened safely") from error
    try:
        descriptor_metadata = _validated_by_id_directory_metadata(os.fstat(directory_fd))
        named_metadata = _validated_by_id_directory_metadata(
            os.stat(BY_ID, follow_symlinks=False)
        )
        if _by_id_directory_token(descriptor_metadata) != _by_id_directory_token(named_metadata):
            raise ValueError("/dev/disk/by-id changed while it was opened")
        return directory_fd, descriptor_metadata
    except (OSError, ValueError):
        os.close(directory_fd)
        raise


def _require_by_id_directory_binding(
    directory_fd: int, expected: os.stat_result
) -> None:
    try:
        descriptor_metadata = _validated_by_id_directory_metadata(os.fstat(directory_fd))
        named_metadata = _validated_by_id_directory_metadata(
            os.stat(BY_ID, follow_symlinks=False)
        )
    except OSError as error:
        raise ValueError("/dev/disk/by-id binding is unavailable") from error
    expected_token = _by_id_directory_token(expected)
    if (
        _by_id_directory_token(descriptor_metadata) != expected_token
        or _by_id_directory_token(named_metadata) != expected_token
    ):
        raise ValueError("/dev/disk/by-id changed during disk measurement")


def _candidate_path(disk: str) -> Path:
    if type(disk) is not str:
        raise ValueError("installation target must be a /dev/disk/by-id identity")
    path = Path(disk)
    if (
        str(path) != disk
        or not path.is_absolute()
        or path.parent != BY_ID
        or not path.name.startswith(STABLE_DISK_PREFIXES)
    ):
        raise ValueError("installation target must be a /dev/disk/by-id identity")
    return path


def _measure_by_id_path(path: Path) -> dict[str, Any]:
    path = _candidate_path(os.fspath(path))
    directory_fd, directory_metadata = _open_by_id_directory()
    try:
        try:
            link_before = _validated_by_id_link_metadata(
                os.stat(path.name, dir_fd=directory_fd, follow_symlinks=False)
            )
            link_target_before = os.readlink(path.name, dir_fd=directory_fd)
        except OSError as error:
            raise ValueError("stable disk identity is unavailable") from error
        if not hasattr(os, "O_PATH"):
            raise ValueError("descriptor-only block measurement is unavailable")

        flags = os.O_PATH | getattr(os, "O_CLOEXEC", 0)
        try:
            descriptor = os.open(path.name, flags, dir_fd=directory_fd)
        except OSError as error:
            raise ValueError("stable disk target cannot be opened for measurement") from error
        try:
            target_metadata = _validated_block_device_metadata(os.fstat(descriptor))
        finally:
            os.close(descriptor)

        _require_by_id_directory_binding(directory_fd, directory_metadata)
        try:
            resolved_target = path.resolve(strict=True)
            resolved_metadata = _validated_block_device_metadata(resolved_target.stat())
            if not resolved_target.is_relative_to(DEVICE_ROOT):
                raise ValueError("stable disk target resolves outside /dev")
        except (OSError, RuntimeError) as error:
            raise ValueError("stable disk target cannot be resolved") from error
        if _metadata_token(resolved_metadata) != _metadata_token(target_metadata):
            raise ValueError("stable disk target changed during measurement")

        major = os.major(target_metadata.st_rdev)
        minor = os.minor(target_metadata.st_rdev)
        kernel_identity = _sysfs_block_identity(major, minor)

        try:
            link_after = _validated_by_id_link_metadata(
                os.stat(path.name, dir_fd=directory_fd, follow_symlinks=False)
            )
            link_target_after = os.readlink(path.name, dir_fd=directory_fd)
            verification_descriptor = os.open(path.name, flags, dir_fd=directory_fd)
        except OSError as error:
            raise ValueError("stable disk identity changed during measurement") from error
        try:
            verification_metadata = _validated_block_device_metadata(
                os.fstat(verification_descriptor)
            )
        finally:
            os.close(verification_descriptor)
        _require_by_id_directory_binding(directory_fd, directory_metadata)
        if (
            _link_token(link_before, link_target_before)
            != _link_token(link_after, link_target_after)
            or _metadata_token(target_metadata) != _metadata_token(verification_metadata)
        ):
            raise ValueError("stable disk identity changed during measurement")

        identity = {
            "stable_path": str(path),
            "symlink_target": link_target_before,
            "symlink_device": link_before.st_dev,
            "symlink_inode": link_before.st_ino,
            "symlink_uid": link_before.st_uid,
            "symlink_gid": link_before.st_gid,
            "symlink_mode": stat.S_IMODE(link_before.st_mode),
            "symlink_ctime_ns": link_before.st_ctime_ns,
            "resolved_target": str(resolved_target),
            "target_node_device": target_metadata.st_dev,
            "target_node_inode": target_metadata.st_ino,
            "target_node_uid": target_metadata.st_uid,
            "target_node_gid": target_metadata.st_gid,
            "target_node_mode": stat.S_IMODE(target_metadata.st_mode),
            "target_node_ctime_ns": target_metadata.st_ctime_ns,
        }
        identity.update(kernel_identity)
        return identity
    finally:
        os.close(directory_fd)


def measure_stable_disk(disk: str) -> dict[str, Any]:
    identity = _measure_by_id_path(_candidate_path(disk))
    if identity["partition"] or not identity["whole_disk"]:
        raise ValueError("installation target must be a whole disk, not a partition")
    return identity


def stable_disks() -> list[str]:
    try:
        # A physical device commonly has several by-id aliases (for example
        # WWN and ATA).  Present exactly one deterministic identity per kernel
        # device number so the UI cannot create ambiguous duplicate targets.
        entries_by_device: dict[str, str] = {}
        for path in BY_ID.iterdir():
            if not path.name.startswith(STABLE_DISK_PREFIXES):
                continue
            try:
                identity = _measure_by_id_path(path)
            except (OSError, ValueError):
                continue
            if identity["whole_disk"] and not identity["partition"]:
                candidate = str(path)
                device = identity["major_minor"]
                previous = entries_by_device.get(device)
                if previous is None or candidate < previous:
                    entries_by_device[device] = candidate
        return sorted(entries_by_device.values())
    except OSError:
        return []


def build_plan(*, disk: str, filesystem: str, desktop: str, encrypted: bool) -> dict[str, Any]:
    if filesystem not in ALLOWED_FILESYSTEMS or desktop not in ALLOWED_DESKTOPS:
        raise ValueError("unsupported installation selection")
    if type(encrypted) is not bool:
        raise ValueError("encrypted must be an explicit boolean")
    disk_identity = measure_stable_disk(disk)
    disk_identity_digest = hashlib.sha256(
        DISK_IDENTITY_DOMAIN + _canonical_json(disk_identity)
    ).hexdigest()
    body = {
        "format": PLAN_FORMAT,
        "disk": disk,
        "disk_identity": disk_identity,
        "disk_identity_digest": disk_identity_digest,
        "filesystem": filesystem,
        "desktop": desktop,
        "encrypted": encrypted,
        "destructive_operation": True,
        "stable_disk_identity_verified": True,
        "target_revalidation_required": True,
        "recovery_matrix_complete": False,
        "execution_allowed": False,
        "production_dispatch_allowed": False,
        "iso_release_allowed": False,
    }
    body["plan_id"] = hashlib.sha256(
        PLAN_DOMAIN + _canonical_json(body)
    ).hexdigest()
    return body


def _validated_identity(identity: Any) -> dict[str, Any]:
    if type(identity) is not dict or set(identity) != IDENTITY_KEYS:
        raise ValueError("installer plan has an invalid disk identity")
    string_fields = ("stable_path", "symlink_target", "resolved_target", "major_minor")
    integer_fields = tuple(IDENTITY_KEYS - set(string_fields) - {"partition", "whole_disk"})
    if any(type(identity[field]) is not str for field in string_fields):
        raise ValueError("installer plan has an invalid disk identity")
    if any(type(identity[field]) is not int or identity[field] < 0 for field in integer_fields):
        raise ValueError("installer plan has an invalid disk identity")
    if type(identity["partition"]) is not bool or type(identity["whole_disk"]) is not bool:
        raise ValueError("installer plan has an invalid disk identity")
    if identity["partition"] or not identity["whole_disk"]:
        raise ValueError("installer plan target is not a whole disk")
    if identity["major_minor"] != f'{identity["block_major"]}:{identity["block_minor"]}':
        raise ValueError("installer plan block-device identity is inconsistent")
    if identity["size_bytes"] != identity["kernel_512_byte_sectors"] * 512:
        raise ValueError("installer plan block-device size is inconsistent")
    if identity["kernel_512_byte_sectors"] <= 0:
        raise ValueError("installer plan block-device capacity is invalid")
    if identity["diskseq"] <= 0:
        raise ValueError("installer plan block-device disk sequence is invalid")
    _candidate_path(identity["stable_path"])
    return identity


def revalidate_plan_target(plan: dict[str, Any]) -> dict[str, Any]:
    """Remeasure a plan's target; future destructive helpers must call this last."""
    if type(plan) is not dict or set(plan) != PLAN_KEYS:
        raise ValueError("installer plan shape is invalid")
    if plan["format"] != PLAN_FORMAT:
        raise ValueError("installer plan format is unsupported")
    expected_invariants = {
        "destructive_operation": True,
        "stable_disk_identity_verified": True,
        "target_revalidation_required": True,
        "recovery_matrix_complete": False,
        "execution_allowed": False,
        "production_dispatch_allowed": False,
        "iso_release_allowed": False,
    }
    if any(plan[field] is not expected for field, expected in expected_invariants.items()):
        raise ValueError("installer plan safety boundary is invalid")
    if plan["filesystem"] not in ALLOWED_FILESYSTEMS or plan["desktop"] not in ALLOWED_DESKTOPS:
        raise ValueError("installer plan selection is unsupported")
    if type(plan["encrypted"]) is not bool:
        raise ValueError("installer plan encryption setting is invalid")

    stored_identity = _validated_identity(plan["disk_identity"])
    if plan["disk"] != stored_identity["stable_path"]:
        raise ValueError("installer plan disk path and identity disagree")
    expected_identity_digest = hashlib.sha256(
        DISK_IDENTITY_DOMAIN + _canonical_json(stored_identity)
    ).hexdigest()
    if type(plan["disk_identity_digest"]) is not str or not hmac.compare_digest(
        plan["disk_identity_digest"], expected_identity_digest
    ):
        raise ValueError("installer plan disk identity digest is invalid")

    unsigned_plan = dict(plan)
    supplied_plan_id = unsigned_plan.pop("plan_id")
    expected_plan_id = hashlib.sha256(
        PLAN_DOMAIN + _canonical_json(unsigned_plan)
    ).hexdigest()
    if type(supplied_plan_id) is not str or not hmac.compare_digest(
        supplied_plan_id, expected_plan_id
    ):
        raise ValueError("installer plan identifier is invalid")

    current_identity = measure_stable_disk(plan["disk"])
    current_digest = hashlib.sha256(
        DISK_IDENTITY_DOMAIN + _canonical_json(current_identity)
    ).hexdigest()
    if not hmac.compare_digest(current_digest, expected_identity_digest):
        raise ValueError("installation target changed or installer plan is stale")
    return current_identity


def _validated_private_directory_metadata(metadata: os.stat_result) -> os.stat_result:
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise ValueError("installer state path must be a real directory")
    if metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) != 0o700:
        raise ValueError("installer state directory must be caller-owned mode 0700")
    return metadata


def _private_state_directory(path: Path) -> os.stat_result:
    return _validated_private_directory_metadata(path.lstat())


def _validated_plan_metadata(metadata: os.stat_result) -> os.stat_result:
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o600
    ):
        raise ValueError("published installer plan metadata is unsafe")
    return metadata


def _published_plan_metadata(path: Path) -> os.stat_result:
    return _validated_plan_metadata(path.lstat())


def _directory_identity(metadata: os.stat_result) -> tuple[int, int]:
    return metadata.st_dev, metadata.st_ino


def _require_directory_binding(path: Path, expected: os.stat_result) -> None:
    try:
        current = _private_state_directory(path)
    except OSError as error:
        raise ValueError("installer state directory binding is unavailable") from error
    if _directory_identity(current) != _directory_identity(expected):
        raise ValueError("installer state directory changed during publication")


def _plan_metadata_at(directory_fd: int, name: str) -> os.stat_result | None:
    try:
        metadata = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    except FileNotFoundError:
        return None
    return _validated_plan_metadata(metadata)


def atomic_write(path: Path, value: dict[str, Any]) -> None:
    path = Path(path)
    if not path.is_absolute() or not path.name or ".." in path.parts:
        raise ValueError("installer plan path must be absolute and traversal-free")
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    directory_flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        directory_fd = os.open(path.parent, directory_flags)
    except OSError as error:
        raise ValueError("installer state directory cannot be opened safely") from error

    file_fd = -1
    temporary_name: str | None = None
    published = False
    completed = False
    published_identity: tuple[int, int] | None = None
    try:
        parent_metadata = _validated_private_directory_metadata(os.fstat(directory_fd))
        _require_directory_binding(path.parent, parent_metadata)
        _plan_metadata_at(directory_fd, path.name)

        temporary_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        temporary_flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
        for _attempt in range(128):
            candidate = f".securityops-installer2-{os.urandom(16).hex()}.tmp"
            try:
                file_fd = os.open(
                    candidate,
                    temporary_flags,
                    0o600,
                    dir_fd=directory_fd,
                )
            except FileExistsError:
                continue
            temporary_name = candidate
            break
        if file_fd < 0 or temporary_name is None:
            raise ValueError("cannot allocate a private installer plan temporary file")

        os.fchmod(file_fd, 0o600)
        with os.fdopen(file_fd, "w", encoding="utf-8", closefd=False) as stream:
            json.dump(value, stream, sort_keys=True, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        temporary_metadata = _validated_plan_metadata(os.fstat(file_fd))
        _require_directory_binding(path.parent, parent_metadata)

        os.replace(
            temporary_name,
            path.name,
            src_dir_fd=directory_fd,
            dst_dir_fd=directory_fd,
        )
        temporary_name = None
        published = True
        published_identity = _directory_identity(temporary_metadata)
        final_metadata = _plan_metadata_at(directory_fd, path.name)
        if final_metadata is None or _directory_identity(final_metadata) != published_identity:
            raise ValueError("published installer plan identity changed")
        _require_directory_binding(path.parent, parent_metadata)
        os.fsync(directory_fd)
        _require_directory_binding(path.parent, parent_metadata)
        completed = True
    finally:
        if temporary_name is not None:
            try:
                os.unlink(temporary_name, dir_fd=directory_fd)
            except OSError:
                pass
        if published and not completed and published_identity is not None:
            try:
                current = os.stat(
                    path.name, dir_fd=directory_fd, follow_symlinks=False
                )
                if _directory_identity(current) == published_identity:
                    os.unlink(path.name, dir_fd=directory_fd)
                    os.fsync(directory_fd)
            except OSError:
                pass
        try:
            if file_fd >= 0:
                os.close(file_fd)
        finally:
            os.close(directory_fd)


def run_gui() -> int:
    try:
        import gi
        gi.require_version("Gtk", "4.0")
        from gi.repository import Gtk
    except Exception as error:
        print(f"Security Ops Installer 2 requires GTK 4/PyGObject: {error}", file=sys.stderr)
        return 2

    class Window(Gtk.ApplicationWindow):
        def __init__(self, app: Gtk.Application) -> None:
            super().__init__(application=app, title="Security Ops Installer 2")
            self.set_default_size(980, 680)
            root = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
            root.set_margin_top(24); root.set_margin_bottom(24)
            root.set_margin_start(28); root.set_margin_end(28)
            title = Gtk.Label(label="Install Security Ops OS")
            title.add_css_class("title-1"); title.set_xalign(0)
            subtitle = Gtk.Label(label="Review every storage change before anything destructive can run.")
            subtitle.set_xalign(0); subtitle.add_css_class("dim-label")
            root.append(title); root.append(subtitle)

            grid = Gtk.Grid(column_spacing=18, row_spacing=14)
            self.disk = Gtk.DropDown.new_from_strings(stable_disks() or ["No stable disk identity detected"])
            self.fs = Gtk.DropDown.new_from_strings(list(ALLOWED_FILESYSTEMS))
            self.desktop = Gtk.DropDown.new_from_strings(
                [DESKTOP_LABELS[desktop] for desktop in ALLOWED_DESKTOPS]
            )
            self.encrypted = Gtk.Switch(active=True)
            for row, (label, widget) in enumerate((
                ("Target disk", self.disk), ("Filesystem", self.fs),
                ("Desktop", self.desktop), ("LUKS2 encryption", self.encrypted),
            )):
                field = Gtk.Label(label=label); field.set_xalign(0)
                grid.attach(field, 0, row, 1, 1); grid.attach(widget, 1, row, 1, 1)
            root.append(grid)
            self.review = Gtk.TextView(editable=False, monospace=True, wrap_mode=Gtk.WrapMode.WORD_CHAR)
            self.review.set_vexpand(True)
            scroll = Gtk.ScrolledWindow(); scroll.set_child(self.review); root.append(scroll)
            buttons = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
            preview = Gtk.Button(label="Review installation plan")
            preview.add_css_class("suggested-action"); preview.connect("clicked", self.on_preview)
            apply_button = Gtk.Button(label="Install (blocked until recovery validation)")
            apply_button.set_sensitive(False)
            buttons.append(preview); buttons.append(apply_button); root.append(buttons)
            self.set_child(root)

        def selected(self, dropdown: Gtk.DropDown) -> str:
            item = dropdown.get_selected_item()
            return item.get_string() if item else ""

        def on_preview(self, _button: Gtk.Button) -> None:
            try:
                desktop = self.desktop.get_selected()
                if not isinstance(desktop, int) or not 0 <= desktop < len(ALLOWED_DESKTOPS):
                    raise ValueError("desktop selection is out of range")
                plan = build_plan(
                    disk=self.selected(self.disk), filesystem=self.selected(self.fs),
                    desktop=ALLOWED_DESKTOPS[desktop], encrypted=self.encrypted.get_active(),
                )
                atomic_write(Path.home() / ".local/state/securityops/installer2/plan.json", plan)
                text = json.dumps(plan, sort_keys=True, indent=2)
            except Exception as error:
                text = f"Plan blocked: {error}"
            self.review.get_buffer().set_text(text)

    class App(Gtk.Application):
        def __init__(self) -> None:
            super().__init__(application_id="co.securityops.Installer2")
        def do_activate(self) -> None:
            Window(self).present()

    return App().run(None)


if __name__ == "__main__":
    if "--headless-contract" in sys.argv:
        print(json.dumps({
            "format": PLAN_FORMAT,
            "desktops": list(ALLOWED_DESKTOPS),
            "desktop_labels": DESKTOP_LABELS,
            "stable_disk_identity_required": True,
            "whole_disk_required": True,
            "target_revalidation_required": True,
            "execution_allowed": False,
            "production_dispatch_allowed": False,
            "iso_release_allowed": False,
        }, sort_keys=True, indent=2))
        raise SystemExit(0)
    raise SystemExit(run_gui())
