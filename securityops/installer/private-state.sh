#!/run/current-system/profile/bin/bash -p
# CodeMark v1 project=4c63e0fe-589c-4944-8449-97e211a38b72 file=a494c7d4c2b75495b6b9d1989c7c2c51 owner="Cristian Cezar Mois\u00e9s"
# private-state.sh -- fail-closed runtime-file helpers for security-ops-install
# SPDX-License-Identifier: AGPL-3.0-or-later

# This file is sourced by security-ops-install.  Keep it side-effect free so the
# path checks can also be exercised directly by adversarial unit tests.

securityops_trusted_setuid_sudo() {
    local candidate=/run/privileged/bin/sudo metadata directory

    [[ -f "$candidate" && ! -L "$candidate" && -x "$candidate" && -u "$candidate" ]] || return 1
    [[ "$(/run/current-system/profile/bin/readlink -f -- "$candidate")" == "$candidate" ]] || return 1
    metadata=$(/run/current-system/profile/bin/stat -Lc '%u:%g:%a' -- "$candidate") || return 1
    [[ "$metadata" == 0:0:4555 || "$metadata" == 0:0:4755 ]] || return 1
    for directory in /run /run/privileged /run/privileged/bin; do
        [[ -d "$directory" && ! -L "$directory" ]] || return 1
        metadata=$(/run/current-system/profile/bin/stat -Lc '%u:%g:%a' -- "$directory") || return 1
        [[ "$metadata" =~ ^0:0:[0-7]{3,4}$ ]] || return 1
        metadata=${metadata##*:}
        (( (8#$metadata & 8#022) == 0 )) || return 1
    done
    printf '%s\n' "$candidate"
}

securityops_verify_flock_supervisor() {
    local lock_file=${1:-} trusted_flock=${2:-} trusted_python=${3:-}
    local parent_pid=${4:-$PPID} parent_executable lock_identity

    [[ "$parent_pid" =~ ^[1-9][0-9]*$ ]] || return 1
    parent_executable=$(/run/current-system/profile/bin/readlink -f -- \
        "/proc/$parent_pid/exe" 2>/dev/null) || return 1
    [[ "$parent_executable" == "$trusted_flock" ]] || return 1
    [[ -f "$lock_file" && ! -L "$lock_file" ]] || return 1
    lock_identity=$("$trusted_python" -I -S -c '
import os, sys
metadata = os.stat(sys.argv[1], follow_symlinks=False)
print(f"{os.major(metadata.st_dev):02x}:{os.minor(metadata.st_dev):02x}:{metadata.st_ino}")
' "$lock_file") || return 1
    # /proc/locks identifies a BSD flock by owning PID and filesystem
    # major:minor:inode.  Requiring all fields binds the marker to the *direct*
    # supervisor holding this exact root-private lock.  Mere contention from a
    # different installer cannot be misused as authorization.
    awk -v owner="$parent_pid" -v identity="$lock_identity" '
        $2 == "FLOCK" && $3 == "ADVISORY" && $4 == "WRITE" &&
        $5 == owner && $6 == identity { found = 1 }
        END { exit(found ? 0 : 1) }
    ' /proc/locks
}

securityops_resolve_store_path() {
    local requested=${1:-} expected_type=${2:-} resolved metadata owner mode parent
    local store_relative store_item

    [[ "$requested" == /* ]] || {
        echo "private-state: trusted path must be absolute" >&2
        return 1
    }
    case "$expected_type" in
        executable|regular|directory) ;;
        *)
            echo "private-state: unsupported trusted-path type" >&2
            return 1
            ;;
    esac

    resolved=$(/run/current-system/profile/bin/readlink -f -- "$requested") || return 1
    case "$resolved" in
        /gnu/store/*) ;;
        *)
            echo "private-state: trusted path is not in an immutable store item" >&2
            return 1
            ;;
    esac
    store_relative=${resolved#/gnu/store/}
    store_item=${store_relative%%/*}
    [[ "$store_item" =~ ^[0-9abcdfghijklmnpqrsvwxyz]{32}-.+$ ]] || {
        echo "private-state: malformed Guix store item name" >&2
        return 1
    }
    [[ ! -L "$resolved" ]] || return 1
    if [[ "$expected_type" == executable ]]; then
        [[ -f "$resolved" && -x "$resolved" ]] || return 1
    elif [[ "$expected_type" == regular ]]; then
        [[ -f "$resolved" ]] || return 1
    else
        [[ -d "$resolved" ]] || return 1
    fi

    metadata=$(/run/current-system/profile/bin/stat -Lc '%u:%a' -- "$resolved") || return 1
    owner=${metadata%%:*}
    mode=${metadata#*:}
    [[ "$owner" == 0 && "$mode" =~ ^[0-7]{3,4}$ ]] || return 1
    (( (8#$mode & 8#022) == 0 )) || {
        echo "private-state: trusted store path is group/world writable" >&2
        return 1
    }

    # /gnu/store itself is daemon-managed and intentionally group-writable on
    # Guix System.  Everything from the immutable item root down must be owned
    # by root and non-writable by group/other.
    parent=${resolved%/*}
    while [[ "$parent" == /gnu/store/* ]]; do
        metadata=$(/run/current-system/profile/bin/stat -Lc '%u:%a' -- "$parent") || return 1
        owner=${metadata%%:*}
        mode=${metadata#*:}
        [[ "$owner" == 0 && "$mode" =~ ^[0-7]{3,4}$ ]] || return 1
        (( (8#$mode & 8#022) == 0 )) || {
            echo "private-state: trusted store parent is group/world writable" >&2
            return 1
        }
        parent=${parent%/*}
    done
    [[ "$parent" == /gnu/store ]] || return 1
    printf '%s\n' "$resolved"
}

securityops_private_directory() {
    local directory=${1:-} metadata expected

    [[ "$directory" == /* && "$directory" != / ]] || {
        echo "private-state: runtime directory must be an absolute non-root path" >&2
        return 1
    }
    [[ ! -L "$directory" ]] || {
        echo "private-state: refusing symlink runtime directory: $directory" >&2
        return 1
    }

    if [[ ! -e "$directory" ]]; then
        (umask 077; mkdir -- "$directory") || return 1
    fi

    [[ -d "$directory" && ! -L "$directory" ]] || {
        echo "private-state: runtime path is not a directory: $directory" >&2
        return 1
    }
    metadata=$(stat -c '%u:%g:%a' -- "$directory") || return 1
    expected="${EUID}:${EGID}:700"
    [[ "$metadata" == "$expected" ]] || {
        echo "private-state: unsafe runtime directory metadata: $metadata (expected $expected)" >&2
        return 1
    }
}

securityops_private_tempfile() {
    local directory=${1:-} prefix=${2:-} path metadata

    securityops_private_directory "$directory" || return 1
    [[ "$prefix" =~ ^[a-z0-9][a-z0-9-]{0,31}$ ]] || {
        echo "private-state: unsafe private-file prefix" >&2
        return 1
    }

    path=$(umask 077; mktemp -- "$directory/$prefix.XXXXXX") || return 1
    if [[ -L "$path" || ! -f "$path" ]]; then
        rm -f -- "$path"
        echo "private-state: mktemp did not create a regular file" >&2
        return 1
    fi
    metadata=$(stat -c '%u:%g:%a' -- "$path") || {
        rm -f -- "$path"
        return 1
    }
    if [[ "$metadata" != "${EUID}:${EGID}:600" ]]; then
        rm -f -- "$path"
        echo "private-state: unsafe private-file metadata: $metadata" >&2
        return 1
    fi
    printf '%s\n' "$path"
}

securityops_valid_hostname() {
    local value=${1-}
    local LC_ALL=C

    [[ "$value" =~ ^[A-Za-z0-9][A-Za-z0-9-]{0,62}$ ]]
}

securityops_valid_username() {
    local value=${1-}
    local LC_ALL=C

    [[ "$value" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]]
}

securityops_valid_gecos() {
    local value=${1-} trusted_python=${2:-}

    [[ -x "$trusted_python" ]] || return 1
    # The GECOS value becomes one colon-delimited /etc/passwd field.  Send it
    # over stdin (never argv) to isolated Python so Unicode C0/C1, format,
    # surrogate, private-use, and unassigned control categories are rejected
    # consistently in every live locale.  Bound both code points and UTF-8
    # bytes before the disk is touched.
    printf '%s' "$value" | "$trusted_python" -I -S -c '
import sys, unicodedata
value = sys.stdin.read()
valid = (
    len(value) <= 128
    and len(value.encode("utf-8")) <= 512
    and ":" not in value
    and all(not unicodedata.category(character).startswith("C") for character in value)
)
raise SystemExit(0 if valid else 1)
'
}

securityops_password_meets_policy() {
    local value=${1-} minimum=${2:-} maximum=${3:-}
    local username=${4-} hostname=${5-} byte_length first remainder lower
    local LC_ALL=C

    [[ "$minimum" =~ ^[0-9]+$ && "$maximum" =~ ^[0-9]+$ ]] || return 1
    byte_length=${#value}
    (( byte_length >= minimum && byte_length <= maximum )) || return 1
    [[ ! "$value" =~ [[:cntrl:]] ]] || return 1

    lower=${value,,}
    [[ -z "$username" || "$lower" != "${username,,}" ]] || return 1
    [[ -z "$hostname" || "$lower" != "${hostname,,}" ]] || return 1
    case "$lower" in
        password|password123|changeme|letmein|qwerty|securityops|securityops123)
            return 1 ;;
    esac

    # Reject one-character repetition ("aaaaaaaa...") and the most common
    # keyboard/counting sequences.  This is intentionally a small deterministic
    # gate, not a claim of entropy estimation or password-strength scoring.
    first=${value:0:1}
    remainder=${value//"$first"/}
    [[ -n "$remainder" ]] || return 1
    case "$lower" in
        *1234567890*|*0987654321*|*abcdefgh*|*qwertyuiop*|*asdfghjkl*|*zxcvbnm*)
            return 1 ;;
    esac
}

securityops_printable_us_ascii_secret() {
    local value=${1-} minimum=${2:-} maximum=${3:-} byte_length
    local LC_ALL=C

    [[ "$minimum" =~ ^[0-9]+$ && "$maximum" =~ ^[0-9]+$ ]] || return 1
    byte_length=${#value}
    (( byte_length >= minimum && byte_length <= maximum )) || return 1
    # A byte-level, locale-independent set reproducible in the live TUI, VT,
    # PAM, and GRUB.  It excludes DEL, C0/C1, Unicode format characters, and
    # pasted bytes that firmware/early boot cannot reliably reproduce.
    [[ "$value" =~ ^[\ -~]+$ ]]
}

securityops_admin_password_meets_policy() {
    local value=${1-} username=${2-} hostname=${3-}

    securityops_printable_us_ascii_secret "$value" 12 128 &&
        securityops_password_meets_policy "$value" 12 128 "$username" "$hostname"
}

securityops_luks_passphrase_meets_policy() {
    local value=${1-} username=${2-} hostname=${3-}

    # Pinned GRUB 2.14 supplies a 256-byte buffer to grub_password_get; its
    # terminator/editing reserve makes 254 input bytes the exact ceiling.
    securityops_printable_us_ascii_secret "$value" 20 254 &&
        securityops_password_meets_policy "$value" 20 254 "$username" "$hostname"
}

securityops_valid_partition_geometry() {
    local disk_bytes=${1:-} p1_start=${2:-} p1_size=${3:-} p1_type=${4:-}
    local p2_start=${5:-} p2_size=${6:-} p2_type=${7:-}
    local efi_type=c12a7328-f81f-11d2-ba4b-00a0c93ec93b
    local linux_type=0fc63daf-8483-4772-8e79-3d69d8477de4
    local p2_end remaining

    [[ "$disk_bytes" =~ ^[0-9]+$ && "$p1_start" =~ ^[0-9]+$ &&
       "$p1_size" =~ ^[0-9]+$ && "$p2_start" =~ ^[0-9]+$ &&
       "$p2_size" =~ ^[0-9]+$ ]] || return 1
    [[ "${p1_type,,}" == "$efi_type" && "${p2_type,,}" == "$linux_type" ]] || return 1
    (( p1_start == 1024 * 1024 )) || return 1
    (( p1_size == 512 * 1024 * 1024 )) || return 1
    (( p2_start == 513 * 1024 * 1024 )) || return 1
    (( p2_size >= 60 * 1024 * 1024 * 1024 )) || return 1
    p2_end=$((p2_start + p2_size))
    (( p2_end <= disk_bytes )) || return 1
    remaining=$((disk_bytes - p2_end))
    # Allow only the GPT backup header/alignment tail, never a stale undersized
    # second partition from an earlier table.
    (( remaining <= 2 * 1024 * 1024 )) || return 1
}

securityops_same_disk_identity() {
    local original_path=${1:-} original_major_minor=${2:-}
    local original_sysfs=${3:-} original_size=${4:-}
    local original_diskseq=${5:-} original_wwn=${6-} original_serial=${7-}
    local current_path=${8:-} current_type=${9:-} current_major_minor=${10:-}
    local current_sysfs=${11:-} current_size=${12:-}
    local current_diskseq=${13:-} current_wwn=${14-} current_serial=${15-}

    [[ "$original_path" == /dev/* && "$current_path" == /dev/* ]] || return 1
    [[ "$original_major_minor" =~ ^[0-9]+:[0-9]+$ &&
       "$current_major_minor" =~ ^[0-9]+:[0-9]+$ &&
       "$original_size" =~ ^[0-9]+$ && "$current_size" =~ ^[0-9]+$ &&
       "$original_diskseq" =~ ^[0-9]+$ && "$current_diskseq" =~ ^[0-9]+$ ]] || return 1
    [[ "$current_type" == disk && "$current_path" == "$original_path" &&
       "$current_major_minor" == "$original_major_minor" &&
       "$current_sysfs" == "$original_sysfs" &&
       "$current_size" == "$original_size" &&
       "$current_diskseq" == "$original_diskseq" &&
       "$current_wwn" == "$original_wwn" &&
       "$current_serial" == "$original_serial" ]]
}
