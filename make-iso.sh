#!/usr/bin/env bash
# Build and verify a reproducible Security Ops OS ISO with one command.
set -Eeuo pipefail

cd "$(dirname "$0")"

usage() {
    cat <<'EOF'
Usage: ./make-iso.sh [--bundle] [--prune-old] [--jobs N] [--cores N]

Build the ISO through the exact channels.scm graph using Security Ops first and
GNU Guix CI second, then verify its SHA-256 sidecar.

  --bundle  also create verified 1900 MiB release parts under out/
  --prune-old
            after success, remove older local ISOs and release bundles
  --jobs N  allow at most N parallel Guix build jobs
  --cores N allow each Guix build job to use at most N cores
  -h, --help
            show this help
EOF
}

make_bundle=false
prune_old=false
build_resource_args=()
while (($#)); do
    case "$1" in
        --bundle) make_bundle=true ;;
        --prune-old) prune_old=true ;;
        --jobs|--cores)
            option=$1
            [[ $# -ge 2 && "$2" =~ ^[1-9][0-9]*$ ]] || {
                echo "error: $option requires a positive integer" >&2
                exit 2
            }
            build_resource_args+=("$option" "$2")
            shift
            ;;
        -h|--help) usage; exit 0 ;;
        *) usage >&2; exit 2 ;;
    esac
    shift
done

for command_name in awk cat cmp df find flock git guile guix mktemp mv python3 \
    rm sha256sum split stat; do
    command -v "$command_name" >/dev/null 2>&1 || {
        echo "error: required command not found: $command_name" >&2
        exit 1
    }
done
[[ -f securityopsctl && ! -L securityopsctl && -x securityopsctl ]] || {
    echo "error: securityopsctl must be a regular executable file" >&2
    exit 1
}

out_dir="$PWD/out"
[[ ! -L "$out_dir" ]] || {
    echo "error: refusing symbolic-link output directory: $out_dir" >&2
    exit 1
}
mkdir -p "$out_dir"

# Do not allow two multi-gigabyte builds to compete for the same out/ tree.
lock_file="$out_dir/.iso-build.lock"
[[ ! -L "$lock_file" ]] || {
    echo "error: refusing symlink build lock: $lock_file" >&2
    exit 1
}
if [[ "${SECURITYOPS_ISO_LOCK_HELD:-0}" == 1 &&
      -n "${SECURITYOPS_ISO_LOCK_FD:-}" ]]; then
    inherited_lock_fd=$SECURITYOPS_ISO_LOCK_FD
    [[ "$inherited_lock_fd" =~ ^([3-9]|[1-9][0-9]+)$ ]] || {
        echo "error: inherited build lock descriptor is invalid" >&2
        exit 1
    }
    command -v readlink >/dev/null 2>&1 || {
        echo "error: required command not found: readlink" >&2
        exit 1
    }
    inherited_lock=$(readlink -f "/proc/$$/fd/$inherited_lock_fd" 2>/dev/null || true)
    expected_lock=$(readlink -f "$lock_file" 2>/dev/null || true)
    [[ -n "$inherited_lock" && "$inherited_lock" == "$expected_lock" ]] || {
        echo "error: inherited build lock descriptor is missing or invalid" >&2
        exit 1
    }
    flock -n "$inherited_lock_fd" || {
        echo "error: inherited Security Ops ISO build lock is not held" >&2
        exit 1
    }
    exec 9>&"$inherited_lock_fd"
else
    exec 9>>"$lock_file"
    [[ ! -L "$lock_file" ]] || {
        echo "error: build lock became a symlink: $lock_file" >&2
        exit 1
    }
    flock -n 9 || {
        echo "error: another Security Ops ISO build is already running" >&2
        exit 1
    }
fi

result_file=$(mktemp "$out_dir/.make-iso-result.XXXXXX")
bundle_tmp=""
cleanup() {
    rm -f -- "$result_file"
    if [[ -n "$bundle_tmp" && -d "$bundle_tmp" && ! -L "$bundle_tmp" &&
          "$bundle_tmp" == "$out_dir"/.securityops-live-*-release.* ]]; then
        rm -rf -- "$bundle_tmp"
    fi
}
trap cleanup EXIT

echo ">> Preflight: settings adapter, shell syntax, and patch whitespace"
bash -n build.sh make-iso.sh \
    securityops/installer/gen-config.sh \
    securityops/installer/security-ops-install
./securityopsctl validate
git diff --check

echo ">> Reproducible build: pinned channels, Security Ops + GNU Guix CI"
exec 8>"$result_file"
SECURITYOPS_ISO_LOCK_HELD=1 SECURITYOPS_ISO_RESULT_FD=8 \
    ./build.sh --pinned "${build_resource_args[@]}"
exec 8>&-

mapfile -t images <"$result_file"
if [[ ${#images[@]} -ne 1 || -z "${images[0]}" ]]; then
    echo "error: build did not report exactly one ISO" >&2
    exit 1
fi

iso=${images[0]}
[[ "$iso" == "$out_dir"/securityops-live-*.iso && -f "$iso" && ! -L "$iso" ]] || {
    echo "error: build reported an invalid ISO path: $iso" >&2
    exit 1
}
iso_name=${iso##*/}
sidecar="$iso.sha256"
[[ -s "$sidecar" ]] || {
    echo "error: missing checksum sidecar: $sidecar" >&2
    exit 1
}

echo ">> Verifying full ISO checksum"
(cd "$out_dir" && sha256sum -c "$iso_name.sha256")
iso_hash=$(sha256sum "$iso" | awk '{print $1}')
iso_size=$(stat -c '%s' "$iso")

if $make_bundle; then
    bundle_dir="$out_dir/${iso_name%.iso}-release"
    [[ ! -e "$bundle_dir" ]] || {
        echo "error: release bundle already exists: $bundle_dir" >&2
        exit 1
    }

    available_bytes=$(df -PB1 "$out_dir" | awk 'END {print $4}')
    required_bytes=$((iso_size + 536870912))
    [[ "$available_bytes" =~ ^[0-9]+$ ]] || {
        echo "error: could not determine free space for release bundle" >&2
        exit 1
    }
    (( available_bytes >= required_bytes )) || {
        echo "error: release bundle needs at least $required_bytes free bytes; only $available_bytes available" >&2
        exit 1
    }

    bundle_tmp=$(mktemp -d \
        "$out_dir/.${iso_name%.iso}-release.XXXXXX")

    echo ">> Creating 1900 MiB release parts"
    split -b 1900M -d -a 2 -- "$iso" "$bundle_tmp/$iso_name.part"
    (
        cd "$bundle_tmp"
        sha256sum "$iso_name".part?? > SHA256SUMS.parts
        sha256sum -c SHA256SUMS.parts
    )

    part_count=0
    while IFS= read -r -d '' part; do
        ((part_count += 1))
        part_size=$(stat -c '%s' "$part")
        (( part_size < 2147483648 )) || {
            echo "error: release part is not below 2 GiB: $part" >&2
            exit 1
        }
    done < <(find "$bundle_tmp" -maxdepth 1 -type f -name '*.part??' -print0)
    (( part_count > 0 )) || {
        echo "error: split produced no release parts" >&2
        exit 1
    }

    echo ">> Verifying byte-for-byte part reassembly"
    cat "$bundle_tmp/$iso_name".part?? | cmp - "$iso"
    mv -n -T -- "$bundle_tmp" "$bundle_dir"
    [[ ! -e "$bundle_tmp" && -d "$bundle_dir" ]] || {
        echo "error: could not publish release bundle without replacing a directory" >&2
        exit 1
    }
    bundle_tmp=""
    printf '>> Release bundle: %s\n' "$bundle_dir"
fi

if $prune_old; then
    echo ">> Pruning older local Security Ops ISO artifacts"
    while IFS= read -r -d '' old_artifact; do
        [[ "$old_artifact" != "$iso" && "$old_artifact" != "$sidecar" ]] || continue
        if $make_bundle && [[ "$old_artifact" == "$bundle_dir" ]]; then
            continue
        fi
        old_name=${old_artifact##*/}
        if [[ -f "$old_artifact" && ! -L "$old_artifact" ]]; then
            [[ "$old_name" =~ ^(securityops|securityos)-live-[0-9]{8}-[0-9]{6}(-[0-9a-f]{12})?\.iso(\.sha256)?$ ]] || continue
        elif [[ -d "$old_artifact" && ! -L "$old_artifact" ]]; then
            [[ "$old_name" =~ ^(securityops|securityos)-live-[0-9]{8}-[0-9]{6}(-[0-9a-f]{12})?-release$ ]] || continue
        else
            continue
        fi
        printf '   removing %s\n' "$old_artifact"
        if [[ -d "$old_artifact" ]]; then
            rm -rf -- "$old_artifact"
        else
            rm -f -- "$old_artifact"
        fi
    done < <(
        find "$out_dir" -mindepth 1 -maxdepth 1 \
            \( \( -type f \
                   \( -name 'securityops-live-*.iso' \
                      -o -name 'securityops-live-*.iso.sha256' \
                      -o -name 'securityos-live-*.iso' \
                      -o -name 'securityos-live-*.iso.sha256' \) \) \
               -o \( -type d \
                   \( -name 'securityops-live-*-release' \
                      -o -name 'securityos-live-*-release' \) \) \) -print0
    )
fi

printf '\nISO:     %s\n' "$iso"
printf 'Bytes:   %s\n' "$iso_size"
printf 'SHA-256: %s\n' "$iso_hash"
printf 'Status:  verified\n'
