#!/usr/bin/env bash
# CodeMark v1 project=4c63e0fe-589c-4944-8449-97e211a38b72 file=75bdd6d91f985ffb9ad178dde53f605f owner="Cristian Cezar Mois\u00e9s"
# ===========================================================================
# build.sh — build the Security Ops live ISO
# ===========================================================================
# Produces a hybrid BIOS+UEFI iso9660 image you can drop into your Ventoy USB
# folder and boot on a broad range of x86_64 systems (pick Intel/AMD/auto at
# GRUB); as with any custom image, hardware compatibility is not universal.
#
# Usage:
#   ./build.sh [--pinned] [--jobs N] [--cores N]
#
# Notes
#   * Binary substitutes use Security Ops first (com.br, then the .co build
#     farm), then the official GNU Guix CI.
#     Cache misses fall back to source builds; no other cache is contacted.
#   * Builds are big.  Scratch is sent to /var/tmp (not the 4G tmpfs /tmp).
#   * Run from THIS directory so the (local-file "assets/…") paths resolve.
# ===========================================================================
set -euo pipefail
cd "$(dirname "$0")"
original_args=("$@")

pinned=false
GUIX_RESOURCE_ARGS=()
while (($#)); do
    case "$1" in
        --pinned)
            pinned=true
            shift
            ;;
        --jobs|--cores)
            option=$1
            [[ $# -ge 2 && "$2" =~ ^[1-9][0-9]*$ ]] || {
                echo "error: $option requires a positive integer" >&2
                exit 2
            }
            if [[ "$option" == --jobs ]]; then
                GUIX_RESOURCE_ARGS+=("--max-jobs=$2")
            else
                GUIX_RESOURCE_ARGS+=("--cores=$2")
            fi
            shift 2
            ;;
        -h|--help)
            echo "usage: $0 [--pinned] [--jobs N] [--cores N]"
            exit 0
            ;;
        *)
            echo "usage: $0 [--pinned] [--jobs N] [--cores N]" >&2
            exit 2
            ;;
    esac
done

export TMPDIR=/var/tmp                 # keep multi-GB scratch off tmpfs /tmp
OUT_DIR="$PWD/out"
# Open safely in Python and keep that descriptor across exec; never reopen the
# pathname with shell redirection (which follows symlinks and can block on FIFO).
if [[ "${SECURITYOPS_ISO_LOCK_HELD:-0}" != 1 ]]; then
    exec python3 -I ./securityopsctl _build-lock build.sh "${original_args[@]}"
fi
inherited_lock_fd=${SECURITYOPS_ISO_LOCK_FD:-9}
python3 -I ./securityopsctl _build-lock check "$inherited_lock_fd"
exec 9>&"$inherited_lock_fd"
if [[ "$inherited_lock_fd" != 9 ]]; then exec {inherited_lock_fd}>&-; fi
export SECURITYOPS_ISO_LOCK_FD=9

SUBSTITUTE_URLS="https://substitutes.securityops.com.br https://substitutes.securityops.co https://ci.guix.gnu.org"
GUIX_ARGS=(repl -q -L "$PWD" -- "$PWD/securityops/build-image.scm"
           "$PWD" "${GUIX_RESOURCE_ARGS[@]}")

echo ">> Building Security Ops live ISO (Security Ops farm + GNU Guix CI substitutes)…"
if $pinned; then
    echo ">> Using the exact pinned channels.guix graph via time-machine."
    ISO=$(guix time-machine -C channels.guix \
        "${GUIX_RESOURCE_ARGS[@]}" \
        --substitute-urls="$SUBSTITUTE_URLS" --fallback -- "${GUIX_ARGS[@]}")
else
    echo ">> Using the channels in the current Guix profile."
    ISO=$(guix "${GUIX_ARGS[@]}")
fi

echo ">> Built: $ISO"
# Copy through a private temporary file, then publish under a timestamp + hash
# name.  The hash suffix makes same-second builds collision-proof; mv -n keeps
# the final publication no-clobber and atomic on out/'s filesystem.
partial_iso=$(mktemp "$OUT_DIR/.securityops-live.XXXXXX.iso.partial")
partial_sum=""
published_iso=""
published_sum=""
publication_complete=false
cleanup_partial() {
    [[ -z "$partial_iso" ]] || rm -f -- "$partial_iso"
    [[ -z "$partial_sum" ]] || rm -f -- "$partial_sum"
    if ! $publication_complete; then
        [[ -z "$published_sum" ]] || rm -f -- "$published_sum"
        [[ -z "$published_iso" ]] || rm -f -- "$published_iso"
    fi
}
trap cleanup_partial EXIT

cp -- "$ISO" "$partial_iso"
chmod u+w "$partial_iso"
ISO_HASH=$(sha256sum "$partial_iso" | awk '{print $1}')
STAMP=$(date +%Y%m%d-%H%M%S 2>/dev/null || printf 'image')
DEST="$OUT_DIR/securityops-live-$STAMP-${ISO_HASH:0:12}.iso"
[[ ! -e "$DEST" && ! -L "$DEST" ]] || {
    echo "error: refusing to replace existing ISO: $DEST" >&2
    exit 1
}
mv -n -T -- "$partial_iso" "$DEST"
[[ ! -e "$partial_iso" && -f "$DEST" ]] || {
    echo "error: could not publish ISO without replacing a file" >&2
    exit 1
}
partial_iso=""
published_iso="$DEST"

partial_sum=$(mktemp "$OUT_DIR/.securityops-live.XXXXXX.sha256.partial")
printf '%s  %s\n' "$ISO_HASH" "$(basename "$DEST")" >"$partial_sum"
[[ ! -e "$DEST.sha256" && ! -L "$DEST.sha256" ]] || {
    echo "error: refusing to replace existing checksum: $DEST.sha256" >&2
    exit 1
}
mv -n -T -- "$partial_sum" "$DEST.sha256"
[[ ! -e "$partial_sum" && -s "$DEST.sha256" ]] || {
    echo "error: could not publish checksum without replacing a file" >&2
    exit 1
}
partial_sum=""
published_sum="$DEST.sha256"

(cd "$OUT_DIR" && sha256sum -c "$(basename "$DEST").sha256")
publication_complete=true

# make-iso.sh passes an inherited descriptor so it receives the exact artifact
# path without relying on wall-clock mtimes or parsing human-readable logs.
if [[ -n "${SECURITYOPS_ISO_RESULT_FD:-}" ]]; then
    [[ "$SECURITYOPS_ISO_RESULT_FD" =~ ^[0-9]+$ ]] || {
        echo "error: invalid SECURITYOPS_ISO_RESULT_FD" >&2
        exit 1
    }
    printf '%s\n' "$DEST" >&"$SECURITYOPS_ISO_RESULT_FD"
fi

echo ">> Copied to: $DEST"
echo
echo "   Verify:   sha256sum '$DEST'   (also saved to $DEST.sha256)"
echo "   Ventoy:   copy '$DEST' into the Ventoy partition and boot it."
