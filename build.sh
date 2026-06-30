#!/usr/bin/env bash
# ===========================================================================
# build.sh — build the SecurityOS Live ISO
# ===========================================================================
# Produces a hybrid BIOS+UEFI iso9660 image you can drop into your Ventoy USB
# folder and boot live on any machine (pick Intel/AMD/auto at GRUB).
#
# Usage:
#   ./build.sh            # build with the CURRENT guix + nonguix (fast; uses
#                         # the channels you already have pulled)
#   ./build.sh --pinned   # build reproducibly via channels.scm (time-machine)
#
# Notes
#   * Egress is Tor-only on this host: the guix-daemon already routes substitute
#     downloads through Tor, so nothing here needs `torsocks`.  The image build
#     itself runs inside the daemon.
#   * Builds are big.  Scratch is sent to /var/tmp (not the 4G tmpfs /tmp).
#   * Run from THIS directory so the (local-file "assets/…") paths resolve.
# ===========================================================================
set -euo pipefail
cd "$(dirname "$0")"

export TMPDIR=/var/tmp                 # keep multi-GB scratch off tmpfs /tmp
OUT_DIR="$PWD/out"
mkdir -p "$OUT_DIR"

GUIX_ARGS=(system image -L "$PWD" -t iso9660 --label="SECURITY_OPS_LIVE" config.scm)

echo ">> Building SecurityOS Live ISO (this can take a while over Tor)…"
if [[ "${1:-}" == "--pinned" ]]; then
    echo ">> Using pinned channels.scm via time-machine (fully reproducible)."
    ISO=$(guix time-machine -C channels.scm -- "${GUIX_ARGS[@]}")
else
    echo ">> Using the current guix + nonguix in your profile."
    ISO=$(guix "${GUIX_ARGS[@]}")
fi

echo ">> Built: $ISO"
# Epoch-second name so a same-day rebuild can NEVER silently overwrite/alias a
# different image (this was the round-1..3 trap: one date-named file kept being
# mistaken for the latest build).
DEST="$OUT_DIR/securityos-live-$(date +%Y%m%d-%H%M%S 2>/dev/null || echo image).iso"
cp -f "$ISO" "$DEST"
chmod +w "$DEST"
sha256sum "$DEST" | tee "$DEST.sha256"
echo ">> Copied to: $DEST"
echo
echo "   Verify:   sha256sum '$DEST'   (also saved to $DEST.sha256)"
echo "   Ventoy:   copy '$DEST' into the Ventoy partition and boot it."
