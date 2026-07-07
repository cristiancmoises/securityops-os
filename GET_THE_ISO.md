# Download the Security Ops OS live ISO

The live image is **~7 GiB**, larger than any git forge's single-file limit, so
it is published as **4 split parts** (<2 GB each). Because Codeberg and the
self-hosted Forgejo cap attachment size, the binary parts live on the
**GitHub release**:

👉 **https://github.com/cristiancmoises/securityops-os/releases/tag/v1.10.0**

(The full source, tag, and this guide are mirrored on GitHub, Codeberg, and
git.securityops.co. Prefer not to download 7 GB? Build it reproducibly: `./build.sh`.)

**Build:** `r8 · installer · kernel 7.1.2`
**Full ISO sha256:** `f0a21db8c2f6d95d183bd76ac403fe51ac7cbef4e3a6c2a9b15fa05a0b454bd4`
**Size:** `7520593920` bytes

> New in r8: boot the live image, then run **`sudo security-ops-install`** — a
> guided TUI that installs Security Ops OS to a real disk (ext4/btrfs/xfs/zfs,
> optional LUKS2, Sway/i3/KDE). See the README "Install to disk" section.

## 1. Download all parts + the checksum manifest

From the v1.10.0 release assets, grab:

```
securityos-live-20260704-213248.iso.part00
securityos-live-20260704-213248.iso.part01
securityos-live-20260704-213248.iso.part02
securityos-live-20260704-213248.iso.part03
SHA256SUMS.parts
```

## 2. Verify the parts, then reassemble

```sh
sha256sum -c SHA256SUMS.parts          # all parts must say "OK"

cat securityos-live-20260704-213248.iso.part?? > securityos-live-20260704-213248.iso

# confirm the reassembled ISO is byte-perfect:
sha256sum securityos-live-20260704-213248.iso
#   must print:
#   f0a21db8c2f6d95d183bd76ac403fe51ac7cbef4e3a6c2a9b15fa05a0b454bd4
```

## 3. Write it to a USB stick

```sh
lsblk -o NAME,SIZE,MODEL,TRAN          # find the stick (e.g. /dev/sdX)
sudo umount /dev/sdX* 2>/dev/null
sudo dd if=securityos-live-20260704-213248.iso of=/dev/sdX bs=4M status=progress oflag=sync conv=fsync
sync
# Optional read-back verify:
sudo head -c 7520593920 /dev/sdX | sha256sum   # must match the full sha256 above
```

Or drop the reassembled `.iso` into a **Ventoy** partition.

> Prefer to build it yourself (fully reproducible)? See the README — `./build.sh`.

---
*Per-part sha256 (also in `SHA256SUMS.parts`):*

```
99e782927682ba9e5fe3711371aaaddaf2022697775927915fcb314ac3845d67  ...part00
2a364bc32981afac0eab6fdd204d5311db2d30100d18ef7213512fa58f99154f  ...part01
96e693f07d5876b2995f1720bdbe78e3a1241cb30ae8909a8170bf8eb5aacf64  ...part02
f938bce4d1dde011eb7450d981da2b566c1a0ac488a7837dfeb83c9d5c08acfb  ...part03
```

© Cristian Cezar Moisés · sac@securityops.co · AGPL-3.0-or-later
