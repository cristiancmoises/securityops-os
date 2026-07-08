# Download the Security Ops OS live ISO

The live image is **~7 GiB**, larger than any git forge's single-file limit, so
it is published as **4 split parts** (<2 GB each). Because Codeberg and the
self-hosted Forgejo cap attachment size, the binary parts live on the
**GitHub release**:

👉 **https://github.com/cristiancmoises/securityos-os/releases/tag/v1.10.1**

(The full source, tag, and this guide are mirrored on GitHub, Codeberg, and
git.securityops.co. Prefer not to download 7 GB? Build it reproducibly: `./build.sh`.)

**Build:** `r8 · installer · kernel 7.1.2`
**Full ISO sha256:** `2b62240367093d5485995e1024aaefa53d9c12d41c0285ff82650039675f1fae`
**Size:** `7520595968` bytes

> New in r8: boot the live image, then run **`sudo security-ops-install`** — a
> guided TUI that installs Security Ops OS to a real disk (ext4/btrfs/xfs,
> optional LUKS2, Sway/i3/KDE). See the README "Install to disk" section.

## 1. Download all parts + the checksum manifest

From the v1.10.1 release assets, grab:

```
securityos-live-20260707-204011.iso.part00
securityos-live-20260707-204011.iso.part01
securityos-live-20260707-204011.iso.part02
securityos-live-20260707-204011.iso.part03
SHA256SUMS.parts
```

## 2. Verify the parts, then reassemble

```sh
sha256sum -c SHA256SUMS.parts          # all parts must say "OK"

cat securityos-live-20260707-204011.iso.part?? > securityos-live-20260707-204011.iso

# confirm the reassembled ISO is byte-perfect:
sha256sum securityos-live-20260707-204011.iso
#   must print:
#   2b62240367093d5485995e1024aaefa53d9c12d41c0285ff82650039675f1fae
```

## 3. Write it to a USB stick

```sh
lsblk -o NAME,SIZE,MODEL,TRAN          # find the stick (e.g. /dev/sdX)
sudo umount /dev/sdX* 2>/dev/null
sudo dd if=securityos-live-20260707-204011.iso of=/dev/sdX bs=4M status=progress oflag=sync conv=fsync
sync
# Optional read-back verify:
sudo head -c 7520595968 /dev/sdX | sha256sum   # must match the full sha256 above
```

Or drop the reassembled `.iso` into a **Ventoy** partition.

> Prefer to build it yourself (fully reproducible)? See the README — `./build.sh`.

---
*Per-part sha256 (also in `SHA256SUMS.parts`):*

```
655db39dfeb3710fc4ead5c1ce3a0a4d1eeca3425178f91f392be1e42f03e95f  ...part00
2ecf43376576631dbaa89939a63d42dc3cdce10c2fe6ce03dbaa48afe64e8f1c  ...part01
f6bb179ec217ba3606605d3fde6c1a23fb4b14be0f55f90d933588b7efa7b912  ...part02
a3c177f2b711ce4ddd48b2cd69518d0ba1a2d7f3352f039be6d40a41f43adb2c  ...part03
```

© Cristian Cezar Moisés · sac@securityops.co · AGPL-3.0-or-later
