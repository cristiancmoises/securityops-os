# Download the Security Ops OS live ISO

The live image is **~7.6 GiB**, larger than any git forge's single-file limit, so
it is published as **4 split parts** (<2 GB each). Because Codeberg and the
self-hosted Forgejo cap attachment size, the binary parts live on the
**GitHub release**:

👉 **https://github.com/cristiancmoises/securityops-os/releases/tag/v1.11.0**

(The full source, tag, and this guide are mirrored on GitHub, Codeberg, and
git.securityops.co. Prefer not to download 7.6 GB? Build it reproducibly: `./build.sh`.)

**Build:** `r9 · fast · kernel 7.1.3`
**Full ISO sha256:** `d741911ffa348d2b13c910f233bcff24edc97d61ce3e1aad09ccda0694550b99`
**Size:** `7657375744` bytes

> New in r9: the guided installer now launches reliably (`security-ops-install`
> or **Super+Shift+I**); `lf` shows images inline in the terminal; LibreWolf,
> qBittorrent, VaptVupt added; kernel 7.1.3 with Landlock + MGLRU.

## 1. Download all parts + the checksum manifest

From the v1.11.0 release assets, grab:

```
securityos-live-20260709-103518.iso.part00
securityos-live-20260709-103518.iso.part01
securityos-live-20260709-103518.iso.part02
securityos-live-20260709-103518.iso.part03
SHA256SUMS.parts
```

## 2. Verify the parts, then reassemble

```sh
sha256sum -c SHA256SUMS.parts          # all parts must say "OK"

cat securityos-live-20260709-103518.iso.part?? > securityos-live-20260709-103518.iso

# confirm the reassembled ISO is byte-perfect:
sha256sum securityos-live-20260709-103518.iso
#   must print:
#   d741911ffa348d2b13c910f233bcff24edc97d61ce3e1aad09ccda0694550b99
```

## 3. Write it to a USB stick

```sh
lsblk -o NAME,SIZE,MODEL,TRAN          # find the stick (e.g. /dev/sdX)
sudo umount /dev/sdX* 2>/dev/null
sudo dd if=securityos-live-20260709-103518.iso of=/dev/sdX bs=4M status=progress oflag=sync conv=fsync
sync
# Optional read-back verify:
sudo head -c 7657375744 /dev/sdX | sha256sum   # must match the full sha256 above
```

Or drop the reassembled `.iso` into a **Ventoy** partition.

> Prefer to build it yourself (fully reproducible)? See the README — `./build.sh`.

---
*Per-part sha256 (also in `SHA256SUMS.parts`):*

```
d18e9946805142a8a2fcb631d8c89501d8585fb7eea5acb5640959017181928a  ...part00
366e744e0853f0310c2a83a616869f01b70f98adcf2e80f52fdc78d1d26cf959  ...part01
0841b4693c9d29a5e19c2f64c858339390152f85dd9bb7bff4c8bd77248ff981  ...part02
3135ebc33ef36bed1f71e3e87c0291c07b87194ec6b793529cd533e8caf857d8  ...part03
```

© Cristian Cezar Moisés · sac@securityops.co · AGPL-3.0-or-later
