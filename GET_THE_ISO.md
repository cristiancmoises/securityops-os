# Download the Security Ops OS live ISO

The live image is **~7 GiB**, larger than any git forge's single-file limit, so
it is published as **4 split parts** (<2 GB each). Because Codeberg and the
self-hosted Forgejo cap attachment size, the binary parts live on the
**GitHub release**:

👉 **https://github.com/cristiancmoises/securityops-os/releases/tag/v1.9.0**

(The full source, tag, and this guide are mirrored on GitHub, Codeberg, and
git.securityops.co. Prefer not to download 7 GB? Build it reproducibly: `./build.sh`.)

**Build:** `r7 · sway-only · fast`
**Full ISO sha256:** `b9ff788c01182eff8fa709d691fc7c9973750b763a97491d61a087d142018532`
**Size:** `7518189568` bytes

## 1. Download all parts + the checksum manifest

From the v1.9.0 release assets, grab:

```
securityos-live-20260630-192011.iso.part00
securityos-live-20260630-192011.iso.part01
securityos-live-20260630-192011.iso.part02
securityos-live-20260630-192011.iso.part03
SHA256SUMS.parts
```

## 2. Verify the parts, then reassemble

```sh
sha256sum -c SHA256SUMS.parts          # all parts must say "OK"

cat securityos-live-20260630-192011.iso.part?? > securityos-live-20260630-192011.iso

# confirm the reassembled ISO is byte-perfect:
sha256sum securityos-live-20260630-192011.iso
#   must print:
#   b9ff788c01182eff8fa709d691fc7c9973750b763a97491d61a087d142018532
```

## 3. Write it to a USB stick

```sh
lsblk -o NAME,SIZE,MODEL,TRAN          # find the stick (e.g. /dev/sdX)
sudo umount /dev/sdX* 2>/dev/null
sudo dd if=securityos-live-20260630-192011.iso of=/dev/sdX bs=4M status=progress oflag=sync conv=fsync
sync
# Optional read-back verify:
sudo head -c 7518189568 /dev/sdX | sha256sum   # must match the full sha256 above
```

Or drop the reassembled `.iso` into a **Ventoy** partition.

> Prefer to build it yourself (fully reproducible)? See the README — `./build.sh`.

---
*Per-part sha256 (also in `SHA256SUMS.parts`):*

```
99e82bb1777414e5cd6e3c334b603ef3ddcbd0e5c55f5413785dc3ae10a5c800  ...part00
299916b371153589aa6373e68ca1f3caeb2c0988a9b579581dae738e56236f37  ...part01
ceb7b54fb8b0fcbfc835d795b8d81e565492b1f0780640c842c68579b3db5c83  ...part02
ea94aae988f26c7993a600726e4e85d23b3ab281906db397334cf83f2b4847c4  ...part03
```

© Cristian Cezar Moisés · sac@securityops.co · AGPL-3.0-or-later
