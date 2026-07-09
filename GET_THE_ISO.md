# Download the Security Ops OS live ISO

The live image is **~7.6 GiB**, larger than any git forge's single-file limit, so
it is published as **4 split parts** (<2 GB each). Because Codeberg and the
self-hosted Forgejo cap attachment size, the binary parts live on the
**GitHub release**:

👉 **https://github.com/cristiancmoises/securityops-os/releases/tag/v1.12.1**

(The full source, tag, and this guide are mirrored on GitHub, Codeberg, and
git.securityops.co. Prefer not to download 7.6 GB? Build it reproducibly: `./build.sh`.)

**Build:** `r10 · v1.12.1 · wezterm · kernel 7.1.3`
**Full ISO sha256:** `a8ebe5c6525da5f54dbd08ba60e3842a0d29a046f19db440afcacc3b6f20d19d`
**Size:** `7656902656` bytes

> v1.12.1 is a point release over 1.12.0: it trims two `starship.toml` keys that
> made the first shell print config warnings. WezTerm is the default terminal;
> the guided installer works (`security-ops-install` or **Super+Shift+I**).

## 1. Download all parts + the checksum manifest

From the v1.12.1 release assets, grab:

```
securityos-live-20260709-190730.iso.part00
securityos-live-20260709-190730.iso.part01
securityos-live-20260709-190730.iso.part02
securityos-live-20260709-190730.iso.part03
SHA256SUMS.parts
```

## 2. Verify the parts, then reassemble

```sh
sha256sum -c SHA256SUMS.parts          # all parts must say "OK"

cat securityos-live-20260709-190730.iso.part?? > securityos-live-20260709-190730.iso

# confirm the reassembled ISO is byte-perfect:
sha256sum securityos-live-20260709-190730.iso
#   must print:
#   a8ebe5c6525da5f54dbd08ba60e3842a0d29a046f19db440afcacc3b6f20d19d
```

## 3. Write it to a USB stick

```sh
lsblk -o NAME,SIZE,MODEL,TRAN          # find the stick (e.g. /dev/sdX)
sudo umount /dev/sdX* 2>/dev/null
sudo dd if=securityos-live-20260709-190730.iso of=/dev/sdX bs=4M status=progress oflag=sync conv=fsync
sync
# Optional read-back verify:
sudo head -c 7656902656 /dev/sdX | sha256sum   # must match the full sha256 above
```

Or drop the reassembled `.iso` into a **Ventoy** partition.

> Prefer to build it yourself (fully reproducible)? See the README — `./build.sh`.

---
*Per-part sha256 (also in `SHA256SUMS.parts`):*

```
dbf8dee6c7cb4e56f1f8f00af8b979a68b141884192b05cf53bcf5ccd6bc1795  ...part00
0080796f589620db573c224024335862119808a4dda56d013294074a41b42b13  ...part01
10fc7857dd91dc4629f191d79bd6d865f827947721484f411222c9e149fde82f  ...part02
c570b64b278d077c621e301fbeb58d41519d4460da39a203eb147acb5822cb08  ...part03
```

© Cristian Cezar Moisés · sac@securityops.co · AGPL-3.0-or-later
