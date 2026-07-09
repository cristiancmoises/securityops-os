# Download the Security Ops OS live ISO

The live image is **~7.6 GiB**, larger than any git forge's single-file limit, so
it is published as **4 split parts** (<2 GB each). Because Codeberg and the
self-hosted Forgejo cap attachment size, the binary parts live on the
**GitHub release**:

👉 **https://github.com/cristiancmoises/securityops-os/releases/tag/v1.12.0**

(The full source, tag, and this guide are mirrored on GitHub, Codeberg, and
git.securityops.co. Prefer not to download 7.6 GB? Build it reproducibly: `./build.sh`.)

**Build:** `r10 · wezterm · kernel 7.1.3`
**Full ISO sha256:** `e72999c843720de914d182e1b0c70fb70b07f846d88c227963f727cfe130b47b`
**Size:** `7656906752` bytes

> New in r10: the guided installer really works now (`security-ops-install` or
> **Super+Shift+I**); **WezTerm** is the default terminal; the maintainer's safe
> fish aliases are ported; a `schedutil` CPU-governor perf tweak at boot.

## 1. Download all parts + the checksum manifest

From the v1.12.0 release assets, grab:

```
securityos-live-20260709-155649.iso.part00
securityos-live-20260709-155649.iso.part01
securityos-live-20260709-155649.iso.part02
securityos-live-20260709-155649.iso.part03
SHA256SUMS.parts
```

## 2. Verify the parts, then reassemble

```sh
sha256sum -c SHA256SUMS.parts          # all parts must say "OK"

cat securityos-live-20260709-155649.iso.part?? > securityos-live-20260709-155649.iso

# confirm the reassembled ISO is byte-perfect:
sha256sum securityos-live-20260709-155649.iso
#   must print:
#   e72999c843720de914d182e1b0c70fb70b07f846d88c227963f727cfe130b47b
```

## 3. Write it to a USB stick

```sh
lsblk -o NAME,SIZE,MODEL,TRAN          # find the stick (e.g. /dev/sdX)
sudo umount /dev/sdX* 2>/dev/null
sudo dd if=securityos-live-20260709-155649.iso of=/dev/sdX bs=4M status=progress oflag=sync conv=fsync
sync
# Optional read-back verify:
sudo head -c 7656906752 /dev/sdX | sha256sum   # must match the full sha256 above
```

Or drop the reassembled `.iso` into a **Ventoy** partition.

> Prefer to build it yourself (fully reproducible)? See the README — `./build.sh`.

---
*Per-part sha256 (also in `SHA256SUMS.parts`):*

```
b4d9cec0a74fc08a748634cbb5e140fbb0fbacbffc200caf1a8278f6a1353de3  ...part00
8f98661fa625ceff78565fe37016ab47ee42004ab94bfea969819493a7d72349  ...part01
3663476d27e36c78891ce0aea85c1b1a0726182bf2190c34c263e39f1b48ad6c  ...part02
fc79260383a5d86dc97608a13c6a010de5f9b3454401e1f237f24041302af586  ...part03
```

© Cristian Cezar Moisés · sac@securityops.co · AGPL-3.0-or-later
