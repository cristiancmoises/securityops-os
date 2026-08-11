# Download the Security Ops OS live ISO

The live image is **7.06 GiB** (`7,585,067,008` bytes), larger than the
supported single-file release-asset limit, so it is published as **four split
parts**. The binary parts live on the canonical GitHub release; Codeberg and
the self-hosted Forgejo carry source and metadata-only mirrors to avoid
duplicating multi-gigabyte data:

👉 **https://github.com/cristiancmoises/securityops-os/releases/tag/v1.13.0**

**Build:** `r11 · v1.13.0 · kernel 7.1.8-SecurityOps`

**Full ISO SHA-256:** `8f3b9f8717eda7ce7916bd20dd641e2f05516b5b4684d6f636b5bbf440849d99`

**Exact size:** `7585067008` bytes

This release adds the one-command `securityopsctl` maintainer workflow and
uses the authenticated Security Ops cache first, followed by
`ci.guix.gnu.org`, with source fallback for cache misses.

## 1. Download every release asset

Download these five files from the v1.13.0 GitHub release:

```text
securityops-live-20260810-235949-8f3b9f8717ed.iso.part00
securityops-live-20260810-235949-8f3b9f8717ed.iso.part01
securityops-live-20260810-235949-8f3b9f8717ed.iso.part02
securityops-live-20260810-235949-8f3b9f8717ed.iso.part03
SHA256SUMS.parts
```

## 2. Verify and reassemble the ISO

Run these commands in the directory containing all five files:

```sh
sha256sum -c SHA256SUMS.parts

cat securityops-live-20260810-235949-8f3b9f8717ed.iso.part?? \
  > securityops-live-20260810-235949-8f3b9f8717ed.iso

sha256sum securityops-live-20260810-235949-8f3b9f8717ed.iso
# Must print:
# 8f3b9f8717eda7ce7916bd20dd641e2f05516b5b4684d6f636b5bbf440849d99
```

Do not write the image to media unless all four part checks report `OK` and
the reassembled ISO has the exact full-image hash above.

## 3. Write it to a USB drive

Replace `/dev/sdX` with the whole target drive, not a partition. This destroys
everything on that drive, so verify it carefully with `lsblk` first.

```sh
lsblk -o NAME,SIZE,MODEL,TRAN
sudo umount /dev/sdX* 2>/dev/null || true
sudo dd \
  if=securityops-live-20260810-235949-8f3b9f8717ed.iso \
  of=/dev/sdX bs=4M status=progress oflag=sync conv=fsync
sync

# Optional full read-back verification:
sudo head -c 7585067008 /dev/sdX | sha256sum
# Must match the full ISO SHA-256 above.
```

The reassembled ISO can also be copied to a Ventoy partition.

## Build it yourself

Clone the tagged source and run the professional maintainer tool. It validates
the canonical OS settings, uses the pinned channel set and both ordered
substitute servers, builds the image, verifies its checksum, and creates a
transactional release bundle:

```sh
git clone --branch v1.13.0 --depth 1 \
  https://github.com/cristiancmoises/securityops-os.git
cd securityops-os
./securityopsctl doctor
./securityopsctl build --bundle
```

See the README and `./securityopsctl --help` for package, kernel, release, and
resource-control commands.

## Per-part SHA-256

These values are also stored in `SHA256SUMS.parts`:

```text
5112e38992094fac0168c510c51465bf30b8d6ba02784596f8bd799baac4bdd4  securityops-live-20260810-235949-8f3b9f8717ed.iso.part00
53f51aea162dcee6ff38012fa225d64960b72c9c5ac1e5dfda15b0dd95df000f  securityops-live-20260810-235949-8f3b9f8717ed.iso.part01
33b79ee42d920659aba7880998b792c4a87bd3d6d2bb170d2719f669e238958a  securityops-live-20260810-235949-8f3b9f8717ed.iso.part02
008697a11d59bb4d36d55376f048330a440662661692d26a2fda56db8e5682b1  securityops-live-20260810-235949-8f3b9f8717ed.iso.part03
```

© Cristian Cezar Moisés · sac@securityops.co · AGPL-3.0-or-later
