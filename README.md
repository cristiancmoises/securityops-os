<div align="center">

# Security Ops OS

### *In Code We Trust.*

**A hardened, privacy-focused, reproducible GNU Guix System — as a portable x86_64 live ISO.**
*Custom Linux 7.1.8-SecurityOps · sway (Wayland) · guided disk installer · curated offensive & forensics toolkit · Tor on tap.*

`build r11 · v1.13.0 · wezterm · kernel 7.1.8` &nbsp;•&nbsp; © Cristian Cezar Moisés &nbsp;•&nbsp; AGPL-3.0-or-later &nbsp;•&nbsp; sac@securityops.co

</div>

---

## What is it?

**Security Ops OS** is a complete operating system defined by a pinned **Guix
configuration and module tree** — and shipped as a hybrid BIOS/UEFI **live ISO** you can
`dd` to a USB stick (or drop into Ventoy) and boot across a broad range of
**x86_64 PCs**.

It is built for **security professionals, power users, privacy enthusiasts, and
the Guix-curious** who want one image that is:

- 🔁 **Reproducible & declarative** — the whole OS is `channels.scm`, `config.scm`,
  `securityops/settings.json`, and the imported `securityops/` modules.
  Anyone can use `guix time-machine` to rebuild the exact pinned channel graph.
  The *sanitized build source is embedded on the running system* at
  `/etc/securityops/src` — boot it, read it, rebuild it. The self-referential
  download/checksum guide is omitted.
- 🛡️ **Hardened, pragmatically** — a KSPP-flavored custom kernel + boot-cmdline +
  sysctl + nftables profile **that deliberately doesn't break offensive tooling**
  (no lockdown, no module-sig enforcement). See **[SECURITY.md](SECURITY.md)**.
- 🧰 **Loaded for security work** — nmap, Wireshark, aircrack-ng, hashcat, John,
  Hydra, radare2/rizin, binwalk, and a deep network/crypto/forensics set. Full
  list: **[docs/PACKAGES.md](docs/PACKAGES.md)**.
- 🧅 **Tor-ready** — a loopback Tor SOCKS proxy, `torsocks`, `nyx`, Tor Browser,
  i2pd, and the **Torando Control** GUI.
- ⚡ **Blazing-fast first launch** — sway-only Wayland, a slimmed profile, and a
  boot-time fontconfig cache prewarm: **login → usable desktop in ~7 seconds.**
- 🔓 **No secrets baked in** — a *sanitized public sibling* of the maintainer's
  real workstation: no active host disk identifiers, private keys, credentials,
  or personalized DNS/network configuration.

> **Honesty first.** Security Ops OS is *stateless-live*, **not** anti-forensic
> like Tails; Tor is **opt-in**, not force-routed; it is a hardened single domain,
> **not** VM-isolated like Qubes. Read **["What this is NOT"](SECURITY.md#what-this-is-not-honest-limitations)**
> before trusting it with a serious threat model.

---

## How it compares

A fair, honest comparison (✅ strong · ⚠️ partial/with caveats · ❌ no):

| Dimension | **Security Ops OS** | Tails | Whonix | Qubes OS | Kicksecure | Kali / Parrot | Vanilla Guix |
|---|---|---|---|---|---|---|---|
| **Base** | Guix + nonguix | Debian | Debian | Xen | Debian | Debian | Guix |
| **Reproducible / declarative system** | ✅ Scheme, pinned, rebuildable | ⚠️ vendor ISO only | ❌ | ⚠️ template split | ❌ | ❌ | ✅ |
| **Atomic rollback / generations** | ✅ Guix generations | ❌ | ❌ | ⚠️ clone/revert | ❌ | ❌ | ✅ |
| **Boot-anywhere live USB** | ✅ `dd`/Ventoy, RAM overlay | ✅ | ⚠️ VMs | ❌ installed | ❌ | ✅ | ⚠️ installer |
| **Amnesic / leave-no-trace** | ⚠️ stateless, *not* anti-forensic | ✅ engineered | ⚠️ | ✅ DisposableVM | ❌ | ⚠️ | ❌ |
| **Tor** | ⚠️ SOCKS, **opt-in** | ✅ forced, fail-closed | ✅ gateway VM | ⚠️ via Whonix | ❌ | ⚠️ AnonSurf | ❌ |
| **Isolation model** | hardened single domain | anonymity+amnesia | 2-VM network iso | ✅ Xen hardware iso | hardening | none | DAC |
| **Kernel hardening** | ✅ KSPP subset, *no lockdown* (by design) | ⚠️ moderate | ✅ + AppArmor | ✅ dom0 | ✅✅ hardened_malloc | ❌ minimal | ⚠️ stock |
| **Pentest toolkit OOTB** | ✅ curated (no MSF/Burp) | ❌ | ❌ | ❌ | ❌ | ✅✅ exhaustive | ❌ |
| **Default desktop** | sway (Wayland) | GNOME | XFCE | XFCE | XFCE | XFCE/MATE | any |
| **Learning curve** | high (Guix/Scheme) | low | moderate | high | moderate | moderate | high |

**Where it fits:** none of the others give you a *reproducible + declarative +
rollbackable Guix System* that is **also** a curated pentest/forensics image that
targets **broad x86_64 hardware coverage**. If you need enforced anonymity → **Tails/Whonix**;
strongest isolation → **Qubes**; maximal hardening → **Kicksecure**; the biggest
turnkey tool catalog → **Kali/Parrot**. Security Ops OS wins on
*reproducibility + portability + pragmatic hardening + Tor-on-tap + a real toolkit*,
and is honest about the rest.

---

## Quickstart

### 1. Get the ISO
Build it yourself (fully reproducible — see below), or use a release image. Then
**always verify the checksum**:

```sh
sha256sum securityops-live-*.iso        # compare to the published sha256
```

### 2. Write it to a USB stick
```sh
lsblk -o NAME,SIZE,MODEL,TRAN           # find the stick (e.g. /dev/sdX)
sudo umount /dev/sdX* 2>/dev/null
sudo dd if=securityops-live-*.iso of=/dev/sdX bs=4M status=progress oflag=sync conv=fsync
sync
# Optional but recommended — prove the bytes landed:
sudo head -c <iso-byte-size> /dev/sdX | sha256sum     # must match the ISO sha256
```
Or drop the `.iso` into a **Ventoy** partition and boot it (use *"Boot in normal mode"*).

### 3. Boot & log in
At GRUB pick the entry for your machine (**five entries**, each stamped with the
build id):

| Entry | Use it when |
|---|---|
| **Security Ops (auto-detect GPU)** | Default — works almost everywhere |
| **Security Ops — Intel GPU (i915)** | Intel box with a working GPU |
| **Security Ops — AMD GPU (amdgpu)** | AMD/Radeon box with a working GPU |
| **Security Ops — Intel CPU (no GPU / safe graphics)** | Intel, `nomodeset` software fallback |
| **Security Ops — AMD CPU (no GPU / safe graphics)** | AMD, `nomodeset` software fallback |

Log in as **`securityops` / `securityops`** (passwordless `sudo`) → you land
straight in **sway**. `cat /etc/securityops/build-id` confirms which build you booted.

> **Default sway keys:** `Super+Return` terminal · `Super+d` launcher · `Super+e`
> browser · `Super+Shift+I` **install to disk** · `Super+q` close · `Super+1..9`
> workspaces · `Super+Shift+e` exit · volume/brightness media keys.

### 4. Install it to disk (optional — guided)

Like what you booted? Put it on a real disk with the built-in guided installer:

```sh
security-ops-install
```

A branded black-on-cyan TUI walks you through everything and then does the work
for you — **no manual `guix system init`, no hand-written config**:

| Choice | Options |
|---|---|
| **Filesystem** | ext4 · Btrfs · XFS  *(ZFS root remains disabled/planned; UEFI installs only)* |
| **Encryption** | optional **LUKS2** full-disk (your passphrase, never stored) |
| **Desktop** | **Sway** (Wayland) · **i3** (X11) · **KDE Plasma** |
| **Locale / timezone / keyboard / hostname** | picked from menus |
| **Accounts** | your user + root (passwords hashed with `openssl passwd -6`) |

It **generates a self-contained declarative `/etc/config.scm`** for your exact
choices, partitions the disk, makes the filesystem and runs `guix system init`
through the release's pinned channel time-machine.
The installed system ships a **hardened base + a curated core toolset** (the
live image's full arsenal is one `guix install` away). It stays 100 %
declarative — the installer also copies the `(securityops …)` modules and pinned
channels to the target. Reconfigure with the same authenticated graph:

```sh
sudo guix time-machine -C /etc/guix/channels.scm \
  --substitute-urls='https://substitutes.securityops.com.br https://ci.guix.gnu.org' --fallback -- \
  system reconfigure -L /etc/securityops/src \
  --substitute-urls='https://substitutes.securityops.com.br https://ci.guix.gnu.org' --fallback \
  /etc/config.scm
```

> **Safety:** nothing is written until you **type the target device path** to
> confirm. The installer refuses the disk you booted from, warns on targets with
> mounted partitions, and routes the install through a `cow-store` overlay so the
> build lands on the target disk (not RAM).

---

## Security & hardening

A defense-in-depth profile that **keeps pentest tooling working**. Highlights:

- **Kernel (KSPP subset):** hardened/randomized SLUB freelist, `HARDENED_USERCOPY`,
  `STACKPROTECTOR_STRONG`, `INIT_ON_ALLOC`, Yama, dmesg-restrict, `BUG_ON_DATA_CORRUPTION`.
- **Boot cmdline:** `init_on_alloc=1`, `slab_nomerge`, `page_alloc.shuffle=1`,
  `randomize_kstack_offset=on`, `vsyscall=none`, `module_blacklist=dccp,sctp,rds,tipc`.
- **Sysctl:** `kptr_restrict=2`, `ptrace_scope=1`, unprivileged-BPF off, BPF-JIT
  hardened, full ASLR, `fs.protected_*`, anti-spoof/redirect/source-route.
- **Firewall:** nftables, **default-drop** stateful input, nothing listening inbound.
- **Anonymity:** loopback Tor SOCKS + `torsocks`/`nyx`/Tor Browser; Torando can
  opt one local user into transparent Tor routing with a killswitch.
- **Resilience:** zram (zstd), earlyoom (protects the desktop), MGLRU.

Full, file-grounded breakdown **and an honest "What this is NOT"** →
**[SECURITY.md](SECURITY.md)**. Report vulnerabilities to **sac@securityops.co**.

---

## What's inside (packages)

A curated set across recon, sniffing/MITM, wireless, cracking/RE/forensics,
crypto & keys, firewall/VPN/anonymity, filesystems & recovery, system & monitoring,
media, and dev — plus a full sway desktop. **Complete table → [docs/PACKAGES.md](docs/PACKAGES.md).**

### Security Ops native tools (the **securityops** channel)

| Tool | What it is | License |
|---|---|---|
| **Evelin** | Post-quantum secure tunnel (SSH-shaped): ML-KEM-1024 + ML-DSA-87 + ChaCha20-Poly1305 | **AGPL-3.0 _or_ Commercial (dual)** |
| **Esquema** | Rootless, Guile-native container runtime — user/mount/PID/net/cgroup namespaces, `pivot_root`, cap-drop, seccomp-BPF allowlist, `NO_NEW_PRIVS` | AGPL-3.0-or-later |
| **VaptVupt** | Post-quantum backup & compression (ML-KEM-768 + X25519, Argon2id, AES-256) — CLI + Qt GUI | AGPL-3.0-or-later |
| **Turbo Recorder** | Auto-configuring HW-accelerated screen+audio recorder (NVENC/QSV/VAAPI/AMF) | GPL-3.0 |
| **Torando** | Transparent Tor proxy + leak killswitch for one user, with a live-status GUI | AGPL-3.0-only |
| *BTP* *(planned)* | Berkeley Transport Protocol — PQ successor to HTTP+TLS | Apache-2.0 (impl) |
| *mirim* *(planned)* | Tiny encrypted-at-rest embedded SQL DB, `#![forbid(unsafe_code)]` Rust | **AGPL-3.0 _or_ Commercial (dual)** |

**Dual-licensed (Evelin, mirim):** free under the **AGPL** for open use; a separate
**commercial license** lifts the AGPL's copyleft / network-use obligations for
proprietary or closed-source/SaaS use — **contact sac@securityops.co**.

---

## 📡 The `securityops` Guix channel — *recommended*

The current app set comes from the authenticated `securityops` channel together
with nonguix and small-guix; the latter's gocix/sops-guix dependencies are also
explicitly pinned. The exact channel closure is in
[`channels.scm`](channels.scm). You can also add the Security Ops channel to any
Guix system, not just this ISO:

```scheme
;; ~/.config/guix/channels.scm
(cons (channel
        (name 'securityops)
        (url "https://git.securityops.com.br/cristiancmoises/securityops-channel.git")
        (branch "main")
        (introduction
         (make-channel-introduction
          "af46f5cce66179f3e53f87c86ca2538c8fc63f98"
          (openpgp-fingerprint
           "0CFA 43B9 AA96 42EA AF2B  E983 C4C6 61C9 ECFB 46E8"))))
      %default-channels)
```
```sh
guix pull
guix install evelin-bin vaptvupt turborec torando-gui   # then use them anywhere
```
The channel depends on nonguix; use this repository's `channels.scm` when you
want the complete authenticated set without assembling dependencies manually.
Browse it: **https://git.securityops.com.br/cristiancmoises/securityops-channel**

### Binary substitutes: Security Ops first, GNU Guix CI second

The image, its guided installer, and `build.sh` use exactly two ordered Guix
binary caches: **`https://substitutes.securityops.com.br`** first, then the
official **`https://ci.guix.gnu.org`** build farm. No other default substitute
is retained. Both Ed25519 public keys are versioned as
`substitutes.securityops.com.br.pub` and `ci.guix.gnu.org.pub`; cache misses
build from source.

Authorize both public keys once on a machine that does not already trust them:

```sh
sudo guix archive --authorize < substitutes.securityops.com.br.pub
sudo guix archive --authorize < ci.guix.gnu.org.pub
```

This restriction applies to **binary substitutes**. A source build can still
fetch pinned channel repositories and upstream source archives.

---

## Maintain the OS with one tool

Run the interactive maintainer console:

```sh
./securityopsctl
```

Or automate the same safe operations:

```sh
./securityopsctl status
./securityopsctl package add sqlmap yara
./securityopsctl package remove google-chrome-stable
./securityopsctl kernel set 7.1.9
./securityopsctl release set 1.14.0 --revision r12
./securityopsctl apply --add sqlmap --remove vlc --kernel 7.1.9 --build
./securityopsctl validate --full
./securityopsctl build --bundle --prune-old
```

`securityops/settings.json` is the single source of truth for release/kernel
metadata and package add/remove overrides. `securityopsctl` validates its
schema, edits it atomically under the ISO build lock, obtains kernel hashes from
the official kernel.org tarball, and keeps the hand-written package groups
untouched. Package-only changes reuse the kernel and all unchanged Guix store
paths; kernel-only changes rebuild the kernel-dependent path. The reusable
release-engineering prompt is in
[`docs/MAINTAINER_PROMPT.md`](docs/MAINTAINER_PROMPT.md).

Local development images can retain the last published release identity. Before
publishing a formal release, use `release set`, follow the maintainer prompt,
and regenerate the release notes/download guide from the verified artifact;
ordinary package and kernel experiments never rewrite prose documentation.

---

## Build it yourself (reproducible)

```sh
git clone https://github.com/cristiancmoises/securityops-os.git securityops-iso
cd securityops-iso
./make-iso.sh            # pinned build + preflight + checksum verification
# ./make-iso.sh --bundle # also make verified 1900 MiB release parts
# ./make-iso.sh --bundle --prune-old  # keep only the new local release
```
That one command uses the exact pinned channel graph, prevents concurrent ISO
builds, checks the project scripts and patch whitespace, calls the lower-level
`./build.sh --pinned`, and verifies the resulting checksum. It produces a
timestamp-and-hash-named `out/securityops-live-YYYYMMDD-HHMMSS-HASH.iso` plus a
`.sha256` sidecar.
`--bundle` additionally creates release-ready split parts and proves that they
reassemble byte-for-byte. It needs roughly one additional ISO's worth of free
space. `--prune-old` removes older local ISOs/bundles only after the new output
has verified successfully. Multi-GB `out/` is git-ignored.

Prerequisites are GNU/Linux, Bash, GNU Guix with both cache keys authorized,
Python 3, `flock` (util-linux), Git, and standard GNU coreutils. Optional
`--jobs N` and `--cores N` flags let you bound build parallelism.

The first build compiles the custom kernel and any misses from both caches;
subsequent builds reuse the Guix store. `build.sh` passes the ordered Security
Ops + GNU Guix CI URL list to both time-machine stages, with source fallback.

---

## Sanitization — no sensitive data

Security Ops OS is the **public, sanitized sibling** of a real workstation.
No host LUKS/FS/swap identifiers, mapped devices, private keys, credentials, VPN
accounts, or personalized resolver configuration are active in the image. The
live root is a **read-only iso9660 + RAM overlay**; public historical/reference
documents may retain non-secret development provenance. See
**[docs/SANITIZATION.md](docs/SANITIZATION.md)**.

---

## License & contact

- **This repository:** **GNU AGPL-3.0-or-later** — see **[LICENSE](LICENSE)**.
- **Bundled native tools** keep their own licenses (table above); two are
  **dual-licensed (AGPL + Commercial)**.
- **Copyright © Cristian Cezar Moisés.** All rights reserved where applicable.
- **Contact / commercial licensing / security reports:** **sac@securityops.co**

<div align="center">

**Security Ops OS — In Code We Trust.**
*Reproducible. Hardened. Yours to rebuild.*

</div>
