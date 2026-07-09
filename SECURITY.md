# Security Policy & Hardening Reference — Security Ops OS

*Custom Linux **7.1.3-SecurityOps** · GNU Guix System live ISO · sway-only Wayland · guided installer*
© Cristian Cezar Moisés · contact **sac@securityops.co**

This document describes (1) **how to report a vulnerability**, and (2) the
**actual, file-grounded hardening** applied by the image. Everything below is
verified against the real sources — `securityos/kernel.scm`, `config.scm`, and
`securityos/sessions.scm` — and is honest about what the system *does not* do.

> **Design goal: hardening that does not break offensive/forensic tooling.**
> There is deliberately *no* kernel lockdown, *no* module-signature enforcement,
> and loose reverse-path filtering — so pentest tools, MITM and out-of-tree
> drivers keep working.

---

## Reporting a vulnerability

Please report security issues **privately** to **sac@securityops.co** (PGP on
request). Include affected component, version/build tag (`cat
/etc/securityos/build-id`), reproduction steps, and impact. We aim to
acknowledge within **72 hours** and to coordinate a fix and disclosure timeline
with you. Please do not open public issues for undisclosed vulnerabilities.

**Out of scope (by design — see "What this is NOT"):** the published live
credentials (`securityops` / `securityops`, passwordless `sudo`), the absence of
full-disk encryption on the live medium, and the intentional lack of kernel
lockdown / module-signature enforcement.

---

## Layer 1 — Kernel build hardening (KSPP `CONFIG_*` actually built into the ISO)

The ISO kernel is `linux-securityos` (vanilla Linux 7.1.3 + the nonguix
broad-driver base config + an **additive** KSPP/perf overlay via
`customize-linux`). Only mainline, additive options are used.

| `CONFIG_*` | What it does / why it matters |
|---|---|
| `SLAB_FREELIST_HARDENED=y` | Obfuscates slab freelist pointers so heap-overflows can't hijack the allocator. |
| `SLAB_FREELIST_RANDOM=y` | Randomizes object hand-out order within a slab page (anti heap-grooming). |
| `SHUFFLE_PAGE_ALLOCATOR=y` | Randomizes buddy-allocator free lists (paired with `page_alloc.shuffle=1`). |
| `HARDENED_USERCOPY=y` | Bounds-checks `copy_to/from_user()` against real object size. |
| `STACKPROTECTOR_STRONG=y` | Stack canaries on a wide set of functions (anti stack-smash). |
| `INIT_ON_ALLOC_DEFAULT_ON=y` | Zeroes allocations on alloc (kills uninitialized-memory leaks). |
| `SECURITY_YAMA=y` | Yama LSM — backs the `ptrace_scope` restriction below. |
| `SECURITY_DMESG_RESTRICT=y` | Default-restricted dmesg (reinforced by sysctl). |
| `BUG_ON_DATA_CORRUPTION=y` | Turns list/structure corruption into a hard `BUG()` — fail-closed. |
| `SECURITY_LANDLOCK=y` *(r9)* | Landlock LSM — unprivileged, per-process filesystem/network sandboxing. |
| `FORTIFY_SOURCE=y` *(r9)* | Compile-time + runtime bounds checks on `mem*`/`str*` (buffer-overflow detection). |
| `SCHED_STACK_END_CHECK=y` *(r9)* | Panics on kernel-stack overflow instead of silently corrupting memory. |

*Performance (r9): `NET_SCH_CAKE=m` (bufferbloat-killing qdisc) and
`LRU_GEN_ENABLED=y` — MGLRU is now **on by default in the kernel**, not just
toggled at boot.*

> **Honest scope.** Landlock *is* now built **and initialized** (r9 adds
> `CONFIG_SECURITY_LANDLOCK=y` + `lsm=landlock,yama,bpf` on the kernel cmdline).
> The rest of the broader KSPP set in `securityos/securityops.defconfig`
> (`RANDSTRUCT_FULL`, `PAGE_TABLE_CHECK`, `STRICT_KERNEL_RWX`, `VMAP_STACK`,
> `APPARMOR`, IMA, `DM_CRYPT`/`DM_VERITY`…) belongs to the maintainer's
> **separate, dormant** single-laptop kernel and is **not** applied to this ISO.
> We only claim what the image actually builds.

---

## Layer 2 — Boot command-line hardening (`%base-kernel-arguments`, all entries)

| Token | What it does |
|---|---|
| `init_on_alloc=1` | Zero pages on allocation — defeats uninitialized-memory info leaks. |
| `slab_nomerge` | No merging of same-size slab caches (heap isolation/hygiene). |
| `page_alloc.shuffle=1` | Randomizes free-page lists at boot. |
| `randomize_kstack_offset=on` | Per-syscall random kernel-stack offset. |
| `vsyscall=none` | Removes the legacy fixed-address vsyscall ROP target. |
| `module_blacklist=dccp,sctp,rds,tipc` | Hard-blocks rarely-used, CVE-heavy network stacks (CIS-style). |
| `modprobe.blacklist=pcspkr` | Disables the PC-speaker module. |

**Per-entry IOMMU.** The four hardware-specific GRUB entries add
`intel_iommu=on` / `amd_iommu=on iommu=pt` (DMA-remapping against malicious
DMA). **Caveat:** the default *auto-detect* entry does **not** enable IOMMU.

---

## Layer 3 — Sysctl hardening (`%securityos-sysctl`, wins on conflict)

**Kernel / process:** `kernel.kptr_restrict=2` (hide kernel pointers),
`kernel.dmesg_restrict=1`, `kernel.yama.ptrace_scope=1` (ptrace children only),
`kernel.kexec_load_disabled=1`, `kernel.perf_event_paranoid=3`,
`kernel.unprivileged_bpf_disabled=1`, `net.core.bpf_jit_harden=2`,
`kernel.randomize_va_space=2` (full ASLR).

**Filesystem:** `fs.protected_symlinks=1`, `fs.protected_hardlinks=1`,
`fs.protected_fifos=2`, `fs.protected_regular=2` (close classic `/tmp` TOCTOU /
sticky-dir escalation primitives).

**Network:** `tcp_syncookies=1`; `rp_filter=2` (**loose** anti-spoof — *loose by
choice* so MITM/forwarding works); `accept_redirects=0` (v4+v6),
`send_redirects=0`, `accept_source_route=0` (v4+v6).

---

## Layer 4 — Firewall (nftables, default-drop, stateful)

`%simple-firewall` installs an `inet filter` table:

- **`input` — `policy drop`**: `ct state invalid drop`; `ct state
  established,related accept` (stateful return-only); `iif lo accept`; ICMP/ICMPv6
  accept; DHCP `udp dport {67,68,546} accept`; `counter drop`.
- **`forward` — `policy drop`** (not a router).
- **`output` — `policy accept`** (egress unrestricted, so DHCP/DNS/VPN/Tor work
  anywhere).

Zero unsolicited inbound exposure; nothing listens inbound by default.

---

## Layer 5 — Anonymity (Tor SOCKS, opt-in)

`%tor-service` runs Tor with `SOCKSPort 127.0.0.1:9050` (**loopback only**),
`SafeLogging 1`. Tooling: `tor`, `torsocks`, `nyx`, `torbrowser`, `i2pd`, and the
loopback **Torando Control** GUI. **Caveat:** this is an *opt-in SOCKS proxy*,
**not** transparent system-wide torification — un-proxied apps egress clearnet.

---

## Layer 6 — Memory / resilience

- **zram** — 6 GB `zstd` compressed RAM swap (the live root is a RAM overlay).
- **earlyoom** — kills at 5% free mem/swap, *before* the kernel OOM hangs the
  desktop; `avoid-regexp` protects `sway`/`swaybg`/`waybar`/`greetd`/`tuigreet`/
  `shepherd`.
- **MGLRU** — enabled at boot (`lru_gen/enabled=y`, `min_ttl_ms=1000`).
- **prewarm-fontconfig** — builds `/var/cache/fontconfig` at boot (availability,
  not security): eliminates the multi-minute first-GUI-launch stall.

---

## Layer 7 — Attack-surface reduction

- Rare-protocol kernel blacklist (Layer 2).
- **No GDM / no display manager** — greetd + tuigreet (GL-free TUI) on vt7, with
  only `video`/`input` groups. Far less code/privilege than a graphical DM.
- **sway-only Wayland** — the entire legacy X11 stack (xmonad, XLibre, picom,
  xterm) was removed; `xorg-server-xwayland` only, for X apps under sway.
- **Minimal curated services** — NetworkManager, elogind, polkit, dbus, udisks,
  upower, cups, ntp + the explicit set (nftables, Tor, zram, earlyoom, greetd,
  MGLRU, fontconfig prewarm, Torando, Guix Home). No SSH/web server listening.

---

## Layer 8 — Installer & runtime isolation

**Guided installer (`security-ops-install`).** Turning the live image into an
installed system is the one operation that *destroys* data, so the installer is
built defensively:

- **No disk is touched until you type the target device path** to confirm — exact
  string match, no normalization bypass. This is the primary accidental-wipe
  backstop.
- It **refuses the disk you booted from** (parent-disk of `/`, derived via
  `lsblk -no pkname`) and **warns on any target with mounted partitions**.
- Passwords never hit disk as plaintext or a command line: they travel by
  environment, are hashed with `openssl passwd -6` read from **stdin**, and only
  the SHA-512 crypt hash is written into the generated `config.scm`.
- Free-text fields (hostname/user/full name) are validated and **escaped** before
  they enter the Scheme config, so a `"`/`\` can't corrupt or inject into it.
- On any mid-operation failure the error trap **unmounts `/mnt`, closes the LUKS
  mapping**, and tells you the disk was *partially* modified (no false "done").
- Success is gated on the **real `guix system init` exit code AND the presence of
  `/mnt/boot/grub/grub.cfg`** (written last) — never a false-positive signal.
- **Optional LUKS2 full-disk encryption** (`cryptsetup luksFormat`, aes-xts) with
  the matching initrd crypto modules, so an installed system unlocks at boot.

**Esquema (rootless container runtime).** Ships in the profile for defense-in-
depth process isolation without a daemon or root: unprivileged **user namespaces**
plus mount/PID/UTS/IPC/net/cgroup namespaces, `pivot_root`, **full capability
drop**, a **seccomp-BPF syscall allowlist**, and `NO_NEW_PRIVS`. The FFI only
`dlopen`s `libesquema.so` from `$ESQUEMA_LIBDIR` (the immutable store path), never
a writable working directory.

---

## What this is **NOT** (honest limitations)

- **The live medium itself is not encrypted** — its root is a read-only iso9660 +
  volatile RAM overlay, so no disk/UUID/LUKS is referenced on the ISO. (Full-disk
  **LUKS2 is available when you _install_ to a real disk** — see Layer 8.)
- **No kernel lockdown / no module-signature enforcement** — *on purpose*, so
  pentest tooling and out-of-tree drivers load freely.
- **No Secure Boot** — GRUB boots an unsigned kernel; no measured boot.
- **Not amnesic like Tails** — non-persistent only because the root is a RAM
  overlay; there is **no** enforced RAM-wipe on shutdown and **no** anti-forensic
  protection against disks you mount.
- **Tor is available, not enforced** — `output` policy is accept-all.
- **Published live credentials** — user `securityops` / pass `securityops`,
  `%wheel NOPASSWD: ALL`. Treat any booted instance as trivially root-able by
  anyone with local access. (Intended for a *live* image.)
- **No early CPU microcode update** — plain `base-initrd` is used (the nonguix
  `microcode-initrd` panicked under the iso9660 loader).
- **`random.trust_cpu=on`** — trades entropy conservatism for instant CRNG init.

---

*Sources of truth: `securityos/kernel.scm`, `config.scm`, `securityos/sessions.scm`.
`securityos/securityops.defconfig` is reference-only and not consumed by the ISO build.*
