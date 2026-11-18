# Security Policy & Hardening Reference — Security Ops OS

*Security Ops OS GNU/Linux distribution · custom Linux **7.3.4-SecurityOps** · declarative GNU Guix management · selectable Sway / XMonad+XLibre / KDE · guided installer*
© Cristian Cezar Moisés · contact **sac@securityops.co**

This document describes (1) **how to report a vulnerability**, and (2) the
hardening requested by the source configuration. Source policy and synthetic
tests do not prove enforcement in a compiled kernel or booted image. Current
live/install and hardware validation remains outstanding; historical image
claims must not be transferred to the uncommitted repair worktree.

> **Design goal: hardening that does not break offensive/forensic tooling.**
> There is deliberately *no* kernel lockdown, *no* module-signature enforcement,
> and loose reverse-path filtering — so pentest tools, MITM and out-of-tree
> drivers keep working.

---

## Reporting a vulnerability

GUI packaging repair (2026-09-26): launchers use declared Store Bash and isolated
Store Python (`-I`), with explicit Qt/Python or GTK typelib paths instead of
empty build-environment fallbacks. Imports and generated artifacts were tested
without creating a GUI. This is not a general environment/loader sandbox, an
interactive accessibility audit, channel authentication, or release approval.
Installer 2's Apply block and all application-level admission checks remain
unchanged. No disk installation, system reconfiguration, or boot was exercised
by this repair. The restored package source set still requires reconciliation
into the admitted ISO build inputs.

Application selection (2026-09-27): the canonical package overrides add Thunar,
Guix Center, Installer 2, Heroic, Steam, Tor Browser and guixvis to live and generated
OS candidates.
No installer action, privilege, channel pin or substitute policy changes.
Selection tests use an unavailable daemon socket and inspect actual package
objects; they cannot establish Store closure admission or safe GUI execution.
The earlier Store audit's 25 blocked objects, including the unexplained local
versus signed libgtop NAR difference, remain unresolved. A passing source/graph
gate must not promote those inputs or enable Installer 2 Apply.
Gaming selection uses Heroic 2.22.1 from Nonguix and the SecurityOps Steam
1.0.0.87 wrapper, not Nonguix's 1.0.0.85. These are inherited FHS containers,
not QEMU/KVM guests or evidence of VM isolation. The pinned Steam recipe fetches
its bootstrap from an HTTP origin with a fixed Guix hash; hash integrity is
not publisher authentication. Its client self-updates outside that bootstrap
version. Heroic's binary recipe sets `#:validate-runpath? #f`; its actual
closure and launch still require validation. No recipe was changed, client
started, credential supplied or proprietary license accepted by this selection.
Tor Browser 16.0.1 is selected from the pinned SecurityOps channel at
`34a0099058eada895d92069f36feb2267ebfa203`; the canonical specification
resolves to a single recipe. The required source gates check exact package
object identity, one occurrence and default output in the live OS and three
generated systems. A negative fixture replaces Tor Browser with a distinct
object and must be rejected. These are pinned selection checks, not a
provider-qualified selector or a runtime enforcement mechanism. Channel
changes must pass the same gates;
neither browser execution, anonymity nor current vulnerability status is
established by this repair.

The OS-local guixvis recipe preserves its GPL-3.0-or-later license and the
reviewed channel build/check/install behavior, with explicit Cargo compilation
jobs derived from Guix's build parallelism. This does not cap test-harness
threads or aggregate memory. Both archives have immutable
commit URLs and SHA-256 hashes; this binds their bytes, not an upstream
publisher signature. Standard pinned Rust/Cargo inputs retain Guix graft
semantics. No substitute key, channel, service, autostart or runtime Guix lookup
policy is changed. Cargo frozen/offline flags do not sandbox arbitrary build
scripts. Exact-provider tests cover source/vendor origins and compiler inputs;
they are not a build, web-service security audit or ISO/runtime approval.

Source validation restoration (2026-09-26): the image and A/B evaluator now
share `securityops/source-selection.scm`. Existing exclusions are preserved;
agent metadata, local evidence/runtime state and the named handoff artifacts
are also excluded at every directory depth. This basename policy is not a
content/secret scan or source authorization, and does not change Guix symlink
serialization. The evaluator separately rejects untracked selected inputs,
symlink/hardlink aliases and changed source identities. It retains immutable
tool checks, bounded subprocesses and failure on uncertain cleanup. Receipts
are private, ignored and excluded from the embedded source. The optional
singleton ShellCheck profile must pass manifest, closure and executable-identity
checks; it does not replace the canonical channel graph or authorize a cache.
The explicit `securityopsctl prepare-validation` command creates/verifies only
the private build lock, not a validation receipt or production approval. CLI
and wrappers reject unsafe existing files without modifying them: regular file,
current owner, one link, exact `0600`, owned non-group/world-writable root/out.
Directory-relative no-follow/nonblocking opens and pathname/inode checks precede
and follow nonblocking locking. Wrappers inherit the locked descriptor across
exec instead of reopening its name; checking a duplicate never explicitly
unlocks the parent's exclusive lock on that open-file description. The private
handoff expects an exclusive lock, not a borrowed shared-reader descriptor
(converting a shared flock is not guaranteed to preserve it on failure).
An environment flag alone is
not accepted as a held lock. The missing-lock evaluator check is unchanged.
This is cooperative serialization, not isolation from malicious code running as
the repository owner or root. A descendant retaining the inherited descriptor
keeps the lock busy until it closes it; never delete a busy lock to bypass it.
Source/channel admission and full system validation remain outstanding.
No production or ISO approval follows from preparation or focused tests.

Engineering source inventory (2026-09-26): 34 restored GUI/package-check inputs
were added to the isolated worktree's index, preserving all prior index entries.
The 31 historical Python bodies match their preserved seed; that provenance is
not publisher authentication or a full application security audit. The separate
Evelin checkout contains exactly 17 public source inputs at
`e96392d21ff408b82f73ce207ba0ab48312a2ed0`, not binaries or owner credentials.
Its unsigned example policies cannot authorize runtime execution. Installer 2
Apply remains disabled, and the Phase 46 Guix executor remains blocked.
Runtime/toolchain contract reconciliation is pending.
The historical test no longer terminates `flock` before its payload: a fixed
isolated Python payload signals readiness and exits on pipe EOF, then `flock`
reaps it before the test collects the supervisor. Real nonblocking flock
contention is checked before the negative authorization probe. All historical
assertions remain; no installer code or evaluator cleanup boundary was changed.
Regressions cover normal exit and injected assertion/KeyboardInterrupt exceptions,
not real signal delivery or crash recovery. The missing hardening/kernel-config
modules and their actual consumers were subsequently restored from reviewed
historical Phase 48 sources. This is engineering provenance, not signed publisher
admission. At that restoration checkpoint, quick passed 22 checks and 189 tests
in each A/B context, with zero failures/errors/skips. Full passed its source
suites but failed at `full-a`; `full-b` did not run. That was not approval of
the pinned-graph gate.
These source checks are not OS-sandbox containment or VM execution evidence.

`validate --full` limits automatic local package discovery to
`securityops/packages` using an internal Scheme entry in the unchanged pinned
Guix. Unlike `build -L`, `repl -L` keeps the root available for explicit imports
without adding it to recursive package discovery. Only the three fixed dry-run
commands are dispatched; extra options, a changed discovery list, noncanonical
root/package directories and nonprivate generated installer inputs fail closed.
Nonempty inherited Guix package paths and any inherited Guix command-extension
path are rejected before starting Guile. Guile module/compiled/extension paths must resolve within
root-owned nonwritable Store items; this preserves the evaluator's admitted
profile paths without treating Store identity as publisher admission or verifying
permissions throughout every descendant. Present but empty Guile paths are also
rejected: empty load/command paths can include the current directory. Unset paths
retain upstream defaults. The installer argument is a dynamic private
file, not a constant path. This avoids accidental execution of cache/test scripts
by enumeration; it does not sandbox trusted Scheme imports, close filesystem
check/use races, authenticate missing channel introductions, or authorize a
build. The source inventory, lock and environment gates remain required.
After this discovery repair, ten focused tests pass in current and pinned Guix.
Official quick/full fail source A (199 tests, one failure, no errors/skips): the
current user profile changed to one without Nonguix. A fresh-copy diagnostic
with the previous immutable profile passes 199 tests, and a separate full CLI
diagnostic completes kernel/image/installer dry runs. These are not official
A/B approval. Existing channel authentication warnings and the earlier timeout
remain recorded; no trust key, profile or production flag was changed here.

The opt-in evaluator `--pinned-guix` resolves the checked-in channel file using
the measured bootstrap Guix with authentication enabled and the existing
substitute order/fallback. Source inputs must be tracked, hash-bound and copied
privately under the existing shared lock. A fixed Scheme helper compares every
ordered channel identity (name, URL, branch, commit, introduction) before
exclusively creating a private result file; mixed diagnostic output is never
parsed as a profile path. The result must be an owned single-link regular 0600
file of at most 1024 bytes and identify a root-owned nonwritable Store profile,
manifest and Guix executable. Timeout, nonzero status, uncertain cleanup,
changed inputs or an invalid result block without a personal-profile fallback.
All subsequent tools/environments use the resolved profile and current-system
profile; ShellCheck admission remains separate. The process/resource limits
are unchanged. These are engineering identity checks, not a Scheme sandbox,
independent channel authentication, reproducible builds, boot or ISO approval.
Existing missing-introduction/trust warnings are not repaired by this option.

Normal `build.sh` execution has a separate restricted-discovery entry,
`securityops/build-image.scm`. It constructs only the fixed iso9660 command with
the existing label, source configuration and ordered substitutes/fallback;
callers may supply only the canonical root and positive ASCII resource flags.
Unexpected package-discovery entries, extra commands, arbitrary configuration
paths and noncanonical root/package directories are rejected before dispatch.
This entry intentionally builds when invoked: it does not broaden the three
dry-run operations allowed by `validate-full.scm`. It does not add the full
validator's pre-Guile environment guard to `build.sh`. Inherited Guile paths or
command extensions can execute before its checks, and explicitly imported
Scheme remains trusted executable code. Use a controlled environment; this is
not a sandbox, immutable-source/TOCTOU guarantee, channel admission or ISO test.
The wrapper retains its existing private lock, resource ordering and failure
status. Regression fixtures cannot return an OS and point to an absent daemon;
their passing results do not authorize production closure inputs or an ISO.

Please report security issues **privately** to **sac@securityops.co** (PGP on
request). Include affected component, version/build tag (`cat
/etc/securityops/build-id`), reproduction steps, and impact. We aim to
acknowledge within **72 hours** and to coordinate a fix and disclosure timeline
with you. Please do not open public issues for undisclosed vulnerabilities.

**Out of scope (by design — see "What this is NOT"):** physical observation of
the per-boot credential while it is displayed on trusted VT1, the absence of
full-disk encryption on the live medium, and the intentional lack of kernel
lockdown / module-signature enforcement.

---

## Layer 1 — Requested kernel configuration and build guards

The recipe is `linux-securityops`, using the version/hash in canonical settings
(currently 7.3.4 in this worktree) and Nonguix's broad-driver base.
`customize-linux` receives the
explicit overlay; `verify-required-kconfig` requires one exact resolved entry
per requested key, including disabled symbols, after configure and after build.
Missing, duplicate or mismatched entries fail the build rather than being ignored.

The 7.3.4 source pin is recorded through the maintainer CLI. Its fresh Guix
download matches the official compressed SHA-256; the detached developer
signature over the uncompressed tar was verified with an isolated public
keyring and Greg Kroah-Hartman's kernel.org-published full fingerprint
`647F28654894E3BD457199BE38DBBDC86092693E`. No ownertrust was added.
This does not authenticate the full Guix environment or production owner
authority. Hardening values and guards are unchanged, but configuration
resolution, compilation and boot must be revalidated for 7.3.4. In
particular, the historical 7.2.8 configure-only result below is not evidence
for the new kernel. All 29 names occur in the 7.3.4 Kconfig declarations;
that does not validate resolved values or dependencies.

The 7.2.8 source update verified the detached developer signature over the
uncompressed tar, using a disposable public keyring and Greg Kroah-Hartman's
full fingerprint published by kernel.org. WKD over HTTPS is the trust bootstrap;
ownertrust was not changed and this is not independent production authority.
All 29 requested symbols exist in the exact source tree. The real recipe's
configure-only phase prefix then passed all 29 resolved-value checks in Guix.
Its resulting `.config` SHA-256 is
`4f704721cc1bae0039ba05dbadb1894666b9fb36c2cd4dfe36085ab42f9428d7`.
The inherited base uses `oldconfig` and emits EOF notices for new options;
these remain in the raw log, not hidden as a warning-free build. Compilation,
post-build checks, boot and enforcement remain unvalidated. Hardening policy,
substitute trust and channel pins were not relaxed.

The Python 3.12.12 build prerequisite completed through source fallback, but
its upstream test runner reported `test_pha_required_nocert` failing once with
`ConnectionResetError` before its automatic retry passed. That first failure
and the upstream skips are retained; a successful derivation is not evidence
of a failure-free dependency suite. Its cause remains a release-validation
follow-up, not a waived failure or a diagnosed kernel defect.

The verifier is for builder-owned `.config` and repository-controlled policy.
It checks the opened port's regular-file type and initial 4 MiB size, and checks
cumulative line lengths. It is not a no-follow path API or a strict allocation
bound against a file growing concurrently: `read-line` allocates before the
post-read check. The tests execute it in a Guix builder with synthetic configs;
neither that fixture nor static phase wiring proves a real kernel compilation.

Additional explicit policy and rationale:

- `HZ_250` disabled, `HZ_1000=y`, `HZ=1000`: requested timer policy; no latency gain claimed.
- `VFIO_NOIOMMU` disabled: prohibit that VFIO operating mode.
- `CPU_MITIGATIONS=y`: retain compiled mitigation support.
- `IOMMU_DEFAULT_DMA_STRICT=y`, DMA_LAZY and PASSTHROUGH disabled: request strict
  translated DMA defaults, not identity mappings or deferred invalidation.
  Device compatibility and performance require later boot/hardware testing.

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

The overlay also requests `NET_SCH_CAKE=m` and `LRU_GEN_ENABLED=y`.
Their availability and performance must be measured on the resulting kernel.

> **Scope.** Sources request `CONFIG_SECURITY_LANDLOCK=y` and
> `lsm=landlock,yama,bpf`; effective enforcement needs boot/runtime evidence.
> The rest of the broader KSPP set in `securityops/securityops.defconfig`
> (`RANDSTRUCT_FULL`, `PAGE_TABLE_CHECK`, `STRICT_KERNEL_RWX`, `VMAP_STACK`,
> `APPARMOR`, IMA, `DM_CRYPT`/`DM_VERITY`…) belongs to the maintainer's
> **separate, dormant** single-laptop kernel and is **not** applied to this ISO.
> Editing that reference file does not change this recipe.

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

**Shared policy.** `(securityops hardening)` supplies `mitigations=auto`,
`intel_iommu=on`, `iommu.passthrough=0` and `iommu.strict=1` to live and generated
installed configurations. The four live menu variants no longer append
`iommu=pt` or `amd_iommu=on`. These requests do not prove firmware support,
effective IOMMU isolation, usable groups or passthrough compatibility.

---

## Layer 3 — Shared sysctl policy

`securityops-harden-sysctls` removes conflicting defaults by key before appending
the policy, preserving unrelated defaults. Both live and generated installed
configurations use it; `%securityops-sysctl` now contains live performance tuning
only. Tests exercise the actual expressions and Guix serializer, not host sysctls.

**Kernel / process:** `kernel.kptr_restrict=2` (hide kernel pointers),
`kernel.dmesg_restrict=1`, `kernel.yama.ptrace_scope=1` (ptrace children only),
`kernel.kexec_load_disabled=1`, `kernel.perf_event_paranoid=3`,
`kernel.unprivileged_bpf_disabled=1`, `net.core.bpf_jit_harden=2`,
`kernel.randomize_va_space=2` (full ASLR).

**Filesystem:** `fs.protected_symlinks=1`, `fs.protected_hardlinks=1`,
`fs.protected_fifos=2`, `fs.protected_regular=2`, `fs.suid_dumpable=0`.

**Network:** `tcp_syncookies=1`; `rp_filter=2` (**loose** anti-spoof — *loose by
choice*); IPv4 all/default `accept_redirects`, `secure_redirects`,
`send_redirects` and `accept_source_route` are zero. IPv6 all/default
`accept_redirects=0` and `accept_source_route=-1` are requested explicitly.

---

## Binary substitute trust

The live daemon and every system emitted by the guided installer replace Guix's
default cache list with exactly two ordered entries:
`https://substitutes.securityops.com.br` first and the official
`https://ci.guix.gnu.org` build farm second. Their repository-pinned Ed25519
public keys are the only substitute keys added by this configuration. `build.sh`
applies the same URL order to both the time-machine and image stages. Cache
misses build from source; this does not prevent pinned Git channels or package
source origins from being fetched.

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

## Layer 5 — Anonymity (Tor, operator opt-in)

`%tor-service` exposes loopback-only SOCKS (`9050`), transparent (`9040`), DNS
(`5353`), and cookie-authenticated control (`9051`) ports with `SafeLogging 1`.
Nothing redirects traffic merely because those listeners exist. Tooling includes
`torsocks`, `nyx`, Tor Browser, i2pd, and **Torando Control**; Torando can opt one
local user into transparent TCP/DNS routing plus a killswitch. **Caveat:** this is
not forced system-wide torification—other users/apps egress clearnet unless the
operator explicitly proxies them.

---

## Layer 6 — Memory / resilience

- **zram** — 6 GB `zstd` compressed RAM swap (the live root is a RAM overlay).
- **earlyoom** — kills at 5% free mem/swap, *before* the kernel OOM hangs the
  desktop; `avoid-regexp` protects the active Sway, XMonad/XLibre, or KDE core
  processes together with `greetd`/`tuigreet`/`shepherd`.
- **MGLRU** — enabled at boot (`lru_gen/enabled=y`, `min_ttl_ms=1000`).
- **prewarm-fontconfig** — builds `/var/cache/fontconfig` at boot (availability,
  not security): eliminates the multi-minute first-GUI-launch stall.

---

## Layer 7 — Attack-surface reduction

- Rare-protocol kernel blacklist (Layer 2).
- **No graphical display manager in the live image** — greetd + tuigreet
  (GL-free TUI) on VT7, with only `video`/`input` groups. Its immutable chooser
  starts Sway, XMonad on XLibre, or KDE without accepting an arbitrary command.
- **Desktop tradeoff is explicit** — Sway is the default native-Wayland path.
  KDE is a larger native-Wayland stack. XMonad intentionally adds the XLibre
  X11 server and therefore restores same-display X11 observation/injection
  risks; it is a compatibility option, not a hardening or isolation boundary.
  XWayland clients retain X11 semantics among themselves under Wayland too.
- **No XLibre masquerade** — the XMonad launcher and generated installed GDM
  configuration both construct an `xlibre-configuration` from the pinned
  XLibre packages. Failure to resolve XLibre stops evaluation instead of using
  Xorg under an XLibre label. The upstream channel lacks a signed Guix channel
  history at this checkpoint, an explicit supply-chain limitation.
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
- It requires exactly one kernel `root=` argument, decodes the pinned Guix ISO's
  bare DCE representation back to its ISO UUID, enumerates every duplicate UUID
  match, traces every match to all physical parent disks, and **refuses those
  boot media**. Resolution failures stop the installer before partitioning.
- It rejects mounted descendants, active swaps, device-mapper/RAID/LVM holders,
  disks below 64 GiB, and concurrent installer runs. Immediately before the
  wipe it rechecks the canonical device, major/minor, sysfs path, size, kernel
  disk sequence, WWN/serial when present, and live-root topology. After writing
  GPT it requires a fatal partition-table reread and validates each partition's
  parent, start, size, kind and GUID before formatting.
- Password plaintext never enters argv, environment, logs, the generated
  configuration, or the Guix store. The administrative password is converted
  through a protected descriptor to a yescrypt verifier held in a root-owned
  mode-0600 volatile file. Both accounts are declaratively locked; only after a
  successful system init is the verifier sent on stdin to the target
  `/etc/shadow`, verified, synchronized together with the root filesystem and
  separate ESP, and removed. Administrative input is restricted to 12–128
  printable US-ASCII bytes so the live TUI, PAM, and console consume the same
  reproducible bytes.
- Hostname and username are validated. The optional full name is bounded and
  rejects colons/control characters; every generated Scheme string is escaped,
  so a `"`/`\` cannot corrupt or inject into the configuration.
- On a mid-operation failure the error trap unmounts `/mnt` and closes the LUKS
  mapping only when per-run ownership and current device topology still prove
  they belong to this installer. If the COW helper or its worker cannot be
  terminated and authenticated recovery cannot prove completion, cleanup
  deliberately refuses to touch target/private state and requires operator
  recovery or reboot; this is reported as failure, never as "done".
- Init runs through the release's authenticated pinned `guix time-machine` in a
  private mount namespace, with an empty root-owned HOME/XDG configuration and
  the ordered Security Ops + GNU Guix CI URLs on both stages. Dynamic cleanup
  restores and hash/SQLite-validates the live Guix database, verifies the daemon
  transition, and removes the target-backed store overlay. A root-private
  lifecycle lock, fsync'd recovery journal, installer/container/supervisor
  identities, and separately journaled Guix worker process group make retries
  fail closed across signals or parent death; no database/store cleanup begins
  until the worker boundary is proven empty.
- Success is gated on the **real pinned `guix system init` exit code AND the
  presence of `/mnt/boot/grub/grub.cfg`** (written last)—never a false-positive.
- **Optional LUKS2 root-volume encryption** (`cryptsetup luksFormat`, AES-XTS)
  with matching initrd crypto modules and an exact Argon2id keyslot profile of
  `time=4`, `memory=65536 KiB`, `parallelism=1`, verified from LUKS2 JSON after
  formatting. The pinned GRUB EFI 2.14 module set includes LUKS2/Argon2 support;
  the full installed cold-boot test remains a mandatory release gate. The UEFI
  system partition remains unencrypted. LUKS input is restricted to 20–254
  printable US-ASCII bytes, and the trusted live input path visibly switches to
  US for passphrase creation because GRUB's first cryptomount prompt precedes
  its installed keyboard map. Plaintext variables are unset immediately after
  the mapping opens.
- The release installs an unsigned GRUB/kernel chain. It therefore refuses to
  erase a disk unless exactly one non-symlink `SecureBoot` efivar is a regular
  five-byte value (four attribute bytes plus one UINT8) whose value is explicitly
  zero; enabled, absent, truncated, extended, or otherwise malformed policy
  fails closed.

**Esquema (rootless container runtime).** Ships in the profile for defense-in-
depth process isolation without a daemon or root: unprivileged **user namespaces**
plus mount/PID/UTS/IPC/net/cgroup namespaces, `pivot_root`, **full capability
drop**, a **seccomp-BPF syscall allowlist**, and `NO_NEW_PRIVS`. The FFI only
`dlopen`s `libesquema.so` from `$ESQUEMA_LIBDIR` (the immutable store path), never
a writable working directory.

---

## What this is **NOT** (honest limitations)

- **The live medium itself is not encrypted** — its root is a read-only iso9660 +
  volatile RAM overlay, so no disk/UUID/LUKS is referenced on the ISO.
  **LUKS2 root-volume encryption is available when installing**, but the UEFI
  system partition remains unencrypted—see Layer 8.
- **No kernel lockdown / no module-signature enforcement** — *on purpose*, so
  pentest tooling and out-of-tree drivers load freely.
- **No Secure Boot** — GRUB boots an unsigned kernel; no measured boot.
- **Not amnesic like Tails** — non-persistent only because the root is a RAM
  overlay; there is **no** enforced RAM-wipe on shutdown and **no** anti-forensic
  protection against disks you mount.
- **Tor is available, not enforced** — `output` policy is accept-all.
- **Local-console credential exposure** — the `securityops` password is freshly
  generated for each boot and displayed only on VT1. It is not embedded in the
  ISO, argv, environment, or logs; root remains locked and sudo requires that
  password. A person who can observe/control the physical console can still
  authenticate during that boot, which is inherent to this recovery-oriented
  live-media workflow.
- **Handled early-boot memory probe** — the statically linked Guile init uses
  BDWGC's guarded address-space limit probe.  Linux can log the probe's handled
  `SIGSEGV` before the collector restores the signal handler; init continues
  and this message alone does not mean PID 1 crashed.  Boot qualification still
  treats a missing activation or login prompt as a failure rather than assuming
  every such message is benign.
- **No early CPU microcode update** — plain `base-initrd` is used (the nonguix
  `microcode-initrd` panicked under the iso9660 loader).
- **`random.trust_cpu=on`** — trades entropy conservatism for instant CRNG init.

---

*Sources of truth: `securityops/kernel.scm`, `config.scm`, `securityops/sessions.scm`.
`securityops/securityops.defconfig` is reference-only and not consumed by the ISO build.*
