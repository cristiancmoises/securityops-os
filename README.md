<div align="center">

# Security Ops OS

### *In Code We Trust.*

**A hardened, privacy-focused GNU/Linux distribution, assembled declaratively with GNU Guix — as a portable x86_64 live ISO.**
*Custom Linux 7.3.4-SecurityOps · Sway / XMonad+XLibre / KDE · guided disk installer · curated offensive & forensics toolkit · Tor on tap.*

`build r13 · v1.14.0 · sway · kernel 7.3.4` &nbsp;•&nbsp; © Cristian Cezar Moisés &nbsp;•&nbsp; first-party OS code: AGPL-3.0-or-later or separate commercial agreement &nbsp;•&nbsp; sac@securityops.co

</div>

---

## What is it?

Security Ops OS is a hardened, privacy-focused GNU/Linux distribution built
declaratively with GNU Guix and shipped as a hybrid BIOS/UEFI **live ISO** for
x86_64 PCs — boot it from a USB stick (or Ventoy), run it live, or install it
to disk with the guided installer.

**Current release — v1.14.0** (build `r13 · sway · kernel
7.3.4-SecurityOps`, 2026-11-13):

- **Kernel** — custom Linux **7.3.4-SecurityOps** (hardening + performance
  recipe) built from the cdn.kernel.org source, with the SHA-256 pinned in
  `securityops/settings.json`.
- **Channels** — the maintainer's full working graph pinned at exact
  authenticated commits: `guix`, `nonguix`, `radix`, `rosenthal`, `small-guix`,
  `securityops`, `gocix`, `sops-guix` (`channels.guix`).
- **Newest overrides** — Thunar 4.20.10 · Heroic 2.22.1 · Steam 1.0.0.87 ·
  Tor Browser 16.0.1 · guixvis 0.8.0 · Installer 2 0.1.0 · Guix Center 0.2.0.
- **ArtCraft suite** — all 13 official Linux apps (table below).
- **Sessions** — Sway (default) · XMonad+XLibre · KDE Plasma.
- **Fast-install flow** — guided disk installer + Installer 2 + Guix Center.
- **Substitutes** — Security Ops build farm first, GNU Guix CI fallback.
- **Distribution** — one-file ISO over direct HTTPS or webseeded torrent;
  checksums and links in [GET_THE_ISO.md](GET_THE_ISO.md).

### Key packages at a glance

| Category | Packages |
|---|---|
| **Anonymity & browsing** | Tor Browser 16.0.1 · LibreWolf · Tor · torsocks · nyx · i2pd · Torando GUI |
| **ArtCraft creative suite (13)** | PhotoCraft 0.9.0 · VectorCraft 0.10.0 · FilmCraft 0.7.2 · LightCraft 0.8.0 · PdfCraft 0.8.0 · EffectCraft 0.10.0 · DesignCraft 0.8.0 · FigCraft 0.6.0 · WordCraft 0.7.0 · SoundCraft 0.5.0 · DeckCraft 0.7.0 · CADCraft 0.7.0 · GridCraft 0.7.0 |
| **Desktops & terminals** | Sway · XMonad + XLibre · KDE Plasma · wezterm · fish · starship |
| **Security tooling** | nmap · Wireshark · aircrack-ng · hashcat · John · Hydra · radare2/rizin · binwalk |
| **Gaming & desktop apps** | Steam 1.0.0.87 · Heroic 2.22.1 · Thunar 4.20.10 |
| **OS management** | `securityopsctl` · guixvis 0.8.0 · Security Ops Installer 2 · Guix Center |
| **Native tools (channel)** | Evelin · Esquema · Zupt · Turbo Recorder · Torando |
| **Kernel** | `linux-securityos` 7.3.4 — KSPP-subset hardening + performance overlay |

The complete per-function inventory is in [docs/PACKAGES.md](docs/PACKAGES.md).

<details>
<summary><b>Engineering log — historical validation notes</b></summary>

Kernel version syntax, 2026-10-21: the CLI and Guile adapter accept canonical
`X.Y` initial releases and `X.Y.Z` patch releases literally, without adding or
removing `.0`. Release metadata still requires `X.Y.Z` or `X.Y.Z-rc.N`.
Historical check, 2026-10-21: the Linux 7.3 CLI dry run reached the
download prerequisite but Guix was then unavailable on CT128. That attempt
left the then-current 7.2.11 pin and channels unchanged.
Parser tests are not source authentication, a kernel build, boot or ISO evidence.

Historical source candidate update, 2026-10-17: Linux 7.2.11 was pinned through
`./securityopsctl kernel set 7.2.11`, after a real dry run. The official archive's
SHA-256 and Guix nix-base32 match; its developer signature over the uncompressed
tar was freshly verified using an isolated public keyring. Channel pins,
package overrides and hardening are unchanged. This is source metadata, not a
compiled or booted kernel. The 29-value configure-only result below belongs to
7.2.8 and does not qualify 7.2.11; pinned derivation, configure/build, boot and
ISO checks remain required before release.

Historical kernel source update, 2026-09-26: Linux 7.2.8 was pinned through
`./securityopsctl kernel set 7.2.8`, with locally measured Guix/SHA-256 hashes
and a verified kernel.org developer signature. A configure-only Guix derivation
executed the real recipe through its strict guard: all 29 required values passed,
including HZ=1000, strict IOMMU and disabled VFIO no-IOMMU. The hardening recipe
and channel pins are unchanged. This does not compile or boot the kernel,
repair the previously reported live-boot errors, or provide a rebuilt ISO.
The release/build labels above remain source metadata, not a published artifact.

Packaging repair, 2026-09-26: the isolated Guix Center and Installer 2 recipes
now declare their Bash, Python and Qt/GTK runtime paths. Build both packages
with `guix build -L "$PWD" -e '(@ (securityops packages guix-center) securityops-guix-center)' -e '(@ (securityops packages installer2) security-ops-installer2)'`.
Check the returned Store outputs with
`python3 -I -B tests/check_gui_package_artifacts.py --guix-center STORE_OUTPUT --installer2 STORE_OUTPUT`.
This checks launchers, preserved source bodies and imports without starting
applications. These engineering builds do not update an ISO, authenticate its
channel graph, validate boot, or prove installation. Installer 2 remains a
planner: its destructive Apply operation is disabled. Release/source
reconciliation and live/install validation remain outstanding; the historical
release metadata below does not identify these new package outputs.

Application selection (2026-09-27, refreshed 2026-11-13): canonical overrides
now select Thunar 4.20.10, Guix Center 0.2.0, Installer 2 0.1.0, Heroic 2.22.1
from Nonguix, Steam 1.0.0.87 from the pinned SecurityOps channel, Tor Browser
16.0.1 from the pinned SecurityOps channel, and guixvis 0.8.0 (formerly
pacvis).
Inspect them with
`./securityopsctl package changes`. The overrides feed both the live OS and
generated installed systems; tests load the real OS package lists and check
provider identity, uniqueness and the default output in each supported desktop
configuration. This is source integration, not an application launch or a new
ISO. Installer 2 remains planner-only with installation disabled. Historical
Store provenance findings, boot and installation validation remain unresolved.
The Steam version identifies its bootstrap launcher, not its self-updating
client. No client launch, account login, license acceptance or game test is
included. The inherited Steam HTTP origin (hash-pinned) and Heroic's disabled
runpath validation remain explicit release-review concerns; see SECURITY.md.
The Tor override also supplies the browser to generated installed systems,
where it was previously absent. `torbrowser@16.0.1` resolves to a single
recipe in the pinned graph; required selection tests enforce the package
object and reject provider drift. This is not a browser launch or an
anonymity/security audit; future pin changes require fresh validation.

The OS-local GPL guixvis recipe imports the reviewed SecurityOps channel recipe
from commit `017b9e3aa09bbafca341dfba7c91ca96211e8020`, using immutable HTTPS
archive URLs and measured hashes. The build channel pin advances to
`34a0099058eada895d92069f36feb2267ebfa203` for the refreshed r13 image, while
the guixvis origins stay at the reviewed commit. Build/test phases remain
frozen/offline Cargo with web support and the pinned Guix Rust
and Cargo inputs. Cargo compilation jobs follow Guix's selected core count
(one job when parallel builds are disabled), not a total-memory/thread cap.
Run `guixvis` for the terminal UI or explicitly invoke
`guixvis web` for its loopback web UI; no service is started automatically.
The canonical recipe was built once through the pinned graph: 121 Rust tests
passed, with two upstream live/cache tests ignored; `--help` and `--version`
also passed. This is not reproducibility, full interactive/indexer validation
or ISO qualification; the earlier private diagnostic build remains separate.

Source validation restoration, 2026-09-26: run
`./tools/validation/securityops-validate quick` for the independent A/B source gate,
or `./tools/validation/securityops-validate full` for the additional pinned-graph
dry runs. Both use the same embedded-source selector as `config.scm` and keep
private receipts under ignored `.dsh/state/`. The restored evaluator and
selector passed 50 focused tests in each of two independent contexts. This
does not approve the whole project. Bash syntax checks now parse each of the
five scripts separately in each pass: one `bash -n` with several filenames
only parses the first script. ShellCheck still receives the complete list.
Historical grouped Bash checks do not establish syntax coverage of the other
four scripts. This correction is not build or ISO qualification.
When ShellCheck is absent from the admitted
base profiles, both modes accept `--check-tools-profile /gnu/store/...-profile`
only for a validated immutable singleton ShellCheck profile, not an arbitrary
PATH extension. A disposable profile made from the existing ShellCheck Store
item passed that admission without changing the host profile or trust keys.
When the personal Guix profile differs from the repository channels, use
`./tools/validation/securityops-validate quick --pinned-guix` (or `full`), appending
`--check-tools-profile /gnu/store/...-profile` if required. This opt-in resolves
`channels.guix` once for the evaluator, compares channel names, URLs, branches,
commits and introductions with the resulting immutable profile, and uses that
profile plus the current-system profile throughout A/B and full validation.
There is no personal-profile fallback after resolution. The bootstrap Guix and
selected tools are recorded separately. Resolution can fetch channel code and
write the Store; it does not update host profiles, pins, keys or build an ISO.
The existing 20 GiB free-space floor applies to both the worktree filesystem
and `/gnu/store`: a worktree on another SSD does not relocate the Store.
Full mode still performs the CLI's own pinned dry runs. Matching metadata is
not publisher authentication; existing channel trust warnings remain blockers
to stronger release claims. Without the option, historical behavior is unchanged.
Before the first validation in a new checkout, run
`./securityopsctl prepare-validation`. It only creates/verifies the private
`out/.iso-build.lock`; it does not invoke Guix, modify settings, or start a build.
The CLI and both build wrappers share the same no-follow, nonblocking opener.
Existing locks must be owned regular single-link files with mode `0600`; the
repository and `out/` must be owned and not writable by group/others. Unsafe
existing locks are refused, never chmodded, removed or replaced automatically.
The evaluator still requires an existing lock and retains all source/tool gates.
The isolated repair worktree now tracks the 34 reviewed GUI/package-check inputs.
Neither step authenticates publishers or provides a compiled runtime.
The historical test's orphaned child was fixed using readiness plus pipe EOF,
allowing the unchanged `flock` supervisor to reap its child. Three regressions
cover normal return, assertion failure and injected Python `KeyboardInterrupt`;
they do not simulate real signals or power loss.

Hardening restoration, 2026-09-26: the missing modules were found in the same
historical Phase 48 checkout as the evaluator. The shared policy now feeds both
live and generated installer configurations; the kernel recipe declares its
strict Kconfig verifier before and after compilation. HZ=1000, strict IOMMU
defaults and disabled VFIO no-IOMMU are requested policy, not hardware evidence.
At the hardening-restoration checkpoint, quick passed all 22 checks, with 189 tests in each A/B
context with zero failures/errors/skips. Tests also build the helper's actual
Guix imported-module closure and check synthetic inputs inside that builder.
This did not compile the kernel or execute its full build phases. That full gate
passed its A/B source suites but failed at `full-a`; `full-b` was not executed.
Pinned-graph/live/install validation remains outstanding. No channel pin, kernel
version, host configuration or production approval was changed by this repair.
Do not create substitute prerequisites or bypass checks to report PASS.
No new ISO was built.

Full-validation discovery repair, 2026-09-26: `securityopsctl validate --full`
now runs its three fixed dry runs through an internal Scheme entry inside the
same pinned `guix time-machine`. Local package enumeration is limited to
`securityops/packages`; explicit imports and relative assets still use the
checkout. This prevents recursive discovery of `out/cache` and test scripts.
Channel discovery entries, substitute order, fallback and locking are preserved.
Unexpected arguments, noncanonical source paths, nonempty `GUIX_PACKAGE_PATH`
and any inherited `GUIX_EXTENSIONS_PATH` are refused. Guile module, compiled
module and extension paths must resolve beneath root-owned nonwritable Store
items, preserving the evaluator's profile paths. This is a location check, not
admission of code or verification of every descendant's permissions. Present
but empty Guile paths are refused; unset paths retain upstream defaults.
Settings are never silently discarded. The generated installer path is dynamic
and must identify a private regular single-link file. This is not a Scheme sandbox,
channel authentication, kernel build, ISO build or live/install approval.

Validation snapshot for this repair: all ten focused tests pass in both current
and pinned Guix. Official quick/full now stop in source A (199 tests, one failure,
no errors/skips) because the current user Guix profile no longer supplies
`(nongnu packages linux)`. The host profile was not changed by this repair.
A separate fresh-copy diagnostic using the previous immutable profile passes
199 tests; its full CLI diagnostic completes the three pinned dry runs in
880 seconds. Neither replaces official A/B approval or channel authentication.
The earlier 300-second timeout is retained. No new ISO was built.

Normal-build discovery repair, 2026-09-27: both `build.sh` branches now use
`securityops/build-image.scm` to limit local package discovery to
`securityops/packages`, while keeping the checkout available for imports.
The entry accepts only the canonical root and positive `--max-jobs=N` /
`--cores=N` arguments, preserving their order and duplicates. Image type, label,
configuration, substitute order and fallback are fixed internally; the outer
pinned time-machine invocation and lock are unchanged. Unexpected discovery
entries fail closed. Unlike the full validator, this entry performs a real build
when invoked normally: its regression tests stop before returning an OS and use
an unavailable daemon socket. Those tests are not an ISO build or boot approval.
The full validator remains a separate, unchanged dry-run-only entry.
This repair does not sandbox Scheme or add the full validator's environment
guard to normal builds; use a controlled build environment.

</details>

**Security Ops OS** is a complete operating system defined by a pinned **Guix
configuration and module tree** — and shipped as a hybrid BIOS/UEFI **live ISO** you can
`dd` to a USB stick (or drop into Ventoy) and boot across a broad range of
**x86_64 PCs**.

The distribution identifies itself as **Security Ops OS** through
`/etc/os-release`, `/etc/issue`, the kernel's `-SecurityOps` release suffix, and
the source-built `uname -o` field. Linux and GNU Guix provenance remains
explicit. Exact command behavior and licensing boundaries are documented in
**[docs/OS-IDENTITY.md](docs/OS-IDENTITY.md)** and
**[Português](docs/OS-IDENTITY.pt-BR.md)**.

It is built for **security professionals, power users, privacy enthusiasts, and
the Guix-curious** who want one image that is:

- 🔁 **Declarative & pinned** — the whole OS is `channels.guix`, `config.scm`,
  `securityops/settings.json`, and the imported `securityops/` modules.
  Anyone can use `guix time-machine` to reconstruct the pinned channel graph.
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
- ⚡ **Fast default session** — Sway and its core tools live in the system
  profile, while a boot-time fontconfig prewarm reduces cold first launch.
  XMonad+XLibre and KDE are explicit alternatives, not hidden fallbacks.
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
| **Pinned / declarative system** | ✅ Scheme, pinned, rebuildable | ⚠️ vendor ISO only | ❌ | ⚠️ template split | ❌ | ❌ | ✅ |
| **Atomic rollback / generations** | ✅ Guix generations | ❌ | ❌ | ⚠️ clone/revert | ❌ | ❌ | ✅ |
| **Boot-anywhere live USB** | ✅ `dd`/Ventoy, RAM overlay | ✅ | ⚠️ VMs | ❌ installed | ❌ | ✅ | ⚠️ installer |
| **Amnesic / leave-no-trace** | ⚠️ stateless, *not* anti-forensic | ✅ engineered | ⚠️ | ✅ DisposableVM | ❌ | ⚠️ | ❌ |
| **Tor** | ⚠️ SOCKS, **opt-in** | ✅ forced, fail-closed | ✅ gateway VM | ⚠️ via Whonix | ❌ | ⚠️ AnonSurf | ❌ |
| **Isolation model** | hardened single domain | anonymity+amnesia | 2-VM network iso | ✅ Xen hardware iso | hardening | none | DAC |
| **Kernel hardening** | ✅ KSPP subset, *no lockdown* (by design) | ⚠️ moderate | ✅ + AppArmor | ✅ dom0 | ✅✅ hardened_malloc | ❌ minimal | ⚠️ stock |
| **Pentest toolkit OOTB** | ✅ curated (no MSF; Burp CE + Maltego included) | ❌ | ❌ | ❌ | ❌ | ✅✅ exhaustive | ❌ |
| **Default desktop** | Sway; XMonad+XLibre/KDE selectable | GNOME | XFCE | XFCE | XFCE | XFCE/MATE | any |
| **Learning curve** | high (Guix/Scheme) | low | moderate | high | moderate | moderate | high |

**Where it fits:** none of the others give you a *pinned + declarative +
rollbackable Security Ops OS distribution built with GNU Guix* that is **also**
a curated pentest/forensics image targeting **broad x86_64 hardware coverage**.
If you need enforced anonymity → **Tails/Whonix**;
strongest isolation → **Qubes**; maximal hardening → **Kicksecure**; the biggest
turnkey tool catalog → **Kali/Parrot**. Security Ops OS combines
*pinned construction + portability + pragmatic hardening + Tor-on-tap + a real toolkit*,
and is honest about the rest.

---

## Quickstart

### 1. Get the ISO
Build it yourself from pinned inputs. The published v1.14.0 image is
**temporarily unavailable** while a boot regression found in QEMU validation
is fixed; the release assets were withdrawn from every public mirror. No
direct link, torrent or magnet link is published until a fixed image passes
boot validation on QEMU and physical hardware.

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

The live user is **`securityops`**. Each boot generates a new password and
shows it only on trusted local **VT1**; press `Ctrl+Alt+F1` to read it and
`Ctrl+Alt+F7` to return to the login screen. The same one-boot password is
required by `sudo`; root is locked. At the greeter press **F3** to select
**Sway**, **XMonad + XLibre**, or **KDE Plasma**; Sway is the explicit default.
`cat /etc/securityops/build-id` confirms which build you booted.

The XMonad choice starts the pinned XLibre server rather than relabelling Xorg;
KDE runs natively on Wayland. See the desktop behavior and security tradeoffs
in **[docs/DESKTOPS.md](docs/DESKTOPS.md)**.

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
| **Encryption** | optional **LUKS2-encrypted root volume** with a pinned Argon2id profile (`t=4`, `64 MiB`, `p=1`); the UEFI system partition remains unencrypted and plaintext is unset immediately after the mapping opens |
| **Desktop** | **Sway** (Wayland) · **XMonad + XLibre** (X11) · **KDE Plasma** (Wayland) |
| **Locale / timezone / keyboard / hostname** | picked from menus; encrypted installs visibly switch passphrase entry to US because the first GRUB cryptomount prompt precedes the installed keymap |
| **Accounts** | your password-protected administrative user (12–128 printable US-ASCII bytes); root remains locked (a yescrypt verifier exists only in root-private volatile installer state, then the installed `/etc/shadow`) |

It **generates a self-contained declarative `/etc/config.scm`** for your exact
choices, partitions the disk, makes the filesystem and runs `guix system init`
through the release's pinned channel time-machine.
The installed system ships a **hardened base + a curated core toolset** (the
live image's full arsenal is one `guix install` away). It stays 100 %
declarative — the installer also copies the `(securityops …)` modules and pinned
channels to the target. Reconfigure with the same pinned graph (the XLibre
channel-authentication caveat is documented below):

```sh
sudo guix time-machine -C /etc/guix/channels.scm \
  --substitute-urls='https://substitutes.securityops.com.br https://substitutes.securityops.co https://ci.guix.gnu.org' --fallback -- \
  system reconfigure -L /etc/securityops/src \
  --substitute-urls='https://substitutes.securityops.com.br https://substitutes.securityops.co https://ci.guix.gnu.org' --fallback \
  /etc/config.scm
```

> **Safety:** nothing is written until you **type the target device path** to
> confirm. The installer refuses every disk matching/backing the live root,
> active mounts, swaps and device holders, revalidates disk identity and the new
> GPT geometry, enforces a 64 GiB minimum, and routes the install through a private mount-namespace
> `cow-store` overlay so the build lands on the target disk (not RAM). Because
> this release's installed boot chain is unsigned, Secure Boot must be explicitly
> reported disabled before a disk can be erased. LUKS passphrases are restricted
> to 20–254 printable US-ASCII bytes so they remain reproducible at the pinned
> GRUB 2.14 prompt. The target root, ESP, and administrative shadow update are
> synchronized and installer-owned mounts are closed before success is shown.

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
media, and dev — plus the three selectable desktop stacks. **Complete table →
[docs/PACKAGES.md](docs/PACKAGES.md).**

### Security Ops native tools (the **securityops** channel)

| Tool | What it is | License |
|---|---|---|
| **Evelin** | Post-quantum secure tunnel (SSH-shaped): ML-KEM-1024 + ML-DSA-87 + ChaCha20-Poly1305 | **AGPL-3.0-or-later or separate signed commercial agreement** |
| **Esquema** | Rootless, Guile-native container runtime — user/mount/PID/net/cgroup namespaces, `pivot_root`, cap-drop, seccomp-BPF allowlist, `NO_NEW_PRIVS` | GPL-3.0-or-later; no separate commercial option observed |
| **Zupt** | Post-quantum backup & compression (ML-KEM-768 + X25519 hybrid encryption) — CLI + Qt GUI | AGPL application scope / GPL codec scope, or a separate agreement for controlled first-party rights |
| **Turbo Recorder** | Auto-configuring HW-accelerated screen+audio recorder (NVENC/QSV/VAAPI/AMF) | GPL-3.0 |
| **Torando** | Transparent Tor proxy + leak killswitch for one user, with a live-status GUI | AGPL-3.0-only |
| *BTP* *(planned)* | Berkeley Transport Protocol — PQ successor to HTTP+TLS | Apache-2.0 (impl) |
| **mirim** | Tiny encrypted-at-rest embedded SQL DB, `#![forbid(unsafe_code)]` Rust — baked into the image as of r13 | **AGPL-3.0-only engine scope (explicit support files remain MIT), or a separate agreement for controlled first-party rights** |

### Third-party tools repackaged in the **securityops** channel (included on the image)

| Tool | What it is | Version | License |
|---|---|---|---|
| **Burp Suite Community** | Web application security testing toolkit (official PortSwigger JAR, launched on OpenJDK 21) | 2026.10.1 | PortSwigger EULA |
| **Maltego Graph** | OSINT / link-analysis graph suite (official Maltego Linux distribution) | 4.14.0 | Maltego proprietary EULA |
| **PhotoCraft** | Photo editing | 0.9.0 | ArtCraft proprietary binaries; per-app source terms |
| **VectorCraft** | Vector graphics | 0.10.0 | ArtCraft proprietary binaries; per-app source terms |
| **FilmCraft** | Video editing | 0.7.2 | ArtCraft proprietary binaries; per-app source terms |
| **LightCraft** | Photo management | 0.8.0 | ArtCraft proprietary binaries; per-app source terms |
| **PdfCraft** | PDF tools | 0.8.0 | ArtCraft proprietary binaries; per-app source terms |
| **EffectCraft** | Visual effects | 0.10.0 | ArtCraft proprietary binaries; per-app source terms |
| **DesignCraft** | Graphic design | 0.8.0 | ArtCraft proprietary binaries; per-app source terms |
| **FigCraft** | Diagrams and figures | 0.6.0 | ArtCraft proprietary binaries; per-app source terms |
| **WordCraft** | Word processing | 0.7.0 | ArtCraft proprietary binaries; per-app source terms |
| **SoundCraft** | Audio production | 0.5.0 | ArtCraft proprietary binaries; per-app source terms |
| **DeckCraft** | Presentation decks | 0.7.0 | ArtCraft proprietary binaries; per-app source terms |
| **CADCraft** | 2D/3D CAD | 0.7.0 | ArtCraft proprietary binaries; per-app source terms |
| **GridCraft** | Spreadsheets | 0.7.0 | ArtCraft proprietary binaries; per-app source terms |

For the inspected local Evelin, VaptVupt, libvuptsdk, Mirim, and
Cofre Soberano PQ repositories, the recorded scope describes a separate
commercial path for controlled first-party rights. Esquema remains
GPL-3.0-or-later with no separate commercial option in the canonical source
observed for Phase 30. VaptVupt Codec retains GPL-3.0-or-later as its public
option; BTP remains Apache-2.0/CC-BY-4.0 and has no separately declared
commercial path. Different terms always require a project-specific written
agreement signed by the applicable copyright holder and licensee. A commercial
notice is not a grant, and one project's agreement does not cover another.
Every dependency and packaged program retains its own license. See [the
licensing policy](docs/LICENSING.md).

---

## 📡 The `securityops` Guix channel — *recommended*

The current app set comes from the authenticated `securityops` channel together
with nonguix and small-guix; the latter's gocix/sops-guix dependencies are also
explicitly pinned. XMonad's XLibre server ships inside the authenticated
`securityops` channel itself; every entry in the channel closure carries its
published channel introduction. The exact channel closure is in
[`channels.guix`](channels.guix). You can also add the Security Ops channel to any
Guix system, not just this ISO:

```scheme
;; ~/.config/guix/channels.scm
(cons (channel
        (name 'securityops)
        (url "https://git.securityops.com.br/cristiancmoises/securityops-channel.git")
        (branch "main")
        (introduction
         (make-channel-introduction
          "fb3223f3afdc14bab294c78d88e545eda2b146d9"
          (openpgp-fingerprint
           "0CFA 43B9 AA96 42EA AF2B  E983 C4C6 61C9 ECFB 46E8"))))
      %default-channels)
```
```sh
guix pull
guix install evelin-bin zupt turborec torando-gui   # then use them anywhere
```
The channel depends on nonguix; use this repository's `channels.guix` when you
want the complete pinned set without assembling dependencies manually. All
entries carry their published channel authentication.
Browse it: **https://git.securityops.com.br/cristiancmoises/securityops-channel**

Guix may warn that `small-guix` is “not trusted” when its introduction is not
also present in the invoking user's `trusted-channels.scm`. The pinned entry
still contains its published introduction and commit authentication remains
enabled; the warning records local channel-consent state. Do not replace it
with `--disable-authentication`.

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
./securityopsctl release set 1.14.0 --revision r13
./securityopsctl apply --add sqlmap --remove vlc --kernel 7.1.9 --build
./securityopsctl validate --full
./securityopsctl build --bundle --prune-old
```

`securityops/settings.json` is the single source of truth for release/kernel
metadata and package add/remove overrides. `securityopsctl` validates its
schema, edits it atomically under the ISO build lock, obtains kernel hashes from
the official kernel.org tarball, and keeps the hand-written package groups
untouched. Package-only changes reuse the kernel and all unchanged Guix store
paths; kernel-only changes rebuild the kernel-dependent path.

Local development images can retain the last published release identity. Before
publishing a formal release, use `release set` and regenerate the release
notes/download guide from the verified artifact; ordinary package and kernel
experiments never rewrite prose documentation.

---

## Source integrity with CodeMark

The release bundle workflow verifies the source with
[CodeMark 0.3.0](https://github.com/cristiancmoises/codemark/tree/12258d819d636a00453687db1cff9389372303a9)
before building and again before publishing the bundle. The portable executable
is checked into `tools/codemark.pyz` with SHA-256
`d6c9dd09db850a704ff0a33a7a3c75f287d014281ccc4f63a4b9249e873da163`;
its GPL-3.0-or-later license is in `tools/CODEMARK-COPYING`.

```sh
python3 tools/codemark.pyz verify . --json
```

`.codemark/project.json` and `.codemark/manifest.json` are the reviewed source
reference. The release bundle carries copies of both files. After an intended
source change, review the diff, update the reference with
`python3 tools/codemark.pyz mark . --apply`, rerun the project tests, and commit
the changed source and metadata together. The release build never refreshes the
reference automatically.

CodeMark marks supported first-party text sources. Its `skipped` report includes
`securityopsctl` (an extensionless Python program), `securityops/settings.json`,
documentation, binaries, and the ISO. The ISO and its release parts still require
the published SHA-256 checks in the download instructions. This CodeMark
reference is currently unsigned: it detects changes against the committed
manifest but does not authenticate the publisher. A trusted signing key and
independently pinned fingerprint are needed for authenticated provenance.

---

## Build it yourself (pinned and declarative)

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
`--bundle` additionally creates checksum-addressed split transport parts and
proves that they reassemble byte-for-byte. That is packaging evidence, not
release readiness. It needs roughly one additional ISO's worth of free space.
`--prune-old` removes older local ISOs/bundles only after the new output has
verified successfully. Multi-GB `out/` is git-ignored.

Pinned inputs and a successful build make the image reconstructible; they do
not by themselves prove reproducibility. Reproducibility for this candidate is
**BLOCKED** until two independent clean full ISO builds complete and their
unsigned payloads are compared. Any mismatch must be investigated rather than
reported as PASS.

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

- **First-party code in this repository:** **AGPL-3.0-or-later or a separate,
  signed Security Ops OS commercial agreement** — see **[LICENSE](LICENSE)**,
  **[NOTICE](NOTICE)**, and **[licensing scope](docs/LICENSING.md)**.
  The GNU Guix-derived `securityops/installer/cow-system-init.scm` and
  `securityops/bootloader.scm` helpers are explicit exceptions: they are
  **GPL-3.0-or-later only**, with no Security Ops commercial relicensing option
  asserted for upstream-derived rights.
- **Bundled tools and dependencies** keep their own licenses. A commercial
  agreement for the OS definition does not relicense an ISO's components.
- **Copyright © Cristian Cezar Moisés.** All rights reserved where applicable.
- **Contact / commercial licensing / security reports:** **sac@securityops.co**

<div align="center">

**Security Ops OS — In Code We Trust.**
*Declarative. Hardened. Yours to rebuild.*

</div>
