# Changelog — Security Ops OS

All notable changes to the **Security Ops OS** live image are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/); this project
versions the *image*, not individual packages (those track the pinned channels in
`channels.scm`). Each build also carries a visible `build-id` (GRUB menu, login
greeting, `/etc/securityos/build-id`).

© Cristian Cezar Moisés · AGPL-3.0-or-later · sac@securityops.co

> **Current: `1.10.0` ("Security Ops" r8 · guided installer · kernel 7.1.2)** —
> a branded on-ISO guided installer (`security-ops-install`) turns the live image
> into an installed system in minutes; the Esquema rootless container runtime is
> baked in; the custom kernel moves to Linux **7.1.2**.

## [1.10.0] — 2026-07-04  ("Security Ops" r8 · guided installer · kernel 7.1.2)

The live image is now **installable**. Everything the live ISO already gave you —
the hardened kernel, the sway desktop, the security toolset — can now be written
to a real disk (optionally LUKS-encrypted) by a branded, guided TUI. No manual
`guix system init`, no hand-written `config.scm`.

### Added
- **`security-ops-install` — a guided, branded disk installer** shipped *in* the
  live ISO (run `sudo security-ops-install`). A black-background / cyan-text
  **whiptail** TUI with the Security Ops banner walks you through:
  - **Filesystem**: ext4 · Btrfs · XFS · ZFS *(experimental)*.
  - **Full-disk encryption**: optional **LUKS2** (`cryptsetup luksFormat`), your
    passphrase, never stored.
  - **Desktop**: **Sway** (Wayland, default) · **i3** (X11) · **KDE Plasma**.
  - **Locale, timezone, keyboard, hostname**, and **user + root accounts**
    (passwords are hashed with `openssl passwd -6`; plaintext never touches disk).
  - It then **generates a self-contained declarative `/etc/config.scm`** for your
    exact choices, **partitions** the disk (GPT: 512 MiB ESP + root), makes the
    filesystem, and runs **`guix system init`**. The installed system stays
    100 % declarative — keep the file and `sudo guix system reconfigure` forever.
  - Safety first: it touches **no disk** until you **type the target device path**
    to confirm; it refuses the disk you booted from and warns on mounted targets;
    a `cow-store` overlay routes the install to the target disk (not RAM).
- **Esquema — rootless, Guile-native container runtime** is now in the system
  profile (`(securityos packages esquema)`). C sandbox primitives (user / mount /
  PID / UTS / IPC / net / cgroup namespaces, `pivot_root`, full capability drop,
  seccomp-BPF allowlist, `NO_NEW_PRIVS`) exposed to a Guile FFI + Scheme runtime.
  Upstream: `git.securityops.co/cristiancmoises/esquema`.

### Changed
- **Custom kernel → Linux 7.1.2** (`linux-securityos`, vanilla kernel.org + the
  same KSPP hardening + performance overlay; `uname -r` = `7.1.2-SecurityOps`).
- The live config now carries a dormant **`cow-store`** service (auto-start off),
  activated by the installer so `guix system init` writes to the target disk.

### Notes
- ZFS root is **experimental** (out-of-tree module); the installer flags it and
  it may need manual steps after first boot. ext4 / Btrfs / XFS are fully wired.
- Generated configs were validated by lowering (`guix system build`) for every
  desktop × filesystem × LUKS combination.

## [1.9.0] — 2026-06-30  ("Security Ops" r7 · sway-only · blazing-fast)

Sway-only, and the real fix for the "stuck 2-3 minutes after login" stall.

### Fixed
- **The 2-3 minute post-login freeze: fontconfig cache rebuild on first GUI
  launch.**  On a live image the first app to draw text (foot/waybar) made
  fontconfig scan every font through the compressed live overlay and build its
  cache — a multi-minute hang that *looked* like the desktop was stuck.  Now a
  **boot-time shepherd one-shot runs `fc-cache -f`** (system-wide
  `/var/cache/fontconfig`, which fontconfig reads first) in parallel with the
  greeter, so by the time you log in the cache is warm and the first render is
  instant.  Verified: fontconfig's default config lists `/var/cache/fontconfig`
  as its first `<cachedir>`, so the root-built cache is used by the user session.

### Changed
- **Sway-only.**  The entire X11 stack was removed: XLibre (xlibre-server built
  from source), the precompiled xmonad binary, xinit, and the whole
  `xorg`/ModulePath machinery.  No more "GLX no stencil"/wallpaper-only failure
  class, a much smaller image, and a faster build.  greetd/tuigreet now launches
  the single **sway** session directly (`tuigreet --cmd`) — no F3 chooser.
- **Desktop apps moved to the SYSTEM profile** (sway, foot, waybar, mako, wofi,
  rofi, swaybg, nm-applet, wl-clipboard, grim/slurp, fonts): they are on PATH the
  instant greetd hands off, so the session no longer **blocks waiting for
  Guix-Home activation** (the old ≤8-15 s wait is gone — the prelude just sources
  the home profile if present).
- Trimmed the home profile of X11 packages (xmonad/xmobar/picom/st/xterm/xrandr/…)
  and their dotfiles → smaller, faster home activation.

## [1.8.0] — 2026-06-25  ("Security Ops" r6)

Rename, slim/fast first-launch, real input config, and curated tool additions.

### Changed
- **Renamed the OS to "Security Ops"** in all user-visible text (GRUB menu, login
  greeting, MOTD, README, ISO volume label `SECURITY_OPS_LIVE`).  Internal
  identifiers (`securityos` modules/paths, `securityops` user, channel) unchanged.
- **Faster first launch:**
  - Dropped ~90 home fonts (system `%font-packages` already covers the dotfiles;
    the extra fonts only slowed the first-app fontconfig scan) and removed the
    dev toolchains (gcc/ghc/go/rust/node/openjdk/ruby), heavy GUI apps
    (libreoffice/gimp/krita/obs/qemu/virt-manager/telegram/steam), the Qt stack
    (pulled in as deps), and SYSTEM-profile duplicates from the home profile —
    much smaller closure, much quicker Guix-Home activation.
  - Kernel cmdline: restored `quiet loglevel=3`, added
    `random.trust_cpu=on random.trust_bootloader=on` (no more boot-blocking
    "gathering entropy" wait) and `GC_MARKERS=1 GC_NPROCS=1` (dodge the initrd
    guile/libgc segfault).
  - xmonad no longer autostarts a 2nd Tor or the heavy Mullvad GUI; the
    home-activation wait was tightened.
- **Real input handling** in both desktops: sway gains proper
  `type:touchpad`/`type:pointer`/`type:keyboard` blocks (tap, natural-scroll,
  two-finger, DWT, accel) and full keybind parity (workspaces 1-9, layouts,
  media/brightness keys via `pactl`/`brightnessctl`); X11/xmonad gains matching
  libinput `InputClass` sections (adopted from the maintainer's working config).

### Added
- `turborec` (screen+audio recorder), `evelin` (post-quantum transport — prebuilt
  static binaries) to the image.  `keepassxc` + `torando` were already present.
- `brightnessctl` to the system profile (for the sway brightness keys).

### Deferred (by choice, to keep r6 fast)
- `librewolf` (no substitute, hours-long OOM-prone source build — keybinds fall
  back to chromium; `guix install librewolf` post-boot), and `btp` + `mirim`
  (need host Rust builds; planned for a follow-up).

## [1.7.2] — 2026-06-25

THE root cause (found by a multi-agent god-tier review): three rounds of fixes
changed nothing because the real defect was never a dotfile.

### Fixed
- **XLibre could not load GLX / glamor / the modesetting driver — the true cause
  of "glx no stencil", the "many errors" spew, and the wallpaper-only desktop.**
  XLibre 25 ships `libglx.so`, `libglamoregl.so` and `modesetting_drv.so` under
  `<xlibre-server>/lib/xorg/modules/xlibre-25/{,extensions,drivers}`, but Guix's
  stock `xorg-wrapper` generates a `ModulePath` that points only at the BARE
  `lib/xorg/modules` (which contains nothing but the `xlibre-25/` subdir) plus
  the separate `xlibre-video-*` packages.  Xorg does not recurse, so those core
  modules were off-path and never loaded; X limped up on vesa/fbdev.  No
  picom/rofi/sway/dotfile edit could ever touch this — which is why the symptoms
  were invariant across rounds 1–3.
  - Fix: the xmonad session now passes an explicit, COMPLETE `-modulepath` to the
    server (the `xlibre-25` tree first, then every video/input driver package),
    plus `-keeptty` so the rootless server keeps DRM master under logind.  See
    `securityos/sessions.scm` (`%extra-module-dirs`, `%xmonad-launch`).
- **picom** switched to the `xrender` backend (no GLX consumer left in the X
  session) + `picom -b --backend xrender` belt-and-suspenders.

### Added
- **Unmissable build-version stamp** (`%build-version`): in the GRUB menu labels
  (visible before login, survives any GPU failure), the tuigreet greeting,
  `/etc/securityos/build-id`, and the MOTD — so it is trivial to confirm WHICH
  image is booted (`cat /etc/securityos/build-id`).
- **Boot diagnostics**: `/tmp/xorg.log` (X server, `-verbose 6`),
  `/tmp/xmonad-session.log`, `/tmp/sway.log`.
- `build.sh` now writes an **epoch-second-named** ISO + a `.sha256` sidecar so a
  same-day rebuild can never be mistaken for a previous one.

## [1.7.1] — 2026-06-25

Problems persisted on the real Intel IdeaPad after 1.7.0.  Two decisive changes
+ diagnostics, since the desktop's only GLX consumer was the compositor.

### Fixed
- **Made the X session GLX-proof.**  In the xmonad session the *only* component
  that touched GLX was picom; everything else (xmonad/xmobar/rofi/terminals) is
  2D.  Switched `dotfiles/picom/picom.conf` to the **`xrender`** backend (no
  OpenGL at all) and disabled blur, so the "glx … stencil" failure cannot occur
  on any GPU — the desktop now comes up wherever modesetting can put a
  framebuffer.

### Added
- **Boot diagnostics.**  The xmonad session now writes the X server log to
  `/tmp/xorg.log` (`-logfile … -verbose 6`) and the full session stdout/stderr
  (incl. startupHook spawn errors) to `/tmp/xmonad-session.log`; sway already
  logs to `/tmp/sway.log`.  If anything still misbehaves on real hardware, those
  three files pin the cause instead of guessing.
- Build now emits a distinctly-named `securityos-live-YYYYMMDD-r2.iso` and
  **deletes every other ISO** in `out/`, so there is no chance of burning a
  stale image.

## [1.7.0] — 2026-06-25

Second real-hardware pass (Intel IdeaPad): fix the XLibre GLX error, rofi not
loading, and make sway resilient.

### Fixed
- **XLibre: "GLX … no stencil" + broken/blank compositing.**  Two causes:
  1. **picom config was invalid.**  `dotfiles/picom/picom.conf` set
     `active-opacity`/`inactive-opacity` to **1.5** (opacity must be 0.0–1.0) and
     used the **long-removed** `glx-use-copysubbuffermesa` option, so modern picom
     rejected the file and aborted with GLX errors.  Rewritten to a clean, valid
     config (opacities ≤ 1.0, deprecated/duplicate options removed).
  2. **The Intel SNA DDX was being used.**  `xlibre-video-intel` (SNA) is broken
     on modern Intel iGPUs (gen9+) and fails to advertise a usable GLX/glamor
     visual.  It is now **dropped** from the X driver set, so XLibre auto-selects
     its built-in **`modesetting` + glamor** driver (the correct modern path); an
     `OutputClass` pins `modesetting`/`glamor`/`DRI 3` whenever the i915 KMS
     driver is bound.  `vesa`/`fbdev` stay for the `nomodeset` safe-graphics
     entries.
- **rofi did not load.**  `dotfiles/rofi/config.rasi` ended with
  `@theme "/home/berkeley/.local/share/rofi/themes/squared-nord.rasi"` — a
  build-host path that does not exist on the live system (wrong user, file not
  shipped), so rofi aborted on startup.  Now uses a theme that **ships with
  rofi** (`gruvbox-dark`), and `rofi` is added to the **system** profile so it is
  on PATH even before Guix-Home finishes activating.
- **sway "did not work".**  The launcher now ensures `XDG_RUNTIME_DIR` exists and
  **retries with the pixman software renderer** if the hardware GLES2 renderer
  fails to initialise (robust on odd GPUs / no-KMS), still logging to
  `/tmp/sway.log`.

- **"Many errors" at login = dead commands in the dotfiles.**  A parallel
  adversarial audit of every command xmonad/sway spawn confirmed 8 references to
  binaries/scripts that do not exist on the sanitized image.  Each is now fixed
  while keeping the maintainer's keys + intent:
  - `xmonad.hs` startup `spawnOn "2" "libre"` → `librewolf 2>/dev/null || chromium`
    (`libre` was never a real binary).
  - `M-e` and sway `$mod+e` launched **librewolf** (intentionally not installed)
    → now `librewolf 2>/dev/null || chromium`, so they work out of the box and
    automatically prefer librewolf if you `guix install` it post-boot.
  - `fcitx5 -d -r` at startup needed the **fcitx5 daemon**, but only `fcitx5-qt`
    was installed → added the `fcitx5` package to the home profile.
  - `M-o` (`/scripts/batata.sh`), `M-k` (`~/scripts/tmp.sh`) and `M-m`'s
    `covers.sh` referenced personal scripts stripped during sanitization → now
    guarded (`[ -x … ] && …`), so they no-op silently instead of erroring, and
    still work if you drop the scripts back in.
  - `M-p` (`openshot-qt`, not packaged) → guarded with `command -v`.
  - `M-ç` ran `~/.local/bin/noisetorch`; the binary is in the profile → now bare
    `noisetorch` (resolves on PATH).
- **Per-login `modprobe -r dccp sctp rds tipc` always failed (EPERM).**  Moved
  this protocol-hardening to the **kernel command line**
  (`module_blacklist=dccp,sctp,rds,tipc`), where it actually takes effect and
  produces no error.

### Changed
- `rofi` and `wezterm` added to the **system** package set (so the `M-d` launcher
  and the default terminal work regardless of Guix-Home timing).
- Dropped the spurious `Option "DRI" "3"` (not a modesetting option) and the
  deprecated picom `glx-no-stencil` — both only produced startup warnings.

## [1.6.0] — 2026-06-24

Fix both desktops failing to start on real hardware + cut login lag.

### Fixed
- **xmonad showed only the wallpaper, WIN keybinds dead.**  Root cause: the
  session ran `xmonad --recompile` at every login, but the live profile has no C
  toolchain on PATH, so GHC aborted with **"could not execute: gcc"**.  xmonad
  then silently fell back to its **default** config (Alt mod, no autostart) →
  blank desktop.  The recompile was also the bulk of the **login lag**.
  - Fix: the maintainer's `xmonad.hs` is now **compiled once at image-build time**
    into a standalone `xmonad-x86_64-linux` binary (new package
    `(securityos packages xmonad-config)`, built against ghc + xmonad-contrib +
    xmobar + **gcc-toolchain**).  The X session execs it directly — **no runtime
    GHC, no recompile, no gcc dependency, no lag**; WIN (Mod4) keybinds and the
    startupHook are live the instant X comes up.  Verified under Xvfb: it owns
    the root window and performs **no** recompile even with `xmonad.hs` present.
- **sway did not launch / came up blank.**  Same first-login race: the desktop
  autostarted `foot`/`waybar`/`swaybg` before Guix-Home finished activating, so
  none of them were on PATH yet.  (The elogind seat + `XDG_RUNTIME_DIR` were
  confirmed fine.)  sway now also logs to `/tmp/sway.log` (run with `-d`) so any
  residual failure is diagnosable.

### Changed
- **Both session launchers now wait (≤15 s) for Guix-Home activation** before
  starting the desktop, and guarantee `XDG_RUNTIME_DIR` — eliminating the
  first-login "nothing spawns" race for xmonad *and* sway.
- Added `xrdb` to the X stack (referenced by the startupHook).

## [1.5.0] — 2026-06-24

Rebrand to **SecurityOps OS** + a performance pass.

### Changed
- **Rebrand:** the project/OS is now **SecurityOps OS**; GRUB titles, the greeter,
  `/etc/motd`, and docs renamed. All **"fsociety"/"anonymous"** wording removed
  (the `font-anonymous-pro` *font* is unaffected); the `anon.png` placeholder is
  gone. Logo/wallpaper = **`assets/sec.png`** (the top-hat logo) on GRUB + both
  desktops. Slogan **"In Code We Trust."** in the greeter, `/etc/motd`, and the
  config header.

### Performance (deep audit + fixes)
- Kernel `.config` audited: `CC_OPTIMIZE_FOR_PERFORMANCE`, `PREEMPT_DYNAMIC`
  (`preempt=full` on the cmdline), `HIGH_RES_TIMERS`, `NO_HZ_IDLE`,
  `SCHED_AUTOGROUP`, `LRU_GEN` (MGLRU), THP, `ZRAM/ZSWAP`, BBR/fq — all present.
- **Enable Multi-Gen LRU at boot** (`CONFIG_LRU_GEN=y` but not default-on): a
  one-shot service writes `/sys/kernel/mm/lru_gen/enabled` + a 1 s min-TTL —
  better reclaim under pressure (the live root is a RAM overlay).
- **Expanded sysctl perf profile:** `vfs_cache_pressure=50`,
  `dirty_writeback_centisecs`, `sched_autogroup_enabled`, BBR + `fq` +
  `netdev_max_backlog=16384`, `rmem/wmem_max=16M`, `tcp_fastopen=3`,
  `tcp_mtu_probing` (atop the existing zram-tuned swappiness/page-cluster).
- Note: `HZ=250` (broad-config default; `HZ_1000` would need a ~45-min kernel
  rebuild for a marginal gain given HIGH_RES_TIMERS + full preempt — left as an
  optional toggle).

## [1.3.0] — 2026-06-23

Make the desktops actually *usable* on real hardware, and add a proper GNU Guix
Home. Driven by feedback that on a Lenovo IdeaPad (Intel) xmonad came up showing
only the wallpaper and sway was a black screen.

### Added
- **`securityos/home.scm` — a real GNU Guix Home** (`%home-environment`):
  user-facing packages plus dotfiles & keybinds for both desktops — `xmonad.hs`,
  `xmobar`, `sway`, `waybar`, `foot`, `alacritty`, and `fish` (via
  `home-fish-service-type`). Wired into the live system with
  `guix-home-service-type`, and usable standalone (`guix home reconfigure
  securityos/home.scm`).

### Fixed
- **Desktops came up empty** (xmonad = bare wallpaper, sway = black screen):
  nothing was being autostarted. Both session launchers now **autostart a
  terminal + wallpaper** on login and put **both the Guix-Home and system
  profiles on `PATH`** so spawned apps are always found.
  - **xmonad** (verified booting to a usable desktop in QEMU): a terminal
    (`alacritty`) opens on login; **default Alt keybinds** are active
    (`Alt`+`Shift`+`Enter` terminal, `Alt`+`p` dmenu, `Alt`+`1..9` workspaces).
  - **sway**: reads the full `~/.config/sway/config` from Guix Home directly (no
    compilation) — explicit `swaybg` wallpaper, **waybar**, **mako**, an
    autostarted `foot`, and Super keybinds; auto-selects the **pixman** software
    renderer when there is no GPU render node.

### Changed
- Replaced the hand-rolled `/etc/skel`-style activation service with Guix Home.

### Known limitations
- **xmonad's *custom* config (`~/.config/xmonad/xmonad.hs`, Super keybinds +
  xmobar) is provided in `home.scm` as a starting point but is NOT active on the
  live image**: xmonad 0.18 must compile it with GHC, which isn't shipped (it
  would add ~1.5 GB and `GHC_PACKAGE_PATH` isn't auto-set). The live xmonad runs
  the reliable built-in config (no compile, instant). To enable the custom one:
  `guix install ghc ghc-xmonad ghc-xmonad-contrib` then `xmonad --recompile`.
- **sway requires a real GPU** (KMS/DRM); it could not be confirmed rendering
  under QEMU's emulated GPU. It should work on the Intel/AMD **GPU** boot
  entries; on the no-GPU entries use **xmonad**.

[1.3.0]: #130--2026-06-23

## [1.2.0] — 2026-06-23

Boot reliably from a USB stick, ship a custom kernel, and let the operator pick
between **two** desktops at login. Driven by a real-world kernel panic when
booting a raw-`dd`'d USB and a request for the latest kernel + hardening + a
Wayland option.

### Added
- **Custom Linux 7.1** (`securityos/kernel.scm` → `linux-securityos`): the
  vanilla kernel.org `linux-7.1.tar.xz`, built with `customize-linux` so its
  config is *derived from* the proven nonguix blob kernel (broad driver / Wi-Fi
  / storage coverage preserved) and adapted to 7.1 via `make olddefconfig`. A
  small, dependency-light set of mainline hardening options is compiled in
  (`SLAB_FREELIST_HARDENED`, `SLAB_FREELIST_RANDOM`, `SHUFFLE_PAGE_ALLOCATOR`,
  `HARDENED_USERCOPY`, `STACKPROTECTOR_STRONG`, `INIT_ON_ALLOC_DEFAULT_ON`,
  `SECURITY_YAMA`, `DMESG_RESTRICT`). No lockdown / module-signature
  enforcement — that would cripple the pentest/forensics toolset.
- **Two selectable desktops via greetd + tuigreet** (`securityos/sessions.scm`):
  a GL-free TUI greeter (rock-solid on any framebuffer, ideal for the no-GPU
  path) with a session chooser and **no default — the operator picks each boot
  (F3)**:
  - **xmonad (X11)** — launched with `xinit` against Guix's composed
    `xorg-wrapper`, so the vesa/fbdev fallback drivers are on the X module path
    and the no-GPU "safe graphics" entries get a working X.
  - **sway (Wayland)** — launched under `dbus-run-session` with
    `WLR_RENDERER_ALLOW_SOFTWARE=1`, so it still comes up via wlroots/llvmpipe
    on machines with no usable GPU. Full sway stack added: swaybg, swayidle,
    swaylock, foot, wofi, waybar, mako, grim/slurp, wl-clipboard, wlr-randr,
    xwayland.
- **Runtime hardening & performance profile**: memory-hardening kernel cmdline
  (`init_on_alloc=1 slab_nomerge page_alloc.shuffle=1 randomize_kstack_offset=on
  vsyscall=none`), a sysctl profile (kptr/dmesg/ptrace/bpf restrictions, full
  ASLR, fs protections, sane network defaults with *loose* RPF so MITM/forward
  workflows still work; BBR + fq + zram-tuned VM), **zram** zstd swap, and
  **earlyoom** (never sacrifices the compositor/greeter).
- **Embedded source tree** at `/etc/securityos/src` on the running system (the
  whole sanitised repo minus `out/` and `*.iso`), so anyone who boots the image
  can read, tweak and rebuild this exact Guix configuration.
- **Modular, Testament-style layout**: the kernel and the login/session
  machinery now live in their own `(securityos …)` modules, tied together by
  `config.scm`.

### Fixed
- **Kernel panic on boot: `VFS: Unable to mount root fs on unknown-block(0,0)`.**
  Root-caused by reproducing the exact panic in QEMU (booting the ISO as a USB
  device) and bisecting: the nonguix **`microcode-initrd`** prepends a ~15 MB
  *uncompressed* early-cpio to the initramfs, and under GRUB's iso9660/i386
  loader the kernel then receives **no main initramfs** — so it falls back to
  mounting `root=` directly (impossible, iso9660 is a module) and panics. The
  same kernel+initrd booted fine when loaded directly (QEMU `-kernel`/`-initrd`),
  isolating it to the GRUB→kernel initrd hand-off. **Fix: use `base-initrd`
  instead of `microcode-initrd`.** Verified end-to-end in QEMU: GRUB → kernel →
  initrd → greetd → **xmonad desktop with wallpaper**.
- The initrd also carries the USB / iso9660 / CD storage modules needed to mount
  the live root off a raw-`dd`'d stick (`usb-storage`, `uas`, `xhci/ehci/ohci`,
  `usbhid`, `sd-mod`, `sr-mod`, `isofs`, … appended to `%base-initrd-modules`).

### Changed
- **Login manager: SLiM → greetd/tuigreet.** SLiM cannot launch a Wayland
  session, so it was replaced to support sway. The SecurityOps logo still
  themes GRUB and both desktops; the graphical SLiM theme is retired (the
  `theme/slim` assets remain in the tree but are no longer wired in).
- The custom kernel is **not substitutable** (built from source), so the first
  build compiles it; subsequent builds reuse it from the store.
- **Dropped early-microcode loading** (`microcode-initrd` → `base-initrd`) — see
  *Fixed*. The CPU runs on its firmware-resident microcode; for a live image
  this is an acceptable trade for actually booting.

### Known limitations
- **sway needs a real GPU.** Wayland/wlroots requires KMS/DRM, which the
  `nomodeset` "no GPU / safe graphics" entries deliberately disable (so X can use
  vesa/fbdev) — so **use xmonad on the no-GPU entries**. sway was verified to
  *launch* but could not be confirmed *rendering* under QEMU's emulated GPU; it
  should work on the real Intel/AMD **GPU** boot entries. If sway misbehaves on
  your hardware, use xmonad and capture `~/.local/share/sway/…`/journal for
  follow-up. **xmonad is verified working on every path tested.**

[1.2.0]: #120--2026-06-23

## [1.1.0] — 2026-06-23

Make the single ISO **boot and run on machines without a usable GPU**, and cover
the four hardware targets explicitly: GPU Intel, GPU AMD, CPU/no-GPU Intel, and
CPU/no-GPU AMD.

### Added
- **Two new GRUB boot entries**, bringing the menu to **five**:
  - `SecurityOps OS — Intel CPU (no GPU / safe graphics)` — `nomodeset` +
    `intel_iommu=on iommu=pt`, blacklists `amdgpu`/`radeon`/`nouveau`.
  - `SecurityOps OS — AMD CPU (no GPU / safe graphics)` — `nomodeset` +
    `amd_iommu=on iommu=pt`, blacklists `i915`/`xe`/`nouveau`.
  With `nomodeset` the kernel stays on the plain EFI/VESA framebuffer, so
  laptops/desktops/VMs with no dedicated GPU, an unsupported GPU, or a GPU whose
  KMS driver hangs still boot to the xmonad desktop. Like the existing GPU
  entries, both reuse the **exact same on-CD kernel + initrd**. (IOMMU flags are
  vendor-ignored, so choosing the wrong Intel/AMD generic entry is harmless.)
- **`mesa` + `mesa-utils`** in the package set. Mesa automatically selects the
  `llvmpipe` software renderer when no hardware GL driver is present, so OpenGL
  apps still work on the no-GPU entries; `glxinfo`/`glxgears` confirm which
  renderer is active. (Guix's `%default-xorg-modules` already ships the
  `xf86-video-fbdev`/`xf86-video-vesa` drivers the framebuffer path needs, so no
  extra Xorg driver packages were required.)

### Changed
- Renamed `%gpu-menu-entries` → `%boot-menu-entries` and the `gpu-entry` helper →
  `live-entry` (the boot menu now holds non-GPU entries too).
- Dropped the explicit `nss-certs` from the package list — it is already part of
  `%base-packages` on the pinned guix, which silences a duplicate-package warning.
- README and the config header now document all five boot entries and the
  software-rendering fallback.

### Fixed
- **The hand-written GRUB entries now actually boot.** Every non-default entry
  (the original Intel/AMD GPU entries *and* the new no-GPU ones) is now built
  from the image OS's own boot parameters via `operating-system-kernel-arguments`,
  so each one carries the self-referential `root=` / `gnu.system=` / `gnu.load=`
  tokens and locates the disc by its deterministic **fs-UUID** (`search
  --fs-uuid`). Previously these entries (a) omitted `gnu.load=`, so the initrd
  found no boot file and dropped to a rescue Guile REPL instead of switching
  root, and (b) ran `search --label GUIX_IMAGE` while `build.sh` relabels the
  volume to `SECURITYOS_LIVE`, so even finding the disc failed. Net effect: in
  1.0.0 only the auto-detect entry was bootable; now all five boot.

[1.1.0]: #110--2026-06-23

## [1.0.0] — 2026-06-22

First public release: a self-contained, portable live image of the securityops
workstation.

### Added
- **`config.scm`** — a hardware-agnostic GNU Guix `operating-system` for an
  `iso9660` live image (read-only ISO + RAM overlay via `volatile-root`).
- **Three GRUB boot entries** so the operator picks the GPU stack at boot:
  - `SecurityOps OS (auto-detect GPU)` — default; both `i915` and `amdgpu` load
    by PCI ID, so it works on virtually anything.
  - `SecurityOps OS — Intel GPU (i915)` — blacklists `amdgpu`/`radeon`, sets
    `intel_iommu=on iommu=pt`.
  - `SecurityOps OS — AMD GPU (amdgpu)` — blacklists `i915`/`xe`/`nouveau`, sets
    `amd_iommu=on iommu=pt`.
  The Intel/AMD entries are real GRUB `menu-entry` records that reuse the **exact
  same on-CD kernel + initrd** as the default entry (derived through
  `operating-system-for-image`), so they are guaranteed to boot.
- **SecurityOps logo (`sec.png`) in three places**: the GRUB background
  (`grub-theme`, 1920×1080, green-on-black menu colors), the **SLiM** login
  screen (custom `securityops` theme), and the **xmonad** desktop (via `feh` in
  the live user's `~/.xsession`).
- **Hybrid BIOS + UEFI boot** (Guix builds iso9660 with `grub-mkrescue`), so the
  single `.iso` boots on legacy and modern firmware and **drops straight into a
  Ventoy USB folder**.
- **nonguix stock `linux` + `linux-firmware` + dual-microcode `microcode-initrd`**
  for broad hardware / Wi-Fi support (AMD + Intel microcode loaded early).
- **Live user `securityops`** (password `securityops`, passwordless `sudo` via
  `wheel`), auto-populated home skeleton written on each boot by an activation
  service.
- **Curated toolset** drawn from the workstation: recon/scanning (nmap, masscan,
  arp-scan, netdiscover, fping, mtr), capture/MITM (tcpdump, wireshark,
  macchanger, proxychains-ng, socat), wireless (aircrack-ng, reaver, kismet),
  cracking/RE/forensics (hydra, hashcat, john-the-ripper-jumbo, radare2, rizin,
  binwalk, exiftool), crypto/keys (gnupg, age, keepassxc, libfido2, firejail,
  lynis, clamav), anonymity/VPN (tor, torsocks, nyx, i2pd, wireguard-tools,
  openvpn), plus terminals (alacritty, kitty, fish+starship), editors (emacs,
  neovim), browsers (icecat, w3m, lynx), full filesystem tooling, and the Iosevka
  font family.
- **`build.sh`** — wrapper around `guix system image -t iso9660` with a
  `--pinned` (time-machine) mode for reproducible builds; sends scratch to
  `/var/tmp` to avoid the small tmpfs `/tmp`.
- **`channels.scm`** — `guix` + `nonguix` pinned to the workstation's June 2026
  commits, public URLs only.
- **`README.md`**, **`docs/SANITIZATION.md`** (what private data was stripped),
  **`LICENSE`** (GPL-3.0-or-later).

### Security / privacy
- Stripped all host secrets and identifiers: LUKS/FS/swap UUIDs, mapped-devices,
  the personal NextDNS resolvers, private `git.securityops.co` channel URLs, SSH
  keys, and personal shell aliases. See `docs/SANITIZATION.md`.
- Stateful firewall with **no addresses baked in**; plain Tor SOCKS on
  `127.0.0.1:9050`.

### Known limitations
- Heavy source-built browsers (Tor Browser, LibreWolf, ungoogled-chromium) and
  Mullvad are **not** in the default image to keep the build tractable; the README
  shows how to add them from the `securityops` channel after boot.
- Tools not yet packaged for Guix (sqlmap, nikto, bettercap, gobuster, ffuf,
  sleuthkit, volatility3, …) are omitted; install per-engagement.

[1.0.0]: #100--2026-06-22
