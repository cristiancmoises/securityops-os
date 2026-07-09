;; -*- mode: scheme; -*-
;;; ===========================================================================
;;; SecurityOps OS — Live ISO  (GNU Guix System)
;;; Slogan: "In Code We Trust."   Logo: assets/sec.png
;;; ===========================================================================
;;;
;;; A portable, "boot-it-anywhere" live image of the securityops workstation:
;;; a hardened, privacy-focused GNU/Linux loaded with security tooling, a
;;; sway (Wayland) tiling desktop, a guided disk installer, and the
;;; SecurityOps logo on the GRUB menu and the desktop.
;;;
;;; Modular (Testament-style) layout — the moving parts live in their own
;;; modules under ./securityos, tied together here:
;;;     (securityos kernel)    -> linux-securityos  (custom Linux 7.1.3)
;;;     (securityos sessions)  -> greeter + sway session
;;;
;;; Build:   ./build.sh                 (wraps `guix system image -t iso9660`)
;;; Output:  an .iso you write to a USB stick (raw `dd`) or drop into Ventoy.
;;;
;;; GRUB shows five entries so the operator can pick the right hardware stack:
;;;     0.  SecurityOps OS (auto-detect GPU)     <- default, works everywhere
;;;     1.  SecurityOps OS — Intel GPU (i915)              (hardware accel)
;;;     2.  SecurityOps OS — AMD GPU (amdgpu)              (hardware accel)
;;;     3.  SecurityOps OS — Intel CPU (no GPU / safe graphics)
;;;     4.  SecurityOps OS — AMD CPU (no GPU / safe graphics)
;;; All five boot the SAME on-CD kernel + initrd; they differ ONLY in their
;;; kernel command line.  The two "no GPU / safe graphics" entries add
;;; `nomodeset', so machines with NO usable GPU still boot: X falls back to the
;;; vesa/fbdev driver + Mesa llvmpipe, and sway to wlroots software rendering.
;;;
;;; BOOTS FROM USB: the initrd carries the USB / iso9660 / CD storage modules
;;; (see %initrd-extra-modules), so a raw-`dd'd USB stick mounts its own root
;;; instead of panicking with "unable to mount root fs".
;;;
;;; HARDENING / PERFORMANCE: a custom Linux 7.1 (vanilla kernel.org, config
;;; derived from the proven nonguix kernel) + memory-hardening kernel cmdline
;;; flags + a sysctl profile + zram swap + earlyoom.  None of it cripples the
;;; pentest/forensics toolset (no lockdown, no module-signature enforcement).
;;;
;;; "USE MY GUIX": the whole (sanitised) source tree of this image is embedded
;;; at /etc/securityos/src on the running system, so anyone who boots it can
;;; read, tweak and rebuild the exact configuration.
;;;
;;; Maintainer: Cristian Cezar Moisés <sac@securityops.co>
;;; License: AGPL-3.0-or-later (see LICENSE).  © Cristian Cezar Moisés.
;;; ===========================================================================

(use-modules
 (gnu)
 (gnu system)
 (gnu system locale)              ; locale-definition
 (gnu system image)               ; operating-system-for-image, iso9660-image
 (gnu system file-systems)        ; file-system-label
 (gnu system linux-initrd)        ; %base-initrd-modules
 (gnu bootloader)                 ; menu-entry
 (gnu bootloader grub)            ; grub-theme, grub-efi-bootloader
 (gnu services)                   ; extra-special-file, simple-service
 (gnu services guix)              ; guix-home-service-type
 (guix gexp)
 (srfi srfi-1)
 (srfi srfi-13)                   ; string-suffix?
 ;; --- our own modules (resolved via `guix … -L .') ---------------------
 (securityos kernel)              ; linux-securityos
 (securityos sessions)            ; %greeter-command
 (securityos home)                ; %home-environment (Guix Home)
 (securityos packages evelin)     ; evelin — PQ transport (prebuilt static binaries)
 (securityos packages esquema)    ; esquema — rootless, Guile-native container runtime
 (securityos packages installer)  ; security-ops-install — guided disk installer
 (securityos packages vaptvupt))  ; vaptvupt — same vendored build home.scm uses

(use-service-modules base desktop linux networking shepherd sysctl xorg)

(use-package-modules
 admin antivirus base cmake commencement compression compton cryptsetup curl disk
 dns emacs engineering file file-systems firmware fonts fontutils freedesktop gl
 glib gnome gnupg gnuzilla golang-crypto hardware i2p image image-viewers imagemagick
 linux lsof lxde monitoring mtools music ncdu networking nss password-utils pciutils
 pdf photo pulseaudio python rsync rust-apps security-token shells shellutils slang
 ssh suckless terminals text-editors tls tmux tor version-control video vim vpn w3m
 web-browsers wget wm xdisorg xorg
 bittorrent librewolf                       ; qbittorrent, librewolf
 chromium tor-browsers)                     ; ungoogled-chromium, torbrowser

;; nonguix LAST so its blob-enabled `linux-firmware' shadows any gnu bindings.
(use-modules (nongnu packages linux)        ; linux-firmware
             (nongnu system linux-initrd)   ; microcode-initrd
             (nongnu packages chrome)       ; google-chrome-stable
             (small-guix packages mullvad)  ; mullvad-vpn-desktop
             (securityops packages apps)    ; torando-gui
             (securityops services torando)) ; torando-gui-service-type
;; librewolf IS baked in (r9): the ISO build reuses the already-built store item
;; (see %browser-packages), so no from-source compile happens at image time.

;;; ---------------------------------------------------------------------------
;;; Identity & knobs
;;; ---------------------------------------------------------------------------
(define %live-user "securityops")
(define %kbd (keyboard-layout "br" "abnt2"))   ; the maintainer's layout; change freely
(define %wallpaper (local-file "assets/sec.png"))    ; the SecurityOps logo

;; The image's own (sanitised) source tree, embedded so a booted user can
;; inspect and rebuild it.  `out/' (the multi-GB built ISOs) and any *.iso are
;; excluded so the closure stays small.
(define %config-src
  (local-file "." "securityos-src"
              #:recursive? #t
              #:select?
              (lambda (file stat)
                (let ((b (basename file)))
                  (not (or (string=? b "out")
                           (string=? b ".git")
                           (string-suffix? ".iso" file)))))))

;; The live user's dotfiles, keybinds and desktop packages are now declared as a
;; proper GNU Guix Home environment in (securityos home) and applied at boot via
;; `guix-home-service-type' (below).  No hand-rolled /etc/skel activation needed;
;; the configs read the system-wide /etc/securityos/wallpaper.png.

;;; ---------------------------------------------------------------------------
;;; Package set — curated from the workstation, minus hardware/heavy bits.
;;; ---------------------------------------------------------------------------
;; X11 is GONE — Security Ops is sway-only.  The old xmonad/XLibre %desktop-packages
;; (xmonad, ghc-xmonad-contrib, xmobar, dmenu, xterm, feh, picom, arandr, xrandr,
;; setxkbmap, xmodmap, xkill, xinit, …) were removed.  The handful of still-useful
;; GUI utilities now live in %wayland-packages below.

(define %wayland-packages
  ;; The COMPLETE sway desktop, all in the SYSTEM profile so it is on PATH the
  ;; instant greetd hands off — the session never waits on Guix-Home activation.
  (list sway swaybg swayidle swaylock                ; compositor + idle/lock
        foot wofi bemenu rofi wezterm                ; terminals + launchers
        waybar mako                                  ; bar + notifications
        grim slurp wl-clipboard wlr-randr wlsunset   ; screenshots / clipboard / outputs
        network-manager-applet                       ; nm-applet (waybar tray Wi-Fi)
        lxappearance xdg-utils                       ; GTK theming + xdg-open
        xorg-server-xwayland                         ; run X apps under sway
        brightnessctl                                ; sway XF86MonBrightness keys
        tuigreet                                     ; greetd TUI greeter
        dbus))                                       ; dbus-run-session

(define %terminal-packages
  (list alacritty kitty fish starship zoxide bat fzf tmux
        fastfetch pfetch htop btop glances inxi tree))

(define %editor-packages
  (list emacs vim neovim nano))

(define %browser-packages
  ;; Full browser set (securityops / nonguix channels).  librewolf is now baked
  ;; in (r9) — it builds from source for hours, so the ISO build reuses the
  ;; already-built store item; the sway `Super+e' keybind launches it.
  (list icecat w3m lynx
        librewolf                     ; hardened Firefox fork (Super+e)
        ungoogled-chromium            ; the "chromium" the M-we xmonad keybind spawns
        torbrowser                    ; Tor Browser
        google-chrome-stable          ; nonguix
        mullvad-vpn-desktop           ; Mullvad VPN (GUI + CLI)
        torando-gui))                 ; Torando — Tor control GUI (securityops channel)

(define %fs-packages
  (list lf ranger ncdu gparted gnome-disk-utility parted
        ntfs-3g exfatprogs dosfstools e2fsprogs xfsprogs btrfs-progs f2fs-tools
        smartmontools testdisk ddrescue mtools rsync
        7zip zip unzip file lsof))

(define %security-packages
  (list ;; recon / scanning
        nmap masscan arp-scan netdiscover fping mtr whois ndisc6
        ;; sniff / capture / mitm
        tcpdump wireshark macchanger proxychains-ng socat netcat-openbsd
        ;; wireless
        aircrack-ng reaver kismet iw wireless-tools wpa-supplicant
        ;; cracking / RE / forensics
        hydra hashcat john-the-ripper-jumbo radare2 rizin binwalk
        perl-image-exiftool
        ;; crypto / keys / hardening
        gnupg openssl age keepassxc libfido2 firejail lynis clamav
        ;; firewall / vpn / anonymity
        nftables wireguard-tools openvpn tor torsocks nyx i2pd
        ;; dns lookups (drill / kdig)
        ldns knot
        ;; net basics
        curl wget openssh
        ;; Security Ops post-quantum transport (prebuilt static musl binaries)
        evelin
        ;; Security Ops rootless container runtime (C + Guile FFI sandbox)
        esquema
        ;; Security Ops post-quantum backup & compression (CLI + Qt GUI)
        vaptvupt))

(define %installer-packages
  ;; The guided disk installer + the CLI tools it drives.  parted / the mkfs.*
  ;; family / util-linux already come in via %fs-packages; here we add the two
  ;; still-missing pieces: whiptail (newt) for the TUI and cryptsetup for LUKS.
  (list security-ops-installer newt cryptsetup))

(define %sysutil-packages
  (list util-linux pciutils usbutils dmidecode hwinfo hdparm nvme-cli
        lm-sensors ethtool iproute net-tools psmisc procps strace ltrace
        gcc-toolchain git gnu-make cmake python
        ;; firmware blobs for hardware that needs them (Wi-Fi/GPU/etc.).
        ;; microcode-initrd already carries AMD+Intel ucode for early load.
        linux-firmware))

(define %media-packages
  (list mpv zathura zathura-pdf-poppler imagemagick
        pavucontrol playerctl alsa-utils
        qbittorrent                     ; torrent client (Qt GUI)
        ;; terminal image preview for lf: ueberzugpp draws real images in the
        ;; pane over a FIFO; chafa is the tty fallback; feh opens images
        ;; fullscreen; xclip for the lf copy-filename bind.  ffmpeg(+thumbnailer),
        ;; poppler (pdftoppm) and atool give lf its video / PDF / archive previews.
        feh ueberzugpp chafa xclip
        ffmpeg ffmpegthumbnailer poppler atool
        turborec))            ; securityops channel: screen+audio recorder (CLI + Tk GUI)

(define %font-packages
  (list font-dejavu font-liberation font-gnu-freefont
        font-google-noto font-jetbrains-mono font-terminus
        font-awesome font-iosevka-term))

(define %gl-packages
  ;; Mesa = OpenGL.  On the GPU entries it provides the hardware DRI drivers;
  ;; on the nomodeset entries it falls back to the `llvmpipe' software renderer,
  ;; so GL apps (and sway's wlroots) keep working with no usable GPU.
  (list mesa mesa-utils))

(define %live-packages
  (append %wayland-packages %terminal-packages
          %editor-packages %browser-packages %fs-packages %security-packages
          %installer-packages
          %sysutil-packages %media-packages %font-packages %gl-packages
          ;; nss-certs (TLS root CAs) is already in %base-packages on the
          ;; pinned guix, so it is NOT re-listed (avoids a duplicate warning).
          %base-packages))

;;; ---------------------------------------------------------------------------
;;; Hardening / performance knobs (runtime — none of it breaks pentest tools)
;;; ---------------------------------------------------------------------------
(define %securityos-sysctl
  ;; Appended AFTER %default-sysctl-settings, so these win on any conflict.
  '(;; --- kernel / process hardening ---
    ("kernel.kptr_restrict" . "2")          ; hide kernel pointers
    ("kernel.dmesg_restrict" . "1")         ; non-root cannot read dmesg
    ("kernel.yama.ptrace_scope" . "1")      ; ptrace only own children (sudo to relax)
    ("kernel.kexec_load_disabled" . "1")    ; no kexec of an unverified kernel
    ("kernel.perf_event_paranoid" . "3")    ; no unprivileged perf
    ("kernel.unprivileged_bpf_disabled" . "1")
    ("net.core.bpf_jit_harden" . "2")
    ("kernel.randomize_va_space" . "2")     ; full ASLR
    ;; --- filesystem hardening ---
    ("fs.protected_symlinks" . "1")
    ("fs.protected_hardlinks" . "1")
    ("fs.protected_fifos" . "2")
    ("fs.protected_regular" . "2")
    ;; --- network hardening (loose RPF: keeps MITM/forwarding workflows usable) ---
    ("net.ipv4.conf.all.rp_filter" . "2")
    ("net.ipv4.conf.default.rp_filter" . "2")
    ("net.ipv4.tcp_syncookies" . "1")
    ("net.ipv4.conf.all.accept_redirects" . "0")
    ("net.ipv4.conf.all.send_redirects" . "0")
    ("net.ipv4.conf.all.accept_source_route" . "0")
    ("net.ipv6.conf.all.accept_redirects" . "0")
    ("net.ipv6.conf.all.accept_source_route" . "0")
    ;; --- performance: memory / VM (zram-backed swap + responsiveness) ---
    ("vm.swappiness" . "100")               ; swap eagerly into compressed RAM
    ("vm.page-cluster" . "0")               ; zram: fault one page at a time
    ("vm.dirty_ratio" . "10")
    ("vm.dirty_background_ratio" . "5")
    ("vm.vfs_cache_pressure" . "50")        ; keep inode/dentry cache longer (snappier FS)
    ("vm.dirty_writeback_centisecs" . "1500")
    ("kernel.sched_autogroup_enabled" . "1"); per-session fairness = smoother desktop
    ;; --- performance: network (BBR + fq + bigger buffers + fast-open) ---
    ("net.core.default_qdisc" . "fq")
    ("net.ipv4.tcp_congestion_control" . "bbr")
    ("net.core.netdev_max_backlog" . "16384")
    ("net.core.rmem_max" . "16777216")
    ("net.core.wmem_max" . "16777216")
    ("net.ipv4.tcp_fastopen" . "3")
    ("net.ipv4.tcp_mtu_probing" . "1")))

;;; ---------------------------------------------------------------------------
;;; Services
;;; ---------------------------------------------------------------------------
(define %simple-firewall
  ;; Stateful desktop firewall: allow all outbound (so DHCP/DNS/VPN/Tor work
  ;; on any network), accept only replies + loopback + ICMP + DHCP inbound.
  (service nftables-service-type
    (nftables-configuration
     (ruleset
      (plain-file "nftables.conf" "\
flush ruleset
table inet filter {
  chain input {
    type filter hook input priority filter; policy drop;
    ct state invalid drop
    ct state established,related accept
    iif \"lo\" accept
    ip protocol icmp accept
    ip6 nexthdr ipv6-icmp accept
    udp dport { 67, 68, 546 } accept
    counter drop
  }
  chain forward { type filter hook forward priority filter; policy drop; }
  chain output  { type filter hook output  priority filter; policy accept; }
}
")))))

(define %tor-service
  (service tor-service-type
    (tor-configuration
     (config-file
      (plain-file "torrc" "\
Log notice stderr
SOCKSPort 127.0.0.1:9050
SafeLogging 1
")))))

(define %greetd-config
  ;; greetd + tuigreet on vt7: a GL-free TUI login with a session chooser.
  (greetd-configuration
   (greeter-supplementary-groups '("video" "input"))
   (terminals
    (list (greetd-terminal-configuration
           (terminal-vt "7")
           (terminal-switch #t)
           (default-session-command %greeter-command))))))

(define %zram-config
  ;; Compressed RAM swap — invaluable on a live image whose root is a RAM
  ;; overlay; keeps low-RAM machines from OOMing.
  (zram-device-configuration
   (size "6G")
   (compression-algorithm 'zstd)))

(define %earlyoom-config
  ;; Userspace OOM killer: act before the kernel OOM hangs the desktop, but
  ;; never sacrifice the compositor / greeter / Xorg.
  (earlyoom-configuration
   (minimum-available-memory 5)
   (minimum-free-swap 5)
   (avoid-regexp "(^|/)(sway|swaybg|waybar|greetd|tuigreet|shepherd)$")))

(define %live-services
  (cons*
   ;; FHS dynamic-linker shim so foreign glibc ELF binaries can exec.
   (extra-special-file "/lib64/ld-linux-x86-64.so.2"
                       (file-append glibc "/lib/ld-linux-x86-64.so.2"))
   ;; Wallpaper available system-wide (both desktops read this absolute path).
   (extra-special-file "/etc/securityos/wallpaper.png" %wallpaper)
   ;; Build identifier — `cat /etc/securityos/build-id' on the running system to
   ;; confirm WHICH image you booted (ends the "is this the new build?" doubt).
   (extra-special-file "/etc/securityos/build-id"
                       (plain-file "build-id" (string-append %build-version "\n")))
   ;; The image's own source tree, for "boot it and rebuild it".
   (extra-special-file "/etc/securityos/src" %config-src)
   ;; The maintainer's channels (guix + nonguix + guix-xlibre + securityops) as
   ;; the SYSTEM-WIDE `guix pull' default, so `guix pull' on the running system
   ;; picks up the securityops/guix-xlibre channels and their packages.
   (extra-special-file "/etc/guix/channels.scm" (local-file "channels.scm"))
   ;; turborecorder at the exact path the xmonad M-r keybind expects.
   (extra-special-file "/usr/bin/turborecorder"
                       (local-file "securityos/dotfiles/turborecorder"
                                   #:recursive? #t))   ; keep the +x bit
   ;; TTY login banner with the slogan.
   (simple-service 'securityos-motd etc-service-type
     (list (list "motd"
                 (plain-file "motd" (string-append "
   Security Ops  —  In Code We Trust.
   build: " %build-version "

   user: securityops   pass: securityops   (passwordless sudo)

   Install to disk:  security-ops-install     (or press Super+Shift+I)
       guided TUI · ext4/btrfs/xfs · LUKS2 · Sway/i3/KDE · Esquema

")))))

   ;; GNU Guix Home for the live user: desktop packages + dotfiles + keybinds
   ;; (xmonad/xmobar/sway/waybar/foot/fish).  Activated at boot for %live-user.
   (service guix-home-service-type
            (list (list %live-user %home-environment)))

   ;; Torando — loopback Tor-control GUI daemon (securityops channel).
   (service torando-gui-service-type)

   ;; greetd login (replaces SLiM, which cannot launch a Wayland session).
   (service greetd-service-type %greetd-config)

   ;; Copy-on-write store for the guided installer.  Dormant at boot
   ;; (auto-start? #f); `security-ops-install' runs `herd start cow-store /mnt'
   ;; so that `guix system init' writes new store items to the TARGET DISK
   ;; instead of the live RAM overlay (which would otherwise OOM mid-install).
   ;; The type is private to (gnu system install); reach it with @@.  It takes a
   ;; value (ignored by the service proc — the real target is passed at
   ;; `herd start cow-store /mnt' time), so give it #f.
   (service (@@ (gnu system install) cow-store-service-type) #f)

   %simple-firewall
   %tor-service

   ;; Performance / resilience.
   (service zram-device-service-type %zram-config)
   (service earlyoom-service-type %earlyoom-config)
   ;; Multi-Gen LRU is compiled in (CONFIG_LRU_GEN=y) but not default-on; enable
   ;; it + a 1s min-TTL at boot for markedly better page reclaim under memory
   ;; pressure (the live root is a RAM overlay, so this matters).
   (simple-service 'enable-mglru shepherd-root-service-type
     (list (shepherd-service
            (provision '(enable-mglru))
            (requirement '(file-systems))
            (one-shot? #t)
            (start #~(make-forkexec-constructor
                      (list "/bin/sh" "-c"
                            (string-append
                             "echo y > /sys/kernel/mm/lru_gen/enabled 2>/dev/null; "
                             "echo 1000 > /sys/kernel/mm/lru_gen/min_ttl_ms 2>/dev/null; true"))))
            (stop #~(make-kill-destructor)))))

   ;; ───────────────────────────────────────────────────────────────────────
   ;; THE FIRST-LAUNCH STALL FIX.  On a live image the FIRST GUI app (foot /
   ;; waybar) otherwise triggers fontconfig to scan every font through the
   ;; compressed live overlay and build the cache — which made the desktop hang
   ;; for 2-3 MINUTES right after login.  Build the SYSTEM fontconfig cache
   ;; (/var/cache/fontconfig, read by every user) ONCE at boot, in the
   ;; background, in parallel with the greeter — so by the time you finish typing
   ;; your password the cache is warm and the first text render is instant.
   (simple-service 'prewarm-fontconfig shepherd-root-service-type
     (list (shepherd-service
            (provision '(prewarm-fontconfig))
            (requirement '(user-processes))
            (one-shot? #t)
            (start #~(make-forkexec-constructor
                      (list #$(file-append fontconfig "/bin/fc-cache") "-f")))
            (stop #~(make-kill-destructor)))))

   ;; Desktop stack minus GDM (we use greetd).  %desktop-services already brings
   ;; NetworkManager + wpa-supplicant, elogind (seats for sway), polkit, dbus,
   ;; udisks, upower, cups, ntp.  We also fold the hardening sysctl in here.
   (modify-services %desktop-services
     (delete gdm-service-type)
     (sysctl-service-type config =>
       (sysctl-configuration
        (inherit config)
        (settings (append (sysctl-configuration-settings config)
                          %securityos-sysctl)))))))

;;; ---------------------------------------------------------------------------
;;; The live operating-system (parameterised by GRUB menu-entries so we can
;;; reference the image-transformed kernel/initrd without a definition cycle).
;;; ---------------------------------------------------------------------------
(define %base-kernel-arguments
  '("quiet" "loglevel=3"                    ; fast, clean boot
    ;; Trust the CPU/bootloader RNG so the kernel CRNG inits instantly instead of
    ;; blocking boot on "gathering entropy …" (the SSH host-key + early services
    ;; otherwise stall for seconds-to-minutes in a VM / on low-entropy hardware).
    "random.trust_cpu=on" "random.trust_bootloader=on"
    ;; Single-thread Boehm-GC in the guile initrd to dodge the
    ;; "pthread_attr_getstack failed for main thread" → guile segfault seen at
    ;; ~0.6s (passed to userspace as env; harmless on the real system's guile).
    "GC_MARKERS=1" "GC_NPROCS=1"
    "modprobe.blacklist=pcspkr"             ; silence the PC speaker beep
    ;; Disable rarely-used, historically-vulnerable network protocols at the
    ;; kernel level (CIS-style hardening).  This replaces a per-login
    ;; `modprobe -r dccp sctp rds tipc' in the xmonad startupHook that always
    ;; failed with EPERM (a user cannot unload modules) and only spewed errors.
    "module_blacklist=dccp,sctp,rds,tipc"
    ;; --- config-free memory hardening (works with the stock kernel config) ---
    "init_on_alloc=1"                       ; zero pages handed out of the allocator
    "slab_nomerge"                          ; don't merge slab caches (heap hygiene)
    "page_alloc.shuffle=1"                  ; randomise the free-page lists
    "randomize_kstack_offset=on"            ; per-syscall kernel stack offset
    "vsyscall=none"                         ; kill the legacy vsyscall page
    ;; Actually INITIALISE the LSMs we build: the kernel-config CONFIG_LSM order
    ;; doesn't include Landlock, so without this `lsm=' the LANDLOCK=y we added
    ;; (kernel.scm) never activates.  yama (ptrace_scope) + bpf kept; lockdown is
    ;; intentionally OMITTED (the security model deliberately avoids it).
    "lsm=landlock,yama,bpf"
    ;; --- performance (Clear-Linux / XanMod flavour, config-free) ---
    "preempt=full"                          ; low-latency desktop scheduling
    "transparent_hugepage=madvise"          ; THP only where asked (latency)
    "tsc=reliable"                          ; skip TSC re-checks on stable TSCs
    "rcu_nocbs=all"                         ; offload RCU callbacks off the hot CPUs
    "nowatchdog"))                          ; drop the NMI watchdog overhead

;; USB / CD / iso9660 storage modules the initrd needs to mount the live root
;; from a raw-`dd'd USB stick (the fix for the "unable to mount root fs" panic).
;; Duplicates of anything already in %base-initrd-modules are harmless.
(define %initrd-extra-modules
  '("uhci-hcd" "ehci-hcd" "ehci-pci" "ohci-hcd" "ohci-pci"
    "xhci-hcd" "xhci-pci"                   ; USB host controllers
    "usb-storage" "uas"                     ; USB mass storage (BOT + UAS)
    "usbhid" "hid-generic"                  ; USB keyboard at the initrd stage
    "sd-mod" "sr-mod" "cdrom"               ; SCSI disk / CD-ROM
    "isofs"                                 ; the iso9660 filesystem
    "nvme" "ahci"))                         ; for good measure on odd firmware

(define (make-live-os menu-entries)
  (operating-system
    (host-name "securityos-live")
    (label (string-append "Security Ops (auto-detect GPU) · " %build-version))
    (locale "pt_BR.UTF-8")
    (locale-definitions
     (list (locale-definition (name "pt_BR.UTF-8") (source "pt_BR"))
           (locale-definition (name "en_US.UTF-8") (source "en_US"))))
    (timezone "America/Sao_Paulo")
    (keyboard-layout %kbd)

    ;; Custom Linux 7.1 (vanilla kernel.org, nonguix-derived config + hardening).
    (kernel linux-securityos)
    (firmware (list linux-firmware))
    ;; IMPORTANT — use the plain base-initrd, NOT nonguix's microcode-initrd.
    ;; microcode-initrd prepends a ~15 MB *uncompressed* early-cpio (the CPU
    ;; microcode) to the initramfs.  Under GRUB's iso9660 / i386 loader the
    ;; kernel then ends up with NO main initramfs and panics at boot
    ;; ("Kernel panic - not syncing: VFS: Unable to mount root fs on
    ;; unknown-block(0,0)").  Verified by QEMU repro: base-initrd boots to the
    ;; greeter + xmonad desktop; microcode-initrd panics.  Trade-off: no early
    ;; microcode update on this live image (the CPU runs on its built-in
    ;; microcode) — acceptable, and re-addable if booting from a real disk.
    (initrd base-initrd)
    (initrd-modules (append %initrd-extra-modules %base-initrd-modules))
    (kernel-arguments %base-kernel-arguments)

    ;; Live user: passwordless sudo via wheel, in the hardware groups.
    (users (cons* (user-account
                   (name %live-user)
                   (comment "Security Ops")
                   (password "$6$securityoslive$TFWUmT31Bk/GLRel0DP/R2wDakumpcEOGvjnzzfGWqmeWe8SGW8EvCoSIpZH9rPIGMZX49Yeh2KuJ5lF7pbzh1") ; "securityops"
                   (group "users")
                   (supplementary-groups
                    '("wheel" "netdev" "audio" "video" "input"
                      "lp" "tty" "dialout" "kvm")))
                  %base-user-accounts))

    (sudoers-file
     (plain-file "sudoers" "\
Defaults secure_path=\"/run/privileged/bin:/run/setuid-programs:/run/current-system/profile/bin:/run/current-system/profile/sbin\"
root ALL=(ALL) ALL
%wheel ALL=(ALL) NOPASSWD: ALL
"))

    (packages %live-packages)
    (services %live-services)

    ;; Bootloader: GRUB with the SecurityOps logo.  For an iso9660 image
    ;; Guix swaps this to grub-mkrescue (hybrid BIOS+UEFI) but inherits this
    ;; theme, timeout and the menu-entries below.
    (bootloader
     (bootloader-configuration
      (bootloader grub-efi-bootloader)
      (targets (list "/boot/efi"))
      (timeout 15)
      (default-entry 0)                      ; auto-detect entry
      (keyboard-layout %kbd)
      (theme (grub-theme
              (image (local-file "assets/sec.png"))
              (resolution '(1920 . 1080))
              (color-normal '((fg . light-green) (bg . black)))
              (color-highlight '((fg . black) (bg . light-green)))))
      (menu-entries menu-entries)))

    ;; The image machinery overrides "/" with the read-only ISO + a volatile
    ;; (RAM) overlay, so no real disk/LUKS/UUID is referenced anywhere.
    (file-systems %base-file-systems)))

;; Plain OS (no custom entries) → used only to derive the EXACT kernel/initrd
;; the auto live entry will boot, so the GPU / no-GPU entries reuse them verbatim.
(define %live-os-plain (make-live-os '()))

(define %image-os
  (operating-system-for-image
   (image-with-os iso9660-image %live-os-plain)))

(define %live-kernel  (operating-system-kernel-file %image-os))
(define %live-initrd  (operating-system-initrd-file %image-os))

;; The SAME root device the auto entry searches for: the iso9660 volume's
;; (deterministic) fs-UUID — NOT a volume label.  build.sh passes
;; `--label=SECURITYOS_LIVE', which renames the volume but leaves the fs-UUID
;; untouched, so keying on the UUID (`search --fs-uuid') always finds the disc.
(define %image-root-device
  (file-system-device (operating-system-root-file-system %image-os)))

;; The COMPLETE kernel command line the auto entry boots with — including the
;; self-referential root=/gnu.system=/gnu.load= tokens that tell the initrd which
;; system to switch-root into.  Guix injects those ONLY into the auto-generated
;; entry; a hand-written menu-entry's linux-arguments are emitted verbatim, so it
;; MUST carry them too, or the initrd finds no boot file and drops to a rescue
;; REPL.  Each entry below appends ONLY its per-machine extras.
(define %image-kernel-arguments
  (operating-system-kernel-arguments %image-os %image-root-device))

(define (live-entry label extra-args)
  (menu-entry
   ;; Stamp every entry with the build version so you can see — before login,
   ;; even if graphics fail — exactly which image GRUB is booting.
   (label (string-append label " · " %build-version))
   (device %image-root-device)
   (linux %live-kernel)
   (linux-arguments (append %image-kernel-arguments extra-args))
   (initrd %live-initrd)))

(define %boot-menu-entries
  (list
   ;; --- machines WITH a usable GPU: hardware-accelerated KMS ---------------
   (live-entry "Security Ops — Intel GPU (i915)"
               '("modprobe.blacklist=amdgpu,radeon"
                 "i915.modeset=1" "intel_iommu=on" "iommu=pt"))
   (live-entry "Security Ops — AMD GPU (amdgpu)"
               '("modprobe.blacklist=i915,xe,nouveau"
                 "amdgpu.modeset=1" "amd_iommu=on" "iommu=pt"))
   ;; --- machines WITHOUT a usable GPU: nomodeset + software rendering ------
   (live-entry "Security Ops — Intel CPU (no GPU / safe graphics)"
               '("nomodeset"
                 "modprobe.blacklist=amdgpu,radeon,nouveau"
                 "intel_iommu=on" "iommu=pt"))
   (live-entry "Security Ops — AMD CPU (no GPU / safe graphics)"
               '("nomodeset"
                 "modprobe.blacklist=i915,xe,nouveau"
                 "amd_iommu=on" "iommu=pt"))))

;; Final system handed to `guix system image'.
(make-live-os %boot-menu-entries)
