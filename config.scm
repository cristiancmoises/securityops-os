;; -*- mode: scheme; -*-
;; CodeMark v1 project=4c63e0fe-589c-4944-8449-97e211a38b72 file=d8e66588c25f54a4a9b65f3d76afafde owner="Cristian Cezar Mois\u00e9s"
;;; ===========================================================================
;;; Security Ops OS — Live ISO  (built and managed with GNU Guix)
;;; Slogan: "In Code We Trust."   Logo: assets/sec.png
;;; ===========================================================================
;;;
;;; A portable, "boot-it-anywhere" live image of the securityops workstation:
;;; a hardened, privacy-focused GNU/Linux loaded with security tooling, a
;;; selectable Sway, XMonad/XLibre, and KDE desktops, a guided disk installer, and the
;;; SecurityOps logo on the GRUB menu and the desktop.
;;;
;;; Modular (Testament-style) layout — the moving parts live in their own
;;; modules under ./securityops, tied together here:
;;;     (securityops kernel)    -> linux-securityops  (version from settings.json)
;;;     (securityops sessions)  -> greeter + three immutable session launchers
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
;;; HARDENING / PERFORMANCE: configurable vanilla kernel.org Linux (config
;;; derived from the proven nonguix kernel) + memory-hardening kernel cmdline
;;; flags + a sysctl profile + zram swap + earlyoom.  None of it cripples the
;;; pentest/forensics toolset (no lockdown, no module-signature enforcement).
;;;
;;; "USE MY GUIX": the whole (sanitised) source tree of this image is embedded
;;; at /etc/securityops/src on the running system, so anyone who boots it can
;;; read, tweak and rebuild the exact configuration.
;;;
;;; Maintainer: Cristian Cezar Moisés <sac@securityops.co>
;;; License: AGPL-3.0-or-later (see LICENSE).  © Cristian Cezar Moisés.
;;; ===========================================================================

;; Naming the module keeps Guix's local-source closure scanner from attempting
;; and warning about an implicit, nonexistent (config) module.  The final
;; expression remains the operating-system value consumed by `guix system`.
(define-module (config))

(use-modules
 (gnu)
 (gnu system)
 (gnu system locale)              ; locale-definition
 (gnu system image)               ; operating-system-for-image, iso9660-image
 (gnu system file-systems)        ; file-system-label
 (gnu system linux-initrd)        ; %base-initrd-modules
 (gnu system pam)                 ; unix-pam-service
 (gnu bootloader)                 ; menu-entry
 (gnu bootloader grub)            ; grub-theme, grub-efi-bootloader
 (gnu services)                   ; extra-special-file, simple-service
 (gnu services guix)              ; guix-home-service-type
 (guix gexp)
 (guix packages)                  ; package?, package-name
 (srfi srfi-1)                    ; filter, delete-duplicates
 (srfi srfi-13)                   ; string-suffix?
 ;; --- our own modules (resolved via `guix … -L .') ---------------------
 (securityops branding)            ; distribution identity + branded uname
 (securityops kernel)              ; linux-securityops
 (securityops hardening)           ; shared live/installed runtime policy
 (securityops settings)            ; maintainer-controlled kernel/packages
 (securityops source-selection)    ; shared image/evaluator source boundary
 (securityops sessions)            ; three-session greetd chooser
 (securityops services live-credentials) ; per-boot local-console identity
 (securityops home)                ; %home-environment (Guix Home)
 (securityops packages esquema)    ; esquema — rootless, Guile-native container runtime
 (securityops packages installer)) ; security-ops-install — guided disk installer

(use-service-modules base desktop linux networking shepherd sysctl xorg)

(use-package-modules
 admin antivirus base cmake commencement compression compton cryptsetup curl disk
 dns emacs engineering file file-systems firmware fonts fontutils freedesktop gl
 glib gnome gnupg gnuzilla golang-crypto hardware i2p image image-viewers imagemagick
 linux lsof lxde monitoring mtools music ncdu ncurses networking nss password-utils pciutils
 pdf photo pulseaudio python rsync rust-apps security-token shells shellutils slang
 ssh suckless terminals text-editors tls tmux tor version-control video vim vpn w3m
 web-browsers wget wm xdisorg xorg kde-plasma kde-systemtools
 bittorrent librewolf                       ; qbittorrent, librewolf
 chromium tor-browsers)                     ; ungoogled-chromium, torbrowser

;; XLibre ships in the commit-pinned securityops channel.  The XMonad session
;; constructs its server wrapper from this module; ordinary Xorg is never
;; relabelled.
(use-modules (xlibre))

;; nonguix LAST so its blob-enabled `linux-firmware' shadows any gnu bindings.
(use-modules (nongnu packages linux)        ; linux-firmware
             (nongnu packages chrome)       ; google-chrome-stable
             (small-guix packages mullvad)  ; mullvad-vpn-desktop
             (securityops packages apps)    ; latest Evelin/Zupt/Torando packages
             (securityops packages games)   ; steam 1.0.0.87 bootstrap
             (securityops services torando)) ; torando-gui-service-type
;; librewolf IS baked in (r9): the ISO build reuses the already-built store item
;; (see %browser-packages), so no from-source compile happens at image time.

;;; ---------------------------------------------------------------------------
;;; Identity & knobs
;;; ---------------------------------------------------------------------------
(define %live-user "securityops")
(define %locked-root-account
  ;; Guix otherwise synthesizes UID 0 with an empty password when no explicit
  ;; root account is present.  The live image must never inherit that
  ;; first-login convenience behavior: administration goes through the
  ;; per-boot securityops credential and password-protected sudo.
  (user-account
   (name "root")
   (password "!")
   (uid 0)
   (group "root")
   (comment "System administrator (locked)")
   (home-directory "/root")))
(define %kbd (keyboard-layout "br" "abnt2"))   ; the maintainer's layout; change freely
(define %wallpaper (local-file "assets/sec.png"))    ; the SecurityOps logo
(define %securityops-substitute-url "https://substitutes.securityops.com.br")
(define %securityops-farm-substitute-url "https://substitutes.securityops.co")
(define %ci-substitute-url "https://ci.guix.gnu.org")
(define %securityops-substitute-key
  (local-file "substitutes.securityops.com.br.pub"))
(define %ci-substitute-key
  (local-file "ci.guix.gnu.org.pub"))

;; The image's own (sanitised) build source, embedded so a booted user can
;; inspect and rebuild it.  Build output, VCS data, local assistant metadata,
;; and common secret-key file names are excluded.  GET_THE_ISO.md is also
;; excluded because it records the finished image's own hash; embedding it
;; would create a checksum cycle where documenting an ISO changes that ISO.
(define %config-src
  (local-file "." "securityops-src"
              #:recursive? #t
              #:select? securityops-source-file?))

;; The live user's dotfiles, keybinds and desktop packages are now declared as a
;; proper GNU Guix Home environment in (securityops home) and applied at boot via
;; `guix-home-service-type' (below).  No hand-rolled /etc/skel activation needed;
;; the configs read the system-wide /etc/securityops/wallpaper.png.

;;; ---------------------------------------------------------------------------
;;; Package set — curated from the workstation, minus hardware/heavy bits.
;;; ---------------------------------------------------------------------------
;; All three login choices are complete in the SYSTEM profile, so no session
;; waits for Guix Home before its compositor/server, terminal, or launcher can
;; start.  XLibre is present specifically for XMonad; KDE and Sway use Wayland.
(define %desktop-packages
  (list sway swaybg swayidle swaylock                ; compositor + idle/lock
        wezterm wofi bemenu rofi                     ; terminal (wezterm) + launchers
        waybar mako                                  ; bar + notifications
        grim slurp wl-clipboard wlr-randr wlsunset   ; screenshots / clipboard / outputs
        network-manager-applet                       ; nm-applet (waybar tray Wi-Fi)
        lxappearance xdg-utils                       ; GTK theming + xdg-open
        xorg-server-xwayland                         ; run X apps under sway
        brightnessctl                                ; sway XF86MonBrightness keys
        tuigreet                                     ; greetd TUI greeter
        dbus                                         ; dbus-run-session
        ;; XMonad on XLibre.  xlibre-video-intel is deliberately excluded by
        ;; the session wrapper; modern Intel uses XLibre's modesetting driver.
        xlibre-server xmonad ghc-xmonad-contrib xmobar
        xinit xauth xterm xset setxkbmap dmenu feh picom
        ;; Full KDE Plasma Wayland session.
        plasma plasma-workspace konsole dolphin))

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
        ungoogled-chromium            ; fallback target for the sway browser keybind
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
        evelin-bin
        ;; Security Ops rootless container runtime (C + Guile FFI sandbox)
        esquema
        ;; Security Ops post-quantum backup & compression (CLI + Qt GUI)
        zupt zupt-gui))

(define %installer-packages
  ;; The guided disk installer + the CLI tools it drives.  parted / the mkfs.*
  ;; family / util-linux already come in via %fs-packages; here we add the two
  ;; still-missing pieces: whiptail (newt) for the TUI and cryptsetup for LUKS.
  (list security-ops-installer newt cryptsetup))

(define %sysutil-packages
  (list util-linux pciutils usbutils dmidecode hwinfo hdparm nvme-cli ncurses
        lm-sensors ethtool iproute net-tools psmisc procps strace ltrace
        gcc-toolchain git gnu-make cmake python
        ;; Runtime firmware blobs for hardware that needs them (Wi-Fi/GPU/etc.).
        ;; Early CPU microcode is intentionally omitted from this live image.
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
  ;; steam is the SecurityOps channel rebuild of Valve's 1.0.0.87 archive
  ;; around nonguix's FHS container; pin the channel object explicitly because
  ;; nonguix now exports the same bootstrap version.
  (list mesa mesa-utils steam))

(define (package-item-package item)
  ;; `specifications->packages' returns (PACKAGE OUTPUT) pairs, whereas the
  ;; curated lists contain bare packages.  Normalize both shapes here.
  (if (package? item) item (car item)))

(define (package-item-name item)
  (package-name (package-item-package item)))

(define (package-item-key item)
  (string-append (package-item-name item) ":"
                 (if (package? item) "out" (cadr item))))

(define (package-item=? left right)
  (string=? (package-item-key left) (package-item-key right)))

(define %live-packages
  (delete-duplicates
   (filter
    (lambda (item)
      (not (member (package-item-name item) %package-removals)))
    (append
     ;; This source-built Coreutils variant has the same package/output key as
     ;; the base package, so it wins deterministic de-duplication without
     ;; creating profile collisions.  Only uname's GNU-specific -o field is
     ;; branded; all kernel and machine fields preserve upstream semantics.
     (list securityops-coreutils)
     ;; User additions come first so an explicit version/output wins over the
     ;; same default-output package in a curated/base list.
     (specifications->packages %package-additions)
     %desktop-packages %terminal-packages
     %editor-packages %browser-packages %fs-packages %security-packages
     %installer-packages
     %sysutil-packages %media-packages %font-packages %gl-packages
     ;; nss-certs (TLS root CAs) is already in %base-packages on the pinned
     ;; Guix, so it is not re-listed.
     %base-packages))
   package-item=?))

;;; ---------------------------------------------------------------------------
;;; Hardening / performance knobs (runtime — none of it breaks pentest tools)
;;; ---------------------------------------------------------------------------
(define %securityops-sysctl
  ;; Live-only tuning. Security policy is merged separately for both systems.
  '(;; --- performance: memory / VM (zram-backed swap + responsiveness) ---
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
SocksPort 127.0.0.1:9050
VirtualAddrNetworkIPv4 10.192.0.0/10
AutomapHostsOnResolve 1
TransPort 127.0.0.1:9040
DNSPort 127.0.0.1:5353
ControlPort 127.0.0.1:9051
CookieAuthentication 1
SafeLogging 1
")))))

(define %greetd-config
  ;; greetd + tuigreet on vt7: a GL-free TUI login with a session chooser.
  (greetd-configuration
   (allow-empty-passwords? #f)
   (greeter-supplementary-groups '("video" "input"))
   (terminals
    (list (greetd-terminal-configuration
           (terminal-vt "7")
           (terminal-switch #t)
           (extra-shepherd-requirement '(securityops-live-credential))
           (default-session-command %greeter-command))))))

(define %zram-config
  ;; Compressed RAM swap — invaluable on a live image whose root is a RAM
  ;; overlay; keeps low-RAM machines from OOMing.
  (zram-device-configuration
   (size "6G")
   (compression-algorithm 'zstd)))

(define %earlyoom-config
  ;; Userspace OOM killer: act before the kernel OOM hangs the desktop, but
  ;; never sacrifice the selected compositor/server or the greeter.
  (earlyoom-configuration
   (minimum-available-memory 5)
   (minimum-free-swap 5)
   (avoid-regexp
    "(^|/)(sway|swaybg|waybar|xmonad|X|kwin_wayland|plasmashell|greetd|tuigreet|shepherd)$")))

(define %live-services
  (cons*
   ;; FHS dynamic-linker shim so foreign glibc ELF binaries can exec.
   (extra-special-file "/lib64/ld-linux-x86-64.so.2"
                       (file-append glibc "/lib/ld-linux-x86-64.so.2"))
   ;; Wallpaper available system-wide to the Sway and XMonad sessions.
   (extra-special-file "/etc/securityops/wallpaper.png" %wallpaper)
   ;; Build identifier — `cat /etc/securityops/build-id' on the running system to
   ;; confirm WHICH image you booted (ends the "is this the new build?" doubt).
   (extra-special-file "/etc/securityops/build-id"
                       (plain-file "build-id" (string-append %build-version "\n")))
   ;; The image's own source tree, for "boot it and rebuild it".
   (extra-special-file "/etc/securityops/src" %config-src)
   ;; The image's pinned channels (guix, nonguix, radix, rosenthal, small-guix,
   ;; securityops, gocix, and sops-guix) as
   ;; the SYSTEM-WIDE `guix pull' default, so `guix pull' on the running system
   ;; resolves the exact source revisions documented by this release.
   (extra-special-file "/etc/guix/channels.scm" (local-file "channels.guix"))
   ;; turborecorder at a stable system-wide path.
   (extra-special-file "/usr/bin/turborecorder"
                       (local-file "securityops/dotfiles/turborecorder"
                                   #:recursive? #t))   ; keep the +x bit
   ;; TTY login banner with the slogan.
   (simple-service 'securityops-motd etc-service-type
     (list (list "motd"
                 (plain-file "motd" (string-append "
   Security Ops  —  In Code We Trust.
   build: " %build-version "

   live user: securityops
   one-boot password: trusted VT1 only (Ctrl+Alt+F1; return with Ctrl+Alt+F7)
   sudo requires the current one-boot password; root is locked.

   Install to disk:  security-ops-install     (or press Super+Shift+I)
       guided TUI · ext4/btrfs/xfs · LUKS2 · Sway/XMonad+XLibre/KDE · Esquema

")))))

   ;; GNU Guix Home for the live user: shared tools plus Sway/Waybar keybinds.
   ;; XMonad uses an immutable compiled default and KDE manages its own state.
   (service guix-home-service-type
            (list (list %live-user %home-environment)))

   ;; Torando — loopback Tor-control GUI daemon (securityops channel).
   (service torando-gui-service-type)

   ;; greetd login provides the explicit three-session chooser on one VT.
   ;; The one-shot service generates the live password before greetd starts.
   ;; Shadow's chpasswd authenticates through PAM.  Guix's base PAM set has no
   ;; "chpasswd" service, so PAM falls back to /etc/pam.d/other (pam_deny) and
   ;; every password change fails, which in turn blocks greetd.  Declare it.
   (simple-service 'securityops-chpasswd-pam pam-root-service-type
                   (list (unix-pam-service "chpasswd")))
   (simple-service 'securityops-live-credential shepherd-root-service-type
     (list (securityops-live-credential-service %live-user)))
   (service greetd-service-type %greetd-config)

   ;; Reserve VT1 as the trusted, persistent one-boot credential display.
   ;; %desktop-services normally starts mingetty on tty1..tty6; a tty1 getty
   ;; clears and overwrites the credential immediately after the provisioner
   ;; writes it.  Re-add tty2..tty6 explicitly below and delete the inherited
   ;; set in modify-services, leaving conventional recovery logins available
   ;; without allowing another process to race the trusted VT1 message.
   (service mingetty-service-type
            (mingetty-configuration (tty "tty2")))
   (service mingetty-service-type
            (mingetty-configuration (tty "tty3")))
   (service mingetty-service-type
            (mingetty-configuration (tty "tty4")))
   (service mingetty-service-type
            (mingetty-configuration (tty "tty5")))
   (service mingetty-service-type
            (mingetty-configuration (tty "tty6")))

   %simple-firewall
   %tor-service

   ;; Performance / resilience.
   (service zram-device-service-type %zram-config)
   (service earlyoom-service-type %earlyoom-config)
   ;; Boot-time performance tuning (best-effort, all writes guarded).  MGLRU is
   ;; now default-on in the kernel (r9 LRU_GEN_ENABLED=y); we still set its 1 s
   ;; min-TTL for smoother reclaim under the RAM-overlay live root.  We also move
   ;; every CPU to the modern `schedutil' governor for snappier frequency ramp
   ;; (falls back silently to the kernel default if the cpufreq driver lacks it).
   (simple-service 'securityops-perf-tune shepherd-root-service-type
     (list (shepherd-service
            (provision '(securityops-perf-tune))
            (requirement '(udev file-systems))
            (one-shot? #t)
            (start #~(make-forkexec-constructor
                      (list "/bin/sh" "-c"
                            (string-append
                             "echo 1000 > /sys/kernel/mm/lru_gen/min_ttl_ms 2>/dev/null; "
                             "for g in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do "
                             "echo schedutil > \"$g\" 2>/dev/null; done; true"))))
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
   ;; NetworkManager + wpa-supplicant, elogind (desktop seats), polkit, dbus,
   ;; udisks, upower, cups, ntp.  We also fold the hardening sysctl in here.
   (modify-services %desktop-services
     (delete gdm-service-type)
     (delete mingetty-service-type)
     ;; Guix's base console-login PAM policy permits empty passwords for
     ;; first-time installations.  A public live image is not that workflow:
     ;; refuse empty passwords even if a future account declaration regresses.
     (login-service-type config =>
       (login-configuration
        (inherit config)
        (allow-empty-passwords? #f)))
     ;; Console-font instances normally depend on the corresponding getty.
     ;; VT1 has no getty by design, so retain font setup only for tty2..tty6.
     (console-font-service-type fonts =>
       (filter (lambda (tty+font)
                 (not (string=? "tty1" (car tty+font))))
               fonts))
     ;; Ordered, explicit cache policy: Security Ops mirrors first (com.br,
     ;; then the .co build-farm publication, same signing key), then GNU Guix
     ;; CI. No other default substitute is inherited; misses build from source.
     (guix-service-type config =>
       (guix-configuration
        (inherit config)
        (substitute-urls
         (list %securityops-substitute-url
               %securityops-farm-substitute-url
               %ci-substitute-url))
        (authorized-keys
         (list %securityops-substitute-key %ci-substitute-key))))
     (sysctl-service-type config =>
       (sysctl-configuration
        (inherit config)
        (settings (securityops-harden-sysctls
                   (append (sysctl-configuration-settings config)
                           %securityops-sysctl))))))))

;;; ---------------------------------------------------------------------------
;;; The live operating-system (parameterised by GRUB menu-entries so we can
;;; reference the image-transformed kernel/initrd without a definition cycle).
;;; ---------------------------------------------------------------------------
(define %base-kernel-arguments
  (append %securityops-kernel-hardening-arguments
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
    ;; a historical per-login `modprobe -r dccp sctp rds tipc' hook that always
    ;; failed with EPERM (a user cannot unload modules) and only spewed errors.
    "module_blacklist=dccp,sctp,rds,tipc"
    ;; --- performance (Clear-Linux / XanMod flavour, config-free) ---
    "preempt=full"                          ; low-latency desktop scheduling
    "transparent_hugepage=madvise"          ; THP only where asked (latency)
    "rcu_nocbs=all"                         ; offload RCU callbacks off the hot CPUs
    "nowatchdog")))                         ; drop the NMI watchdog overhead

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
    (host-name "securityops-live")
    (label (string-append "Security Ops (auto-detect GPU) · " %build-version))
    (issue %securityops-issue)
    (essential-services
     (securityops-operating-system-essential-services this-operating-system))
    (locale "pt_BR.UTF-8")
    (locale-definitions
     (list (locale-definition (name "pt_BR.UTF-8") (source "pt_BR"))
           (locale-definition (name "en_US.UTF-8") (source "en_US"))))
    (timezone "America/Sao_Paulo")
    (keyboard-layout %kbd)

    ;; Custom Linux 7.1 (vanilla kernel.org, nonguix-derived config + hardening).
    (kernel linux-securityops)
    (firmware (list linux-firmware))
    ;; IMPORTANT — use the plain base-initrd, NOT nonguix's microcode-initrd.
    ;; microcode-initrd prepends a ~15 MB *uncompressed* early-cpio (the CPU
    ;; microcode) to the initramfs.  Under GRUB's iso9660 / i386 loader the
    ;; kernel then ends up with NO main initramfs and panics at boot
    ;; ("Kernel panic - not syncing: VFS: Unable to mount root fs on
    ;; unknown-block(0,0)").  Verified by QEMU repro: base-initrd boots to the
    ;; greeter + desktop chooser; microcode-initrd panics.  Trade-off: no early
    ;; microcode update on this live image (the CPU runs on its built-in
    ;; microcode) — acceptable, and re-addable if booting from a real disk.
    (initrd base-initrd)
    (initrd-modules (append %initrd-extra-modules %base-initrd-modules))
    (kernel-arguments %base-kernel-arguments)

    ;; Live user: locked in the immutable declaration.  A one-shot Shepherd
    ;; service writes a fresh per-boot password to the volatile shadow database
    ;; before greetd starts.  No reusable credential exists in the ISO.
    (users (cons* %locked-root-account
                  (user-account
                   (name %live-user)
                   (comment "Security Ops")
                   (password "!")
                   (group "users")
                   (supplementary-groups
                    '("wheel" "netdev" "audio" "video" "input"
                      "lp" "tty" "dialout" "kvm")))
                  %base-user-accounts))

    (sudoers-file
     (plain-file "sudoers" "\
Defaults secure_path=\"/run/privileged/bin:/run/setuid-programs:/run/current-system/profile/bin:/run/current-system/profile/sbin\"
root ALL=(ALL) ALL
%wheel ALL=(ALL) ALL
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
;; `--label=SECURITY_OPS_LIVE', which renames the volume but leaves the fs-UUID
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
                 "i915.modeset=1"))
   (live-entry "Security Ops — AMD GPU (amdgpu)"
               '("modprobe.blacklist=i915,xe,nouveau"
                 "amdgpu.modeset=1"))
   ;; --- machines WITHOUT a usable GPU: nomodeset + software rendering ------
   (live-entry "Security Ops — Intel CPU (no GPU / safe graphics)"
               '("nomodeset"
                 "modprobe.blacklist=amdgpu,radeon,nouveau"))
   (live-entry "Security Ops — AMD CPU (no GPU / safe graphics)"
               '("nomodeset"
                 "modprobe.blacklist=i915,xe,nouveau"))))

;; Final system handed to `guix system image'.
(make-live-os %boot-menu-entries)
