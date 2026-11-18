# Security Ops OS — Complete Package Inventory

Every package shipped in the live image, by function. Grounded in
`config.scm` (system profile), `securityops/home.scm` (Guix Home for the
`securityops` user), and the **securityops** channel. Generated for build
`r13 · v1.14.0 · sway · kernel 7.3.4`.

This table documents the curated baseline. Maintainer overrides in
`securityops/settings.json` may add or mask packages without rewriting that
baseline; inspect the effective changes with `./securityopsctl package changes`.

## Candidate reconciliation — 2026-09-26

These observations do not assert inclusion in a rebuilt ISO:

Selection update (2026-11-13): `securityopsctl` now records
`thunar@4.20.10`, `securityops-guix-center@0.2.0`,
`security-ops-installer2@0.1.0`, `heroic@2.22.1`, `steam@1.0.0.87`
`torbrowser@16.0.1` and `guixvis@0.8.0`
in the canonical overrides. Real package-object
tests cover the live OS and generated Sway, XMonad+XLibre and KDE systems,
without building images or launching applications. Installer 2 remains a
planner with Apply disabled; this does not fulfill graphical installation.

| Component | Observed candidate / status |
|---|---|
| Linux SecurityOps | 7.3.4 pinned from cdn.kernel.org; fresh Guix archive hash and developer signature over the uncompressed tar verified. All 29 names occur in Kconfig declarations; resolved configuration/build/boot validated only by the release build gates for this revision |
| Thunar | 4.20.10, selected from the pinned GNU XFCE module for live/generated systems; runtime and ISO validation follow the release build |
| Guix Center / Installer 2 | 0.2.0 / 0.1.0; selected through local package recipes and canonical overrides; earlier isolated packaging/import checks do not validate a new image |
| Steam | 1.0.0.87 launcher selected from `(securityops packages games)` at pinned channel `34a0099058eada895d92069f36feb2267ebfa203`; not Nonguix's 1.0.0.85; the downloaded client self-updates separately |
| Heroic | 2.22.1 selected from `(nongnu packages game-client)` at pinned Nonguix `c241d19ff840dc75556f722b231760d119b6adea` |
| Tor Browser | 16.0.1 SecurityOps recipe selected in live/generated systems; a single recipe resolves for the specification, and required tests enforce object identity, unique occurrence and default output. Runtime/privacy validation pending |
| guixvis (repository named pacvis) | 0.8.0 selected from the OS-local GPL module; immutable source/vendor origins from channel commit `017b9e3aa09bbafca341dfba7c91ca96211e8020`, normal pinned Rust/Cargo. The channel pin advances to `34a0099058eada895d92069f36feb2267ebfa203` for the refreshed r13 image. One canonical Store build: 121 Rust tests passed, two live/cache tests ignored; help/version passed. Full runtime/ISO qualification pending; older inspected ISO contained 0.4.1 |
| ArtCraft suite (13 apps) | Official upstream Linux binaries repacked without modification: PhotoCraft 0.9.0, VectorCraft 0.10.0, FilmCraft 0.7.2, LightCraft 0.8.0, PdfCraft 0.8.0, EffectCraft 0.10.0, DesignCraft 0.8.0, FigCraft 0.6.0, WordCraft 0.7.0, SoundCraft 0.5.0, DeckCraft 0.7.0, CADCraft 0.7.0, GridCraft 0.7.0. Source code is MIT or Apache-2.0; ArtCraft brand assets use separate non-free terms. Selected via `securityops/settings.json` `packages.add` and OS-local `(securityops packages *craft)` recipes |

The older inspected host snapshot used SecurityOps channel
`37a314beb2ef82608bb3746811a1c440eecdfdb3`; it is not the pinned candidate graph
used above. These selected versions are not a claim of latest upstream releases
or authenticated complete closures. Heroic and Steam were not found in the
inspected older ISO and have not been opened in this repair. No game, account,
license or GPU compatibility is validated; inherited recipe limits are listed
in SECURITY.md.


## Desktop stacks

| Package | What it does |
|---|---|
| sway | Wayland tiling compositor (explicit live/install default) |
| swaybg | Wallpaper setter for sway |
| swayidle | Idle-management daemon (lock/sleep) |
| swaylock | Wayland screen locker |
| waybar | Wayland status bar |
| mako | Wayland notification daemon |
| fnott | Lightweight Wayland notification daemon |
| wofi | Wayland application launcher menu |
| bemenu | Wayland-native dmenu launcher |
| rofi | Application launcher / dmenu replacement |
| grim | Wayland screenshot grabber |
| slurp | Select a screen region (Wayland) |
| flameshot | Screenshot tool with annotation |
| wl-clipboard | Wayland clipboard copy/paste utilities |
| wlr-randr | Output/display configuration for wlroots |
| wlrctl | Command-line wlroots automation utility |
| wlsunset | Day/night gamma (blue-light) adjustment |
| awww | Animated Wayland wallpaper daemon |
| network-manager-applet | NetworkManager tray applet (nm-applet) |
| lxappearance | GTK theme configurator |
| brightnessctl | Backlight brightness control |
| tuigreet | greetd terminal login greeter |
| xorg-server-xwayland | Run X11 apps under sway |
| xlibre-server | Pinned XLibre X11 server used by the XMonad choice |
| xmonad | Keyboard-driven tiling window manager on XLibre |
| ghc-xmonad-contrib | XMonad extension library |
| xmobar | XMonad-oriented status bar |
| xinit / xauth | Start and authenticate the live XLibre session |
| xterm / dmenu | Compiled-default XMonad terminal and launcher |
| picom / feh | XMonad compositor and Security Ops wallpaper helper |
| plasma / plasma-workspace / plasma-desktop | Full KDE Plasma Wayland desktop |
| konsole / dolphin | KDE terminal and file manager |
| xdg-utils | Desktop integration scripts (xdg-open) |
| xdg-desktop-portal | Sandboxed-app desktop portal backend |
| flatpak-xdg-utils | xdg-utils shims for Flatpak sandbox |
| desktop-file-utils | .desktop file database tools |
| xkeyboard-config | X/Wayland keyboard layout data |
| dbus | Message bus / dbus-run-session |
| glib | GLib core application library |
| gtk | GTK GUI toolkit |
| librsvg | SVG rendering library |

## Terminals & Shell

| Package | What it does |
|---|---|
| wezterm | **Default terminal** (OpenGL, fish shell, kitty-graphics image preview) |
| alacritty | GPU-accelerated terminal emulator |
| kitty | GPU-accelerated terminal emulator |
| cool-retro-term | Retro CRT-style terminal emulator |
| fish | Friendly interactive shell |
| starship | Fast cross-shell prompt |
| zoxide | Smarter cd / directory jumper |
| bat | cat clone with syntax highlighting |
| fzf | Command-line fuzzy finder |
| tmux | Terminal multiplexer |
| tree | Recursive directory tree lister |

## Editors

| Package | What it does |
|---|---|
| emacs | Extensible GNU text editor |
| vim | Vi-improved modal text editor |
| neovim | Modernized Vim fork |
| nano | Simple console text editor |
| emacs-magit | Git porcelain inside Emacs |
| emacs-org | Org-mode notes/outlining |
| emacs-org-static-blog | Static blog generator for Org |
| emacs-vterm | Full terminal emulator in Emacs |
| emacs-emojify | Emoji display in Emacs |
| emacs-nerd-icons | Nerd Font icon set for Emacs |

## Browsers & Privacy

| Package | What it does |
|---|---|
| librewolf | Hardened Firefox fork (default browser, Super+e) |
| icecat | GNU privacy-focused Firefox derivative |
| torbrowser | Tor Browser bundle |
| ungoogled-chromium | De-Googled Chromium browser |
| google-chrome-stable | Google Chrome (nonguix) |
| w3m | Terminal web browser / pager |
| lynx | Text-mode web browser |

## Recon & Network (incl. DNS)

| Package | What it does |
|---|---|
| nmap | Network and port scanner |
| masscan | Internet-scale fast port scanner |
| arp-scan | ARP-based host discovery |
| netdiscover | Passive/active ARP reconnaissance |
| fping | Parallel ICMP ping sweeper |
| mtr | Combined traceroute and ping diagnostic |
| whois | Domain/IP WHOIS lookups |
| ndisc6 | IPv6 neighbor/router discovery tools |
| dnstracer | Trace DNS delegation chains |
| ldns | DNS library with `drill` tool |
| knot | DNS server with `kdig` utility |
| curl | URL data transfer tool |
| wget | Command-line file downloader |
| openssh | SSH client and server |
| iproute | Modern ip/ss networking tools |
| net-tools | Legacy ifconfig/route/netstat |
| ethtool | NIC configuration and diagnostics |

## Sniffing / MITM

| Package | What it does |
|---|---|
| tcpdump | Command-line packet capture/analysis |
| wireshark | GUI network protocol analyzer |
| macchanger | Spoof/randomize MAC addresses |
| proxychains-ng | Force connections through proxy chains |
| socat | Multipurpose bidirectional socket relay |
| netcat-openbsd | TCP/IP swiss-army-knife (nc) |

## Wireless & Bluetooth

| Package | What it does |
|---|---|
| aircrack-ng | Wi-Fi WEP/WPA cracking suite |
| reaver | WPS PIN brute-force attack |
| kismet | Wireless detector / sniffer / IDS |
| iw | Modern Wi-Fi configuration tool |
| wireless-tools | Legacy iwconfig utilities |
| wpa-supplicant | WPA/WPA2/WPA3 client |
| blueman | Bluetooth manager GUI |
| bluez | Linux Bluetooth protocol stack |
| bluez-alsa | Bluetooth A2DP audio for ALSA |

## Cracking / RE / Forensics

| Package | What it does |
|---|---|
| hydra | Parallel network login brute-forcer |
| hashcat | GPU-accelerated password hash cracker |
| john-the-ripper-jumbo | Password cracker (JtR jumbo build) |
| radare2 | Reverse-engineering / disassembly framework |
| rizin | radare2 fork RE toolkit |
| binwalk | Firmware analysis and extraction |
| perl-image-exiftool | Read/write file and image metadata |

## Crypto, Keys & Hardening

| Package | What it does |
|---|---|
| gnupg | OpenPGP encryption and signing |
| openssl | TLS and general crypto toolkit |
| age | Modern simple file encryption |
| keepassxc | Offline password manager |
| libfido2 | FIDO2/U2F hardware-key library |
| pwgen | Random password generator |
| kleopatra | GPG/X.509 certificate manager GUI |
| pinentry | Passphrase entry helper |
| pinentry-gtk2 | GTK passphrase entry dialog |
| firejail | Sandbox/jail untrusted applications |
| lynis | System security auditing tool |
| clamav | Antivirus engine and scanner |
| audit | Linux kernel audit userspace |
| acct | Process accounting utilities |

## Firewall / VPN / Anonymity

| Package | What it does |
|---|---|
| nftables | In-kernel stateful firewall (the live ruleset) |
| wireguard-tools | WireGuard VPN tooling |
| openvpn | OpenVPN client/server |
| tor | Tor anonymity network daemon |
| torsocks | Torify arbitrary socket connections |
| nyx | Terminal Tor status monitor |
| i2pd | I2P anonymous-network router (C++) |
| mullvad-vpn-desktop | Mullvad VPN GUI + CLI |

## Filesystems, Disk & Archives

| Package | What it does |
|---|---|
| lf | Terminal file manager (inline image preview via ueberzugpp) |
| ranger | Vi-style terminal file manager |
| ncdu | NCurses disk-usage analyzer |
| gparted | Graphical partition editor |
| gnome-disk-utility | GNOME Disks management GUI |
| parted | Command-line partition editor |
| ntfs-3g | NTFS read/write driver |
| exfatprogs | exFAT filesystem utilities |
| exfat-utils | Alternative exFAT utilities |
| fuse-exfat | FUSE exFAT driver |
| dosfstools | FAT filesystem utilities |
| e2fsprogs | ext2/3/4 filesystem utilities |
| xfsprogs | XFS filesystem utilities |
| btrfs-progs | Btrfs filesystem utilities |
| f2fs-tools | F2FS flash-filesystem utilities |
| bcachefs-tools | bcachefs filesystem utilities |
| mergerfs | Featureful union FUSE filesystem |
| udevil | Device/filesystem mount manager |
| fuse | Userspace filesystem support |
| smartmontools | SMART disk health monitoring |
| testdisk | Partition recovery / PhotoRec carving |
| ddrescue | Data-recovery copy tool |
| mtools | Access MS-DOS disks without mounting |
| rsync | Fast incremental file sync/transfer |
| borg | Deduplicating encrypted backups |
| atool | Unified archive manager wrapper |
| 7zip | 7-Zip archiver |
| p7zip | 7-Zip POSIX port |
| zip | Zip archive creator |
| unzip | Zip archive extractor |
| file | Identify file types |
| lsof | List open files and sockets |

## System & Monitoring

| Package | What it does |
|---|---|
| util-linux | Core Linux system utilities |
| pciutils | lspci / PCI inspection tools |
| usbutils | lsusb / USB inspection tools |
| dmidecode | DMI/SMBIOS hardware reporting |
| hwinfo | Hardware detection and probing |
| hdparm | ATA/SATA disk parameter tuning |
| nvme-cli | NVMe device management |
| lm-sensors | Hardware temperature/sensor readout |
| psmisc | pstree/killall/fuser tools |
| procps | ps/top/free/uptime utilities |
| strace | Trace system calls |
| ltrace | Trace library calls |
| htop | Interactive process viewer |
| btop | Modern resource monitor (TUI) |
| glances | Cross-platform system monitor |
| sysstat | Performance stats (sar/iostat) |
| inxi | System information report script |
| fastfetch | Fast system-info fetch |
| pfetch | Minimal system-info fetch |
| coreutils | GNU core file/shell utilities |
| findutils | find / xargs / locate |
| grep | Pattern search utility |
| sed | Stream editor |
| gawk | GNU AWK text processing |
| jq | Command-line JSON processor |
| chafa | Terminal image previewer |
| ueberzugpp | Terminal image overlay renderer |
| enca | Detect/convert text encodings |
| uchardet | Charset detection library/tool |
| v4l-utils | Video4Linux device utilities |
| linux-firmware | Device firmware blobs (nonguix) |

## Media & Graphics

| Package | What it does |
|---|---|
| mpv | Scriptable media player |
| vlc | Versatile media player |
| zathura | Keyboard-driven document viewer |
| zathura-pdf-poppler | Poppler PDF backend for zathura |
| qpdfview | Tabbed PDF document viewer |
| poppler | PDF rendering library/tools |
| imagemagick | Image manipulation toolkit |
| feh | Lightweight image viewer |
| qimgv | Qt image viewer |
| pavucontrol | PulseAudio volume control GUI |
| pavucontrol-qt | Qt PulseAudio volume control |
| pulsemixer | TUI PulseAudio mixer |
| pulseaudio | PulseAudio sound server |
| playerctl | MPRIS media-player control |
| alsa-utils | ALSA sound utilities |
| alsa-lib | ALSA sound library |
| ffmpeg | Audio/video transcoding toolkit |
| ffmpegthumbnailer | Video thumbnail generator |
| mpd | Music Player Daemon |
| cmus | Console music player |
| noisetorch | Real-time microphone noise suppression |
| libass | Subtitle (ASS/SSA) rendering |
| libva | VA-API video acceleration |
| libva-utils | VA-API test/utility tools |
| mesa | OpenGL implementation (HW DRI / llvmpipe) |
| mesa-utils | OpenGL info/test tools (glxinfo) |

## Fonts

| Package | What it does |
|---|---|
| font-dejavu | DejaVu Unicode font family |
| font-liberation | Metric-compatible MS-font replacements |
| font-gnu-freefont | GNU FreeFont Unicode family |
| font-google-noto | Noto broad-Unicode coverage fonts |
| font-jetbrains-mono | JetBrains Mono coding font |
| font-terminus | Terminus bitmap terminal font |
| font-awesome | Font Awesome icon glyphs |
| font-iosevka-term | Iosevka Term monospace font (default) |

## Dev & Build

| Package | What it does |
|---|---|
| gcc-toolchain | GCC C/C++ compiler toolchain |
| gnu-make | Build automation tool |
| cmake | Cross-platform build-system generator |
| python | Python interpreter |
| python-pip | Python package installer |
| python-virtualenv | Python virtual environments |
| python-emoji | Emoji handling for Python |
| git | Distributed version control |
| git-lfs | Git large-file storage |
| binutils | Assembler/linker/objdump tools |
| pkg-config | Compiler/linker flag helper |
| sqlite | Embedded SQL database engine |
| libxml2 | XML parsing/processing library |
| pandoc | Universal document converter |
| ansible | Agentless IT automation |
| flatpak | Sandboxed app package manager |
| xlsx2csv | Convert XLSX spreadsheets to CSV |
| cl-clx | Common Lisp X11 client library |
| cl-css | Common Lisp CSS generation library |

## Input, i18n & Misc

| Package | What it does |
|---|---|
| fcitx5 | Input-method framework |
| fcitx5-qt | Qt input-method integration |
| unicode-emoji | Unicode emoji data tables |
| qbittorrent | Qt BitTorrent client |
| cmatrix | Terminal "Matrix" rain animation |

## Security Ops Native Tools (securityops channel)

| Package | What it does |
|---|---|
| evelin-bin | Post-quantum transport (ML-KEM-1024 / ML-DSA-87 / ChaCha20-Poly1305), prebuilt static-musl binaries |
| esquema | Rootless, Guile-native container runtime — user/mount/PID/UTS/IPC/net/cgroup namespaces, `pivot_root`, cap-drop, seccomp-BPF allowlist, `NO_NEW_PRIVS` |
| security-ops-installer | Guided black-on-cyan whiptail disk installer (`security-ops-install`): ext4/btrfs/xfs (ZFS planned/disabled), LUKS2, Sway/XMonad+XLibre/KDE, generates a mode-0600 `config.scm` + runs `guix system init` through the pinned channel time-machine |
| zupt | Post-quantum backup compressor CLI (ML-KEM-768 + X25519 hybrid encryption, source-only build) |
| zupt-gui | PySide6/Qt6 frontend for `.zupt` archives |
| turborec | Screen + audio recorder (CLI + Tk GUI) |
| torando-gui | Loopback Tor-control GUI daemon |
| turborecorder | FFmpeg screen/audio recorder script at `/usr/bin/turborecorder` (HW-encoder auto-detect) |
| mirim | Tiny encrypted-at-rest embedded SQL database (`#![forbid(unsafe_code)]` Rust, CLI + signing tool) |

## Third-party tools repackaged in the channel (included on the image)

| Package | Version | What it does |
|---|---|---|
| burpsuite | 2026.10.1 | Burp Suite Community Edition — web security testing (official PortSwigger JAR on OpenJDK 21) |
| maltego | 4.14.0 | Maltego Graph — OSINT link analysis (official Maltego Linux distribution) |
| cadcraft | 0.7.0 | CADCraft — 2D/3D CAD |
| deckcraft | 0.7.0 | DeckCraft — presentation decks |
| designcraft | 0.8.0 | DesignCraft — graphic design |
| effectcraft | 0.10.0 | EffectCraft — visual effects |
| figcraft | 0.6.0 | FigCraft — diagram and figure design |
| filmcraft | 0.7.2 | FilmCraft — video editing |
| gridcraft | 0.7.0 | GridCraft — spreadsheets |
| lightcraft | 0.8.0 | LightCraft — photo management |
| pdfcraft | 0.8.0 | PdfCraft — PDF tools |
| photocraft | 0.9.0 | PhotoCraft — photo editing |
| soundcraft | 0.5.0 | SoundCraft — audio production |
| vectorcraft | 0.10.0 | VectorCraft — vector graphics |
| wordcraft | 0.7.0 | WordCraft — word processing |

---


---

**Phase 29 desktop integration:** Sway remains the default, while XMonad on the
real pinned XLibre server and KDE Plasma on Wayland are selectable. See
[`DESKTOPS.md`](DESKTOPS.md) for session behavior, installer constraints, and
the explicit X11 and channel-authentication caveats.

_© Cristian Cezar Moisés · contact sac@securityops.co · AGPL-3.0-or-later_
