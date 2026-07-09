;; -*- mode: scheme; -*-
;;; ===========================================================================
;;; (securityos home) — Guix Home for the live `securityops' user
;;; ===========================================================================
;;; The maintainer's full home profile: packages (from ~/.config/guix/home.scm,
;;; minus the NVIDIA-only / huge-niche ones) + dotfiles + keybinds.  Module
;;; imports are reused from the source home.scm so every binding resolves.
;;; Wired in via guix-home-service-type (config.scm); usable standalone too.
;;; NO sensitive data.
;;; ===========================================================================
(define-module (securityos home)
  #:use-module (gnu home services desktop)
  #:use-module (gnu home services fontutils)
  #:use-module (gnu home services gnupg)
  #:use-module (gnu home services shells)
  #:use-module (gnu home services shepherd)
  #:use-module (gnu home services sound)
  #:use-module (gnu home services xdg)
  #:use-module (gnu home services)
  #:use-module (gnu home)
  #:use-module (gnu packages admin)
  #:use-module (gnu packages appimage)
  #:use-module (gnu packages aspell)
  #:use-module (gnu packages audio)
  #:use-module (gnu packages backup)
  #:use-module (gnu packages base)
  #:use-module (gnu packages bash)
  #:use-module (gnu packages benchmark)
  #:use-module (gnu packages bioconductor)
  #:use-module (gnu packages bioinformatics)
  #:use-module (gnu packages bittorrent)
  #:use-module (gnu packages build-tools)
  #:use-module (gnu packages chromium)
  #:use-module (gnu packages cmake)
  #:use-module (gnu packages commencement)
  #:use-module (gnu packages compression)
  #:use-module (gnu packages compton)
  #:use-module (gnu packages cran)
  #:use-module (gnu packages curl)
  #:use-module (gnu packages disk)
  #:use-module (gnu packages dns)
  #:use-module (gnu packages ebook)
  #:use-module (gnu packages emacs)
  #:use-module (gnu packages emacs-xyz)
  #:use-module (gnu packages emulators)
  #:use-module (gnu packages enlightenment)
  #:use-module (gnu packages fcitx5)
  #:use-module (gnu packages file-systems)
  #:use-module (gnu packages firmware)
  #:use-module (gnu packages fonts)
  #:use-module (gnu packages freedesktop)
  #:use-module (gnu packages games)
  #:use-module (gnu packages gawk)
  #:use-module (gnu packages gcc)
  #:use-module (gnu packages gimp)
  #:use-module (gnu packages gl)
  #:use-module (gnu packages glib)
  #:use-module (gnu packages gnome)
  #:use-module (gnu packages gnupg)
  #:use-module (gnu packages golang)
  #:use-module (gnu packages golang-apps)
  #:use-module (gnu packages gstreamer)
  #:use-module (gnu packages gtk)
  #:use-module (gnu packages guile-xyz)
  #:use-module (gnu packages hardware)
  #:use-module (gnu packages haskell)
  #:use-module (gnu packages haskell-apps)
  #:use-module (gnu packages haskell-check)
  #:use-module (gnu packages haskell-xyz)
  #:use-module (gnu packages ibus)
  #:use-module (gnu packages image)
  #:use-module (gnu packages image-processing)
  #:use-module (gnu packages image-viewers)
  #:use-module (gnu packages imagemagick)
  #:use-module (gnu packages java)
  #:use-module (gnu packages kde-graphics)
  #:use-module (gnu packages kde-pim)
  #:use-module (gnu packages libreoffice)
  #:use-module (gnu packages librewolf)
  #:use-module (gnu packages linux)
  #:use-module (gnu packages lisp)
  #:use-module (gnu packages lisp-xyz)
  #:use-module (gnu packages llvm)
  #:use-module (gnu packages luanti)
  #:use-module (gnu packages lxde)
  #:use-module (gnu packages lxqt)
  #:use-module (gnu packages mail)
  #:use-module (gnu packages maths)
  #:use-module (gnu packages mpd)
  #:use-module (gnu packages music)
  #:use-module (gnu packages networking)
  #:use-module (gnu packages ninja)
  #:use-module (gnu packages node)
  #:use-module (gnu packages node-xyz)
  #:use-module (gnu packages nss)
  #:use-module (gnu packages package-management)
  #:use-module (gnu packages password-utils)
  #:use-module (gnu packages pdf)
  #:use-module (gnu packages photo)
  #:use-module (gnu packages pkg-config)
  #:use-module (gnu packages pulseaudio)
  #:use-module (gnu packages python)
  #:use-module (gnu packages python-build)
  #:use-module (gnu packages python-check)
  #:use-module (gnu packages python-xyz)
  #:use-module (gnu packages qt)
  #:use-module (gnu packages ruby)
  #:use-module (gnu packages ruby-check)
  #:use-module (gnu packages ruby-xyz)
  #:use-module (gnu packages rust)
  #:use-module (gnu packages rust-apps)
  #:use-module (gnu packages shells)
  #:use-module (gnu packages shellutils)
  #:use-module (gnu packages sqlite)
  #:use-module (gnu packages ssh)
  #:use-module (gnu packages statistics)
  #:use-module (gnu packages suckless)
  #:use-module (gnu packages telegram)
  #:use-module (gnu packages terminals)
  #:use-module (gnu packages text-editors)
  #:use-module (gnu packages textutils)
  #:use-module (gnu packages tls)
  #:use-module (gnu packages tor)
  #:use-module (gnu packages tor-browsers)
  #:use-module (gnu packages unicode)
  #:use-module (gnu packages version-control)
  #:use-module (gnu packages video)
  #:use-module (gnu packages vim)
  #:use-module (gnu packages virtualization)
  #:use-module (gnu packages vpn)
  #:use-module (gnu packages vulkan)
  #:use-module (gnu packages w3m)
  #:use-module (gnu packages web)
  #:use-module (gnu packages web-browsers)
  #:use-module (gnu packages wine)
  #:use-module (gnu packages wm)
  #:use-module (gnu packages xdisorg)
  #:use-module (gnu packages xfce)
  #:use-module (gnu packages xml)
  #:use-module (gnu packages xorg)
  #:use-module (gnu packages)
  #:use-module (gnu packages antivirus)
  #:use-module (gnu packages acct)
  #:use-module (gnu packages apparmor)
  #:use-module (gnu packages monitoring)
  #:use-module (gnu packages security-token)
  #:use-module (gnu packages crypto)
  #:use-module (gnu packages engineering)
  #:use-module (gnu packages ftp)
  #:use-module (gnu packages samba)
  #:use-module (gnu packages cups)
  #:use-module (gnu packages gnuzilla)
  #:use-module (gnu packages ncdu)
  #:use-module (gnu packages containers)
  #:use-module (gnu packages docker)
  #:use-module (gnu services dbus)
  #:use-module (guix gexp)
  #:use-module (guix packages)
  #:use-module (nongnu packages chrome)
  #:use-module (nongnu packages game-client)
  #:use-module (nongnu packages wine)
  #:use-module (securityops packages apps)                      ; torando-gui
  #:use-module (securityos packages vaptvupt)                   ; vaptvupt CLI + GUI
  #:use-module (gnu home)
  #:use-module (gnu home services)
  #:use-module (gnu home services shells)
  #:use-module (gnu services)
  #:use-module (guix gexp)
  #:export (%home-environment))

(define %wallpaper "/etc/securityos/wallpaper.png")

(define %home-packages
  (list
   torando-gui                              ; Torando Tor-control GUI (securityops)
   vaptvupt  vaptvupt-gui                   ; VaptVupt post-quantum backup (CLI + GUI)
   ;; r6: dropped steam, docker, cmake, cabal-install/cabal-doctest, bundler,
   ;; certbot, edk2-tools and emacs-telega (pulls the huge tdlib) for a leaner,
   ;; faster live image.
   acct    alacritty    alsa-lib    alsa-utils    ansible    arp-scan
   atool    audit    awww    bat    bcachefs-tools    binutils
   blueman    bluez    bluez-alsa    borg    brightnessctl    btop
   btrfs-progs    chafa    cl-clx    cl-css    clamav    cmatrix
   cmus    compton    cool-retro-term    coreutils    desktop-file-utils    dnstracer
   dosfstools    e2fsprogs    emacs    emacs-emojify    emacs-magit    emacs-nerd-icons
   emacs-org    emacs-org-static-blog    emacs-vterm    enca
   exfat-utils    exfatprogs    fastfetch    fcitx5    fcitx5-qt    feh    ffmpeg
   ffmpegthumbnailer    findutils    firejail    fish    flameshot    flatpak
   ;; Fonts come from the SYSTEM profile (%font-packages in config.scm: dejavu,
   ;; liberation, noto, jetbrains-mono, terminus, awesome, iosevka-term, …).
   ;; Shipping ~90 more here only slowed the first-app launch (fontconfig scans
   ;; them all) and bloated the image, so they were dropped for r6.
   flatpak-xdg-utils    fnott    fping    fuse    fuse-exfat
   ;; r6: dev toolchains (gcc/ghc/go/rust/node/openjdk/ruby), heavy GUI apps
   ;; (libreoffice/gimp/krita/obs/qemu/virt-manager/telegram/steam), the Qt
   ;; stack (pulled in automatically as deps), media libs, and SYSTEM-profile
   ;; duplicates (nmap/tcpdump/wireshark/openssh/tor/… already in config.scm)
   ;; were removed to shrink the closure and speed first-login activation.
   fzf    gawk    git    git-lfs    glances    glib
   gnome-disk-utility    gnupg    grep    gtk    icecat    imagemagick
   inxi    jq    keepassxc    kitty    kleopatra    ldns
   lf    libass    libfido2    librsvg    libva    libva-utils
   libxml2    lxappearance    lynis    mergerfs    mpd    mpv
   ;; r7 sway-only: dropped X11 packages (xmonad, xmobar, picom, st, xterm,
   ;; xrandr, xmodmap, xset, setxkbmap, xprop, xwininfo, compton) — the sway
   ;; desktop + its tools live in the SYSTEM profile now (config.scm), so the
   ;; home profile stays small and activation is fast.
   ncdu    neovim    noisetorch    p7zip    pandoc    pavucontrol
   pavucontrol-qt    perl-image-exiftool    pfetch    pinentry    pinentry-gtk2
   pkg-config    poppler    procps    pulseaudio    pulsemixer    pwgen
   python    python-emoji    python-pip    python-virtualenv    qbittorrent    qimgv
   qpdfview    ranger    sed    sqlite    starship    strace
   sysstat    uchardet    udevil    ueberzugpp    unicode-emoji
   v4l-utils    vlc    w3m    whois
   wireguard-tools    wlrctl    xdg-desktop-portal
   xkeyboard-config    xlsx2csv    zip    zoxide

   ))

(define %sway-config
  (mixed-text-file "sway-config"
    (string-append
     "set $mod Mod4\nset $term wezterm\nset $menu wofi --show drun\n"
     "output * bg " %wallpaper " fill\n"
     "default_border pixel 2\ndefault_floating_border pixel 2\nhide_edge_borders smart\n"
     ;; Real input handling (adopted from the maintainer's working config).
     "input type:keyboard { xkb_layout \"br\" xkb_variant \"abnt2\" }\n"
     "input type:touchpad {\n"
     "    tap enabled\n    drag enabled\n    natural_scroll enabled\n"
     "    scroll_method two_finger\n    click_method button_areas\n"
     "    dwt enabled\n    middle_emulation enabled\n    accel_profile adaptive\n}\n"
     "input type:pointer { accel_profile flat }\n"
     "exec mako\nexec nm-applet --indicator\nexec $term\n"
     "bar { swaybar_command waybar }\n"
     ;; launchers / browser
     "bindsym $mod+Return exec $term\nbindsym $mod+d exec $menu\n"
     "bindsym $mod+e exec librewolf 2>/dev/null || chromium\n"
     ;; one-key launch of the guided disk installer (Super+Shift+I); on a
     ;; non-zero exit keep the window open so the error is readable.
     "bindsym $mod+Shift+i exec $term start -- sh -c 'security-ops-install || { echo; echo \"installer exited $? — press Enter to close\"; read _; }'\n"
     ;; window management (sway-native keys)
     "bindsym $mod+q kill\nbindsym $mod+Shift+c reload\n"
     "bindsym $mod+Shift+e exec swaynag -t warning -m 'Exit sway?' -B 'Yes' 'swaymsg exit'\n"
     "bindsym $mod+f fullscreen\nbindsym $mod+Shift+space floating toggle\n"
     "bindsym $mod+Left focus left\nbindsym $mod+Right focus right\n"
     "bindsym $mod+Up focus up\nbindsym $mod+Down focus down\n"
     "bindsym $mod+Shift+Left move left\nbindsym $mod+Shift+Right move right\n"
     "bindsym $mod+Shift+Up move up\nbindsym $mod+Shift+Down move down\n"
     "bindsym $mod+b splith\nbindsym $mod+v splitv\nbindsym $mod+s layout stacking\n"
     "bindsym $mod+w layout tabbed\nbindsym $mod+t layout toggle split\n"
     ;; workspaces 1-9
     "bindsym $mod+1 workspace number 1\nbindsym $mod+2 workspace number 2\nbindsym $mod+3 workspace number 3\n"
     "bindsym $mod+4 workspace number 4\nbindsym $mod+5 workspace number 5\nbindsym $mod+6 workspace number 6\n"
     "bindsym $mod+7 workspace number 7\nbindsym $mod+8 workspace number 8\nbindsym $mod+9 workspace number 9\n"
     "bindsym $mod+Shift+1 move container to workspace number 1\nbindsym $mod+Shift+2 move container to workspace number 2\n"
     "bindsym $mod+Shift+3 move container to workspace number 3\nbindsym $mod+Shift+4 move container to workspace number 4\n"
     "bindsym $mod+Shift+5 move container to workspace number 5\nbindsym $mod+Shift+6 move container to workspace number 6\n"
     "bindsym $mod+Shift+7 move container to workspace number 7\nbindsym $mod+Shift+8 move container to workspace number 8\n"
     "bindsym $mod+Shift+9 move container to workspace number 9\n"
     ;; brightness / volume (pulseaudio = pactl; the ISO has no pipewire) / shots
     "bindsym XF86MonBrightnessUp exec brightnessctl set +5%\nbindsym XF86MonBrightnessDown exec brightnessctl set 5%-\n"
     "bindsym XF86AudioRaiseVolume exec pactl set-sink-volume @DEFAULT_SINK@ +5%\n"
     "bindsym XF86AudioLowerVolume exec pactl set-sink-volume @DEFAULT_SINK@ -5%\n"
     "bindsym XF86AudioMute exec pactl set-sink-mute @DEFAULT_SINK@ toggle\n"
     "bindsym Print exec grim - | wl-copy\nbindsym $mod+Print exec grim -g \"$(slurp)\" - | wl-copy\n"
     "bindsym $mod+z exec flameshot gui\n"
     "include /etc/sway/config.d/*\n")))

(define %waybar-config
  (plain-file "waybar-config"
"{ \"layer\":\"top\",\"position\":\"top\",\"height\":28,
  \"modules-left\":[\"sway/workspaces\"],\"modules-center\":[\"clock\"],
  \"modules-right\":[\"cpu\",\"memory\",\"network\",\"battery\",\"tray\"],
  \"clock\":{\"format\":\"{:%a %d %b  %H:%M}\"},\"cpu\":{\"format\":\"CPU {usage}%\"},
  \"memory\":{\"format\":\"MEM {}%\"},\"battery\":{\"format\":\"BAT {capacity}%\"},\"tray\":{\"spacing\":8} }\n"))


(define %home-environment
  (home-environment
   (packages %home-packages)
   (services
    (list
     (service home-fish-service-type
              (home-fish-configuration
               (config (list (plain-file "conf.fish"
"set -g fish_greeting ''
command -q starship; and starship init fish | source
command -q zoxide;   and zoxide init fish | source
command -q fastfetch; and fastfetch\n")))
               ;; The self-contained subset of the maintainer's own aliases
               ;; (nothing pointing at private scripts, hosts, keys or paths).
               (aliases
                `(("lf"     . "$HOME/.local/bin/lf/lfrun")
                  ("tsocks" . "torsocks")
                  ("c"      . "clear")
                  ("e"      . "cd ..")
                  ("f"      . "fastfetch")
                  ("p"      . "pfetch")
                  ("q"      . "exit")
                  ("ll"     . "ls -l")
                  ("ls"     . "ls -p --color=auto")
                  ("grep"   . "grep --color=auto")
                  ("l"      . "du -h --max-depth=1 .")
                  ("del"    . "shred -uvz")
                  ("s"      . "sensors")
                  ("ee"     . "exiftool -recursive -all=")
                  ("7"      . "7z x")
                  ("7a"     . "7z a")
                  ("gu"     . "guix package -u")
                  ("repair" . "sudo guix gc --verify=repair,contents")
                  ("mpv"    . "mpv --audio-pitch-correction=yes")
                  ("enc"    . "tar -czf - * | openssl enc -e -aes-256-cbc -pbkdf2 -iter 200000 -out secured.tar.gz")
                  ("dec"    . "openssl enc -d -aes-256-cbc -pbkdf2 -iter 200000 -in secured.tar.gz | tar xz")
                  ("isolate" . "guix shell --container --network --no-cwd")))))
     (simple-service 'securityos-xdg-dotfiles
                     home-xdg-configuration-files-service-type
                     ;; r7 sway-only: dropped xmonad/xmobar/picom dotfiles.
                     (list (list "sway/config"        %sway-config)
                           (list "waybar/config"      %waybar-config)
                           (list "alacritty/alacritty.toml" (local-file "dotfiles/alacritty/alacritty.toml"))
                           (list "kitty/kitty.conf"   (local-file "dotfiles/kitty/kitty.conf"))
                           (list "rofi/config.rasi"   (local-file "dotfiles/rofi/config.rasi"))
                           (list "starship.toml"      (local-file "dotfiles/starship/starship.toml"))
                           (list "wezterm/wezterm.lua" (local-file "dotfiles/wezterm/wezterm.lua"))
                           ;; lf: terminal file manager with inline image preview
                           (list "lf/lfrc"            (local-file "dotfiles/lf/lfrc"))
                           (list "lf/colors"          (local-file "dotfiles/lf/colors"))))
     ;; lf's ueberzugpp preview + cleaner scripts → ~/.local/bin/lf/ (keep +x).
     ;; This is what makes `lf' show real images directly in the terminal.
     (simple-service 'securityos-lf-scripts home-files-service-type
                     (list (list ".local/bin/lf/lfrun"
                                 (local-file "dotfiles/lf/lfrun" #:recursive? #t))
                           (list ".local/bin/lf/preview"
                                 (local-file "dotfiles/lf/preview" #:recursive? #t))
                           (list ".local/bin/lf/cleaner"
                                 (local-file "dotfiles/lf/cleaner" #:recursive? #t))))))))
