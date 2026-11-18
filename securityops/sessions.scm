;; -*- mode: scheme; -*-
;; CodeMark v1 project=4c63e0fe-589c-4944-8449-97e211a38b72 file=9451e533ad745403b93f32a3c01c8b9a owner="Cristian Cezar Mois\u00e9s"
;;; ===========================================================================
;;; (securityops sessions) — selectable Sway, XMonad/XLibre, and KDE sessions
;;; ===========================================================================
;;;
;;; greetd + tuigreet remains the small, framebuffer-safe authentication
;;; boundary.  Sway is the explicit default; F3 selects one of three immutable
;;; session launchers.  The X11 choice is deliberately named XMonad + XLibre:
;;; it starts the XLibre server produced by the pinned securityops channel and
;;; never aliases the ordinary Xorg server as XLibre.
;;;
;;; Core launch commands use store paths.  User profile PATH remains available
;;; to applications after login, but cannot change which compositor/server the
;;; greeter starts.  Session logs stay below the user's mode-0700 XDG state
;;; directory instead of predictable files in /tmp.
;;; ===========================================================================

(define-module (securityops sessions)
  #:use-module (guix gexp)
  #:use-module (gnu packages admin)          ; tuigreet
  #:use-module (gnu packages bash)           ; bash
  #:use-module (gnu packages compton)        ; picom
  #:use-module (gnu packages glib)           ; dbus
  #:use-module (gnu packages image-viewers)  ; feh
  #:use-module (gnu packages kde-plasma)     ; plasma-workspace
  #:use-module (gnu packages terminals)      ; wezterm
  #:use-module (gnu packages wm)             ; sway, xmonad, picom
  #:use-module (gnu packages xorg)            ; xinit, xset, setxkbmap
  #:use-module (gnu services xorg)            ; xorg-wrapper
  #:use-module (gnu system keyboard)          ; keyboard-layout
  #:use-module (xlibre)                       ; real XLibre server + DDX modules
  #:use-module (securityops settings)
  #:export (%greeter-command %build-version))

(define %wallpaper-path "/etc/securityops/wallpaper.png")

;; Bump values in settings.json for release identity; all launchers expose the
;; same build string in the greeter, /etc/securityops/build-id, GRUB, and MOTD.
(define %build-version
  (string-append %build-revision " · v" %release-version " · "
                 %desktop-label " · kernel " %kernel-version))

(define %env-prelude
  (string-append
   "if [ -f \"$HOME/.guix-home/profile/etc/profile\" ]; then "
   ". \"$HOME/.guix-home/profile/etc/profile\"; fi; "
   "export PATH=\"$HOME/.guix-home/profile/bin:/run/current-system/profile/bin:$PATH\"; "
   "export XDG_RUNTIME_DIR=\"${XDG_RUNTIME_DIR:-/run/user/$(/run/current-system/profile/bin/id -u)}\"; "
   "export XDG_STATE_HOME=\"${XDG_STATE_HOME:-$HOME/.local/state}\"; "
   "export XDG_CACHE_HOME=\"${XDG_CACHE_HOME:-$HOME/.cache}\"; "
   "export XDG_DATA_HOME=\"${XDG_DATA_HOME:-$HOME/.local/share}\"; "
   "/run/current-system/profile/bin/install -d -m 700 \"$XDG_RUNTIME_DIR\" \"$XDG_STATE_HOME\" "
   "\"$XDG_STATE_HOME/securityops\" \"$XDG_STATE_HOME/securityops/sessions\"; "))

;;; ---------------------------------------------------------------------------
;;; Sway (Wayland, default)
;;; ---------------------------------------------------------------------------
(define %sway-config-fallback
  (mixed-text-file "sway-config-fallback" "\
set $mod Mod4
set $term wezterm
output * bg " %wallpaper-path " fill
input type:keyboard { xkb_layout \"br\" xkb_variant \"abnt2\" }
input type:touchpad { tap enabled drag enabled natural_scroll enabled scroll_method two_finger click_method button_areas dwt enabled middle_emulation enabled accel_profile adaptive }
input type:pointer { accel_profile flat }
exec mako
exec nm-applet --indicator
exec $term
bar { swaybar_command waybar }
bindsym $mod+Return exec $term
bindsym $mod+d exec wofi --show drun
bindsym $mod+q kill
bindsym $mod+Shift+c reload
bindsym $mod+Shift+e exec swaynag -t warning -m 'Exit sway?' -B 'Yes' 'swaymsg exit'
bindsym $mod+Shift+i exec $term start -- security-ops-install
include /etc/sway/config.d/*
"))

(define %sway-launch
  (program-file "securityops-sway-session"
    #~(execl #$(file-append bash "/bin/bash") "bash" "-c"
             (string-append
              #$%env-prelude
              "export XDG_SESSION_TYPE=wayland XDG_CURRENT_DESKTOP=sway DESKTOP_SESSION=sway; "
              "export WLR_NO_HARDWARE_CURSORS=1 WLR_RENDERER_ALLOW_SOFTWARE=1; "
              "export MOZ_ENABLE_WAYLAND=1 _JAVA_AWT_WM_NONREPARENTING=1; "
              "export QT_QPA_PLATFORM='wayland;xcb' GDK_BACKEND='wayland,x11' SDL_VIDEODRIVER=wayland; "
              "CFG=\"$HOME/.config/sway/config\"; [ -f \"$CFG\" ] || CFG="
              #$%sway-config-fallback "; "
              "LOG=\"$XDG_STATE_HOME/securityops/sessions/sway.log\"; "
              "run_sway() { " #$(file-append dbus "/bin/dbus-run-session")
              " " #$(file-append sway "/bin/sway") " -c \"$CFG\"; }; "
              "if [ -e /dev/dri/renderD128 ]; then "
              "run_sway >\"$LOG\" 2>&1 || { "
              "echo '[securityops] hardware renderer failed; retrying with pixman' >>\"$LOG\"; "
              "WLR_RENDERER=pixman run_sway >>\"$LOG\" 2>&1; }; "
              "else WLR_RENDERER=pixman run_sway >\"$LOG\" 2>&1; fi"))))

;;; ---------------------------------------------------------------------------
;;; XMonad on the real XLibre server (X11)
;;; ---------------------------------------------------------------------------
;; Intel uses XLibre's in-tree modesetting DDX; the legacy xlibre-video-intel
;; SNA driver is intentionally absent.  KMS/modesetting covers modern Intel,
;; AMD, Nouveau, and virtio, while the bounded fallbacks cover firmware/VM paths.
(define %securityops-xlibre-modules
  (list xlibre-video-amdgpu
        xlibre-video-ati
        xlibre-video-cirrus
        xlibre-video-fbdev
        xlibre-video-nouveau
        xlibre-video-vesa
        xlibre-input-libinput
        xlibre-input-evdev
        xlibre-input-mouse))

(define %xlibre-wrapper
  (xorg-wrapper
   (xlibre-configuration
    (modules %securityops-xlibre-modules)
    (keyboard-layout (keyboard-layout "br" "abnt2")))))

;; An empty immutable config directory forces XMonad's compiled default config;
;; a missing compiler can therefore never turn first login into a blank session.
(define %xmonad-config-dir
  (computed-file "securityops-xmonad-default-config"
    #~(mkdir #$output)))

(define %xmonad-client
  (program-file "securityops-xmonad-client"
    #~(execl #$(file-append bash "/bin/bash") "bash" "-c"
             (string-append
              #$%env-prelude
              "export XDG_SESSION_TYPE=x11 XDG_CURRENT_DESKTOP=xmonad DESKTOP_SESSION=xmonad; "
              "export XMONAD_CONFIG_DIR=" #$%xmonad-config-dir "; "
              "export XMONAD_CACHE_DIR=\"$XDG_CACHE_HOME/xmonad\"; "
              "export XMONAD_DATA_DIR=\"$XDG_DATA_HOME/xmonad\"; "
              "/run/current-system/profile/bin/install -d -m 700 \"$XMONAD_CACHE_DIR\" \"$XMONAD_DATA_DIR\"; "
              #$(file-append xset "/bin/xset") " s off -dpms 2>/dev/null || true; "
              #$(file-append setxkbmap "/bin/setxkbmap") " br abnt2 2>/dev/null || true; "
              #$(file-append feh "/bin/feh") " --no-fehbg --bg-fill "
              #$%wallpaper-path " >/dev/null 2>&1 || true; "
              #$(file-append picom "/bin/picom") " --daemon 2>/dev/null || true; "
              #$(file-append wezterm "/bin/wezterm") " start >/dev/null 2>&1 & "
              "exec " #$(file-append xmonad "/bin/xmonad")))))

(define %xmonad-launch
  (program-file "securityops-xmonad-xlibre-session"
    #~(execl #$(file-append bash "/bin/bash") "bash" "-c"
             (string-append
              #$%env-prelude
              "LOG=\"$XDG_STATE_HOME/securityops/sessions/xmonad-xlibre.log\"; "
              "exec " #$(file-append dbus "/bin/dbus-run-session") " -- "
              #$(file-append xinit "/bin/xinit") " " #$%xmonad-client
              " -- " #$%xlibre-wrapper
              " :0 vt7 -keeptty -nolisten tcp >\"$LOG\" 2>&1"))))

;;; ---------------------------------------------------------------------------
;;; KDE Plasma (Wayland)
;;; ---------------------------------------------------------------------------
(define %kde-launch
  (program-file "securityops-kde-wayland-session"
    #~(execl #$(file-append bash "/bin/bash") "bash" "-c"
             (string-append
              #$%env-prelude
              "export XDG_SESSION_TYPE=wayland XDG_CURRENT_DESKTOP=KDE DESKTOP_SESSION=plasmawayland; "
              "export QT_QPA_PLATFORM='wayland;xcb' MOZ_ENABLE_WAYLAND=1; "
              "LOG=\"$XDG_STATE_HOME/securityops/sessions/kde-wayland.log\"; "
              "exec " #$(file-append dbus "/bin/dbus-run-session") " -- "
              #$(file-append plasma-workspace "/bin/startplasma-wayland")
              " >\"$LOG\" 2>&1"))))

;;; ---------------------------------------------------------------------------
;;; Immutable session menu consumed by tuigreet
;;; ---------------------------------------------------------------------------
(define %sessions-dir
  (computed-file "securityops-desktop-sessions"
    #~(begin
        (mkdir #$output)
        (call-with-output-file (string-append #$output "/10-sway.desktop")
          (lambda (port)
            (format port "[Desktop Entry]~%Name=Security Ops Sway (Wayland, default)~%Comment=Hardened tiling Wayland session~%Exec=~a~%Type=Application~%"
                    #$%sway-launch)))
        (call-with-output-file (string-append #$output "/20-xmonad-xlibre.desktop")
          (lambda (port)
            (format port "[Desktop Entry]~%Name=Security Ops XMonad + XLibre (X11)~%Comment=XMonad running on the pinned XLibre server~%Exec=~a~%Type=Application~%"
                    #$%xmonad-launch)))
        (call-with-output-file (string-append #$output "/30-kde-wayland.desktop")
          (lambda (port)
            (format port "[Desktop Entry]~%Name=Security Ops KDE Plasma (Wayland)~%Comment=Full KDE Plasma Wayland desktop~%Exec=~a~%Type=Application~%"
                    #$%kde-launch))))))

(define %greeter-command
  (program-file "securityops-greeter"
    #~(execl #$(file-append tuigreet "/bin/tuigreet") "tuigreet"
             "--time"
             "--remember"                    ; username only, never the password
             "--sessions" #$%sessions-dir
             "--cmd" #$%sway-launch          ; safe explicit default
             "--greeting"
             (string-append
              "Security Ops · build " #$%build-version
              " — F3: Sway / XMonad+XLibre / KDE. Default: Sway. "
              "Live user: securityops. One-boot password is shown only on "
              "trusted VT1 (Ctrl+Alt+F1); return with Ctrl+Alt+F7."))))
