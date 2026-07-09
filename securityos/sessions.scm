;; -*- mode: scheme; -*-
;;; ===========================================================================
;;; (securityos sessions) — login + the sway desktop session
;;; ===========================================================================
;;;
;;; Security Ops is now SWAY-ONLY (Wayland).  The entire X11 stack (XLibre +
;;; xmonad + xinit) was removed: it added a large build (xlibre-server from
;;; source, the precompiled xmonad binary), pulled in the whole xorg modules
;;; tree, and was the source of the "only wallpaper / GLX no stencil" pain on
;;; real hardware.  sway needs no DDX/ModulePath — it talks KMS/DRM directly and
;;; falls back to the pixman software renderer when there is no GPU render node.
;;;
;;; Login: greetd + tuigreet (a tiny GL-free TUI) with a SINGLE session (sway),
;;; so there is nothing to choose — log in and you are in sway.
;;;
;;; FAST FIRST LAUNCH: sway and ALL the apps it autostarts (wezterm, waybar, mako,
;;; wofi, swaybg, nm-applet) live in the SYSTEM profile (see config.scm), so they
;;; are on PATH the instant greetd hands off — the session does NOT block waiting
;;; for the per-user Guix-Home activation.  The fontconfig cache is pre-warmed at
;;; boot (a system shepherd one-shot, see config.scm) so the first text render
;;; does not stall for minutes rebuilding it.
;;; ===========================================================================

(define-module (securityos sessions)
  #:use-module (guix gexp)
  #:use-module (gnu packages admin)        ; tuigreet
  #:use-module (gnu packages bash)         ; bash
  #:use-module (gnu packages glib)         ; dbus
  #:use-module (gnu packages wm)           ; sway
  #:export (%greeter-command %build-version))

(define %wallpaper-path "/etc/securityos/wallpaper.png")

;; Bump this on every build so the running image is identifiable at a glance
;; (shown in the GRUB menu, the login greeting, /etc/securityos/build-id and the
;; MOTD).  This is how we tell "is the laptop actually booting the NEW image?".
(define %build-version "r10 · 2026-07-09 · wezterm · fast · kernel 7.1.3")

;; Minimal env prelude.  The desktop's core apps are in the SYSTEM profile, so we
;; no longer block on Guix-Home activation; we just put the home profile on PATH
;; if it is already there (a quick check, no long wait), source it when present,
;; and guarantee XDG_RUNTIME_DIR.
(define %env-prelude
  (string-append
   "if [ -f \"$HOME/.guix-home/profile/etc/profile\" ]; then "
   ". \"$HOME/.guix-home/profile/etc/profile\"; fi; "
   "export PATH=\"$HOME/.guix-home/profile/bin:/run/current-system/profile/bin:$PATH\"; "
   "export XDG_RUNTIME_DIR=\"${XDG_RUNTIME_DIR:-/run/user/$(id -u)}\"; "))

;;; ---------------------------------------------------------------------------
;;; sway (Wayland)
;;; ---------------------------------------------------------------------------
;; Fallback config used only if the user's ~/.config/sway/config (shipped by
;; Guix Home) is not present yet.  Kept in sync with home.scm's %sway-config.
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
  (program-file "securityos-sway-session"
    #~(execl #$(file-append bash "/bin/bash") "bash" "-c"
             (string-append
              #$%env-prelude
              "export XDG_SESSION_TYPE=wayland XDG_CURRENT_DESKTOP=sway DESKTOP_SESSION=sway; "
              ;; Wayland app backends.
              "export WLR_NO_HARDWARE_CURSORS=1 WLR_RENDERER_ALLOW_SOFTWARE=1; "
              "export MOZ_ENABLE_WAYLAND=1 _JAVA_AWT_WM_NONREPARENTING=1; "
              "export QT_QPA_PLATFORM='wayland;xcb' GDK_BACKEND='wayland,x11' SDL_VIDEODRIVER=wayland; "
              ;; elogind normally creates this, but make sure the compositor has a
              ;; valid runtime dir or wlroots aborts before it ever logs anything.
              "mkdir -p \"$XDG_RUNTIME_DIR\" 2>/dev/null; "
              "chmod 700 \"$XDG_RUNTIME_DIR\" 2>/dev/null; "
              "CFG=\"$HOME/.config/sway/config\"; [ -f \"$CFG\" ] || CFG=" #$%sway-config-fallback "; "
              "run_sway() { " #$(file-append dbus "/bin/dbus-run-session")
              " " #$(file-append sway "/bin/sway") " -c \"$CFG\"; }; "
              ;; Try the hardware GLES2 renderer first; if wlroots fails to bring
              ;; it up (broken/odd GPU), retry with the pixman SOFTWARE renderer so
              ;; sway still comes up.  No GPU render node at all -> straight to
              ;; pixman.  /tmp/sway.log always says what happened.
              "if [ -e /dev/dri/renderD128 ]; then "
              "run_sway >/tmp/sway.log 2>&1 || { "
              "echo '[securityos] hardware renderer failed; retrying with pixman' >>/tmp/sway.log; "
              "WLR_RENDERER=pixman run_sway >>/tmp/sway.log 2>&1; }; "
              "else WLR_RENDERER=pixman run_sway >/tmp/sway.log 2>&1; fi"))))

;;; ---------------------------------------------------------------------------
;;; Session (tuigreet) + greeter — single sway session
;;; ---------------------------------------------------------------------------
(define %sessions-dir
  (computed-file "securityos-sessions"
    #~(begin
        (mkdir #$output)
        (call-with-output-file (string-append #$output "/sway.desktop")
          (lambda (port)
            (display (string-append
                      "[Desktop Entry]\nName=Security Ops (sway)\n"
                      "Comment=Tiling Wayland compositor\nExec=" #$%sway-launch
                      "\nType=Application\n") port))))))

(define %greeter-command
  (program-file "securityos-greeter"
    #~(execl #$(file-append tuigreet "/bin/tuigreet") "tuigreet"
             "--time"
             "--remember"
             ;; single session → launch it directly, no chooser needed
             "--cmd" #$%sway-launch
             "--greeting"
             (string-append
              "Security Ops · build " #$%build-version
              "   —   log in to start sway."
              "   user: securityops   pass: securityops"))))
