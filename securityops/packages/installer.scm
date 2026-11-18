;; CodeMark v1 project=4c63e0fe-589c-4944-8449-97e211a38b72 file=ae54bee41b175e8eb63dbbf70addb3e0 owner="Cristian Cezar Mois\u00e9s"
;;; installer.scm — package the Security Ops OS guided installer.
;;;
;;; Ships the installer, its config generator, and its private-state helper into
;;; bin/ so they land on PATH of the live system.  The launcher accepts only the
;;; active profile's immutable store target and requires every helper to be a
;;; root-owned, non-writable sibling in that same package output.
;;;
;;; Runtime tools (whiptail/newt, parted, cryptsetup, mkfs.*, openssl, guile,
;;; guix, herd) are provided by the LIVE SYSTEM profile, not propagated here —
;;; the installer sets PATH to /run/current-system/profile.
;;;
;;; © Cristian Cezar Moisés · sac@securityops.co · AGPL-3.0-or-later
(define-module (securityops packages installer)
  #:use-module (guix packages)
  #:use-module (guix gexp)
  #:use-module (guix build-system trivial)
  #:use-module ((guix licenses) #:prefix license:)
  #:export (security-ops-installer))

(define security-ops-installer
  (package
    (name "security-ops-installer")
    (version "1.0.0")
    (source #f)
    (build-system trivial-build-system)
    (arguments
     (list
      #:modules '((guix build utils))
      #:builder
      #~(begin
          (use-modules (guix build utils))
          (let ((bin (string-append #$output "/bin")))
            (mkdir-p bin)
            (for-each
             (lambda (name src)
               (let ((dst (string-append bin "/" name)))
                 (copy-file src dst)
                 (chmod dst #o755)))
             (list "security-ops-install" "gen-config.sh" "private-state.sh"
                   "cow-system-init.scm")
             (list #$(local-file "../installer/security-ops-install")
                   #$(local-file "../installer/gen-config.sh")
                   #$(local-file "../installer/private-state.sh")
                   #$(local-file "../installer/cow-system-init.scm")))))))
    (synopsis "Security Ops OS guided (whiptail) disk installer")
    (description
     "A branded, black-on-cyan @command{whiptail} guided installer that turns
the Security Ops OS live image into an installed system.  It collects the
target disk, filesystem (ext4/btrfs/xfs), optional LUKS2 encryption,
locale, timezone, keyboard, user accounts and desktop (Sway,
XMonad on the pinned XLibre server, or KDE Plasma),
generates a self-contained declarative @file{/etc/config.scm}, partitions the
disk and runs @command{guix system init} through the release's pinned channel
time-machine.  ZFS root is intentionally not offered until kernel and boot
support are complete.")
    (home-page "https://git.securityops.com.br/cristiancmoises/securityops-os")
    ;; cow-system-init.scm is a GPL-compatible adaptation of GNU Guix's
    ;; installer lifecycle; the original Security Ops scripts remain AGPL-3+.
    (license (list license:agpl3+ license:gpl3+))))

security-ops-installer
