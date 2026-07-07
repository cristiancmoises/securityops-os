;;; installer.scm — package the Security Ops OS guided installer.
;;;
;;; Ships the two scripts (security-ops-install + gen-config.sh) into bin/ so
;;; they land on PATH of the live system.  They call each other via
;;; $(dirname "$0")/gen-config.sh, so co-locating them in one bin/ is required.
;;;
;;; Runtime tools (whiptail/newt, parted, cryptsetup, mkfs.*, openssl, guile,
;;; guix, herd) are provided by the LIVE SYSTEM profile, not propagated here —
;;; the installer sets PATH to /run/current-system/profile.
;;;
;;; © Cristian Cezar Moisés · sac@securityops.co · AGPL-3.0-or-later
(define-module (securityos packages installer)
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
             (list "security-ops-install" "gen-config.sh")
             (list #$(local-file "../installer/security-ops-install")
                   #$(local-file "../installer/gen-config.sh")))))))
    (synopsis "Security Ops OS guided (whiptail) disk installer")
    (description
     "A branded, black-on-cyan @command{whiptail} guided installer that turns
the Security Ops OS live image into an installed system.  It collects the
target disk, filesystem (ext4/btrfs/xfs/zfs), optional LUKS2 encryption,
locale, timezone, keyboard, user accounts and desktop (Sway/i3/KDE Plasma),
generates a self-contained declarative @file{/etc/config.scm}, partitions the
disk and runs @command{guix system init}.")
    (home-page "https://git.securityops.co/cristiancmoises/securityops-os")
    (license license:agpl3+)))

security-ops-installer
