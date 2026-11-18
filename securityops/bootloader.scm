;; CodeMark v1 project=4c63e0fe-589c-4944-8449-97e211a38b72 file=fa0587badc085f9282ec2dc7439a05d0 owner="Cristian Cezar Mois\u00e9s"
;;; Security Ops OS -- branded GNU GRUB UEFI installer
;;;
;;; Copyright © 2013-2026 GNU Guix contributors
;;; Copyright © 2026 Cristian Cezar Moisés
;;; SPDX-License-Identifier: GPL-3.0-or-later
;;;
;;; The UEFI installer is a narrow adaptation of GNU Guix's
;;; (gnu bootloader grub) `make-grub-efi-installer'.  The only intentional
;;; behavioral difference is the SecurityOps bootloader identifier.  Keeping
;;; this as a distinct inherited bootloader preserves Guix's GRUB generation,
;;; rollback, and configuration-file behavior.

(define-module (securityops bootloader)
  #:use-module (gnu bootloader)
  #:use-module (gnu bootloader grub)
  #:use-module (guix build utils)
  #:use-module (guix gexp)
  #:use-module (srfi srfi-1)
  #:export (securityops-grub-efi-bootloader))

(define %securityops-grub-efi-installer
  #~(lambda (bootloader efi-dir mount-point)
      ;; There is nothing useful to do when called while constructing a disk
      ;; image.  For a real target, EFI-DIR is the mounted system partition.
      (when efi-dir
        (let ((grub-install (string-append bootloader "/sbin/grub-install"))
              (install-dir (string-append mount-point "/boot"))
              (target-esp
               (if (file-exists? (string-append mount-point efi-dir))
                   (string-append mount-point efi-dir)
                   efi-dir)))
          ;; The guided installer permits encrypted root with /boot below it.
          (setenv "GRUB_ENABLE_CRYPTODISK" "y")
          (invoke/quiet grub-install "--bootloader-id=SecurityOps"
                        "--boot-directory" install-dir
                        "--efi-directory" target-esp)))))

(define securityops-grub-efi-bootloader
  (bootloader
   (inherit grub-efi-bootloader)
   (name 'securityops-grub-efi)
   (installer %securityops-grub-efi-installer)))
