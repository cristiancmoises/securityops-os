;; CodeMark v1 project=4c63e0fe-589c-4944-8449-97e211a38b72 file=885e11d53ea156ccba1fd7b6faf3caf2 owner="Cristian Cezar Mois\u00e9s"
;;; SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-SecurityOps-Commercial
(define-module (securityops packages installer2)
  #:use-module (guix packages)
  #:use-module (guix gexp)
  #:use-module (guix utils)
  #:use-module (guix build-system trivial)
  #:use-module (gnu packages bash)
  #:use-module (gnu packages glib)
  #:use-module (gnu packages gtk)
  #:use-module (gnu packages python)
  #:use-module (gnu packages python-xyz)
  #:use-module ((guix licenses) #:prefix license:)
  #:export (security-ops-installer2))

(define %installer2-source
  (or (search-path %load-path "securityops/installer2/security_ops_installer2.py")
      (error "Security Ops Installer 2 source is missing from %load-path")))

(define security-ops-installer2
  (package
    (name "security-ops-installer2")
    (version "0.1.0")
    (source #f)
    (build-system trivial-build-system)
    (inputs (list bash-minimal python python-pygobject gtk
                  gobject-introspection gdk-pixbuf))
    (arguments
     (list
      #:modules '((guix build utils))
      #:builder
      #~(begin
          (use-modules (guix build utils)
                       (ice-9 rdelim))
          (let* ((bin (string-append #$output "/bin"))
                 (apps (string-append #$output "/share/applications"))
                 (program (string-append bin "/security-ops-installer2"))
                 (python-path
                  #$(file-append python-pygobject
                                 (string-append "/lib/python"
                                  (version-major+minor (package-version python))
                                  "/site-packages")))
                 (gtk-typelibs #$(file-append gtk "/lib/girepository-1.0"))
                 (gi-path
                  (cons gtk-typelibs
                        (filter (lambda (directory)
                                  (and (file-exists? directory)
                                       (file-is-directory? directory)))
                         (list #$(file-append gobject-introspection "/lib/girepository-1.0")
                               #$(file-append gdk-pixbuf "/lib/girepository-1.0")
                               #$@(map (lambda (input)
                                         (file-append (cadr input) "/lib/girepository-1.0"))
                                       (package-transitive-propagated-inputs gtk)))))))
            (for-each
             (lambda (directory)
               (unless (file-is-directory? directory)
                 (error "Installer 2 runtime directory is missing" directory)))
             (list python-path gtk-typelibs))
            (mkdir-p bin) (mkdir-p apps)
            (copy-file #$(local-file %installer2-source) program)
            (substitute
             program
             (list
              (cons
               (make-regexp "^#!/usr/bin/env python3")
               (lambda (line matches)
                 (string-append "#!" #$(file-append python "/bin/python3") " -I"
                                (if (string-suffix? "\n" line) "\n" ""))))))
            (call-with-input-file program
              (lambda (port)
                (let loop ((line (read-line port))
                           (fixed-count 0)
                           (mutable-count 0))
                  (if (eof-object? line)
                      (begin
                        (unless (= fixed-count 1)
                          (error "Installer 2 isolated Store Python shebang was not unique"))
                        (unless (= mutable-count 0)
                          (error "Installer 2 retained a mutable Python shebang")))
                      (loop
                       (read-line port)
                       (+ fixed-count
                          (if (string=?
                               line
                               (string-append
                                "#!" #$(file-append python "/bin/python3") " -I"))
                              1 0))
                       (+ mutable-count
                          (if (string=? line "#!/usr/bin/env python3") 1 0)))))))
            (chmod program #o555)
            (wrap-program program
              #:sh #$(file-append bash-minimal "/bin/bash")
              `("GUIX_PYTHONPATH" = (,python-path))
              `("GI_TYPELIB_PATH" = ,gi-path)
              `("XDG_DATA_DIRS" =
                (#$(file-append gtk "/share") #$(file-append glib "/share")))
              '("PYTHONDONTWRITEBYTECODE" = ("1")))
            (chmod program #o555)
            (let ((metadata (lstat program)))
              (unless (and (eq? 'regular (stat:type metadata))
                           (= 1 (stat:nlink metadata))
                           (= #o555 (logand #o7777 (stat:perms metadata))))
                (error "Installer 2 wrapper output metadata is unsafe")))
            (call-with-output-file (string-append apps "/co.securityops.Installer2.desktop")
              (lambda (port)
                (format port "[Desktop Entry]~%Name=Security Ops Installer 2~%Exec=~a~%Type=Application~%Categories=System;~%Terminal=false~%" program)))))))
    (synopsis "Modern fail-closed graphical Security Ops OS installer")
    (description
     "GTK 4 installation planner with stable disk identities, explicit plan
review and fail-closed destructive execution.  The apply action remains disabled
until the real-disk BIOS/UEFI, encryption, interruption and recovery matrix is
complete.")
    (home-page "https://securityops.co")
    (license license:agpl3+)))
