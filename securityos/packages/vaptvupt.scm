;; -*- mode: scheme; -*-
;;; SPDX-License-Identifier: AGPL-3.0-or-later
;;; (securityos packages vaptvupt) — the maintainer's VaptVupt post-quantum
;;; backup tool: CLI (vaptvupt 4.0.0) + PySide6 GUI (vaptvupt-gui 1.3.0).
;;; Ported from ~/Downloads/vaptvupt.scm; source = the release tarball shipped
;;; beside this module (no network needed).
(define-module (securityos packages vaptvupt)
  #:use-module (guix packages)
  #:use-module (guix gexp)
  #:use-module (guix utils)
  #:use-module (guix build-system gnu)
  #:use-module (guix build-system copy)
  #:use-module ((guix licenses) #:prefix license:)
  #:use-module (gnu packages elf)         ; patchelf
  #:use-module (gnu packages python)      ; python
  #:use-module (gnu packages qt)          ; python-pyside-6, qtbase, qtwayland
  #:use-module (gnu packages bash)        ; bash-minimal
  #:use-module (gnu packages tls)            ; openssl (libcrypto.so.3)
  #:use-module (gnu packages password-utils) ; argon2 (libargon2.so.1)
  #:export (vaptvupt vaptvupt-gui))

(define %vaptvupt-version "4.0.0")

(define %vaptvupt-source
  (local-file "vaptvupt-4.0.0.tar.gz"))

(define-public vaptvupt
  (package
    (name "vaptvupt")
    (version %vaptvupt-version)
    (source %vaptvupt-source)
    (build-system gnu-build-system)
    (arguments
     (list
      #:tests? #f          ; KAT vectors need vendored-lib runtime paths the
                           ; test harness doesn't set; the binary links fine.
      #:make-flags
      #~(list (string-append "PREFIX=" #$output)
              (string-append "CC=" #$(cc-for-target)))
      #:phases
      #~(modify-phases %standard-phases
          (delete 'configure)
          ;; The prebuilt vendor/zuptsdk/libzuptsdk.so has DT_NEEDED on
          ;; libcrypto.so.3 + libargon2.so.1 but no RUNPATH, so the final link
          ;; can't resolve them transitively.  Set LDFLAGS in the ENVIRONMENT
          ;; (Makefile uses `LDFLAGS ?=` then `+=`, so an env value is kept and
          ;; the vendored -rpath flags still append) with -rpath-link to find
          ;; them at link time and -rpath so the binary finds them at runtime.
          (add-before 'build 'set-ldflags
            (lambda* (#:key inputs #:allow-other-keys)
              (let ((ssl (string-append (assoc-ref inputs "openssl") "/lib"))
                    (arg (string-append (assoc-ref inputs "argon2") "/lib")))
                (setenv "LDFLAGS"
                        (string-append "-L" ssl " -L" arg
                                       " -Wl,-rpath-link," ssl
                                       " -Wl,-rpath-link," arg
                                       " -Wl,-rpath," ssl
                                       " -Wl,-rpath," arg)))))
          (replace 'check
            (lambda* (#:key tests? #:allow-other-keys)
              (when tests?
                (setenv "LD_LIBRARY_PATH"
                        (string-append (getcwd) "/vendor/zuptsdk:"
                                       (getcwd) "/vendor/pqvaptvupt"))
                (invoke "make" "test-vectors")
                (invoke "./test_vectors"))))
          (add-after 'install 'set-vendored-lib-runpath
            (lambda* (#:key inputs outputs #:allow-other-keys)
              (let* ((out  (assoc-ref outputs "out"))
                     (libc (assoc-ref inputs "libc"))
                     (rpath (string-join
                             (list (string-append libc "/lib")
                                   (string-append (assoc-ref inputs "openssl") "/lib")
                                   (string-append (assoc-ref inputs "argon2") "/lib"))
                             ":"))
                     (vdir (string-append out "/lib/vaptvupt")))
                (for-each
                 (lambda (lib)
                   (invoke "patchelf" "--set-rpath" rpath
                           (string-append vdir "/" lib)))
                 '("libzuptsdk.so.2.0.0"
                   "libpqvaptvupt.so.0.6.0"))))))))
    (native-inputs (list patchelf))
    (inputs (list openssl argon2))
    (home-page "https://git.securityops.co/cristiancmoises/vaptvupt")
    (synopsis "Post-quantum backup compression utility (CLI)")
    (description
     "VaptVupt is a pure-C11 backup compressor with post-quantum hybrid
encryption (ML-KEM-768 + X25519 sealed box, Argon2id password mode,
AES-256-CTR + HMAC-SHA256 Encrypt-then-MAC).")
    (license (list license:agpl3+ license:gpl3+))))

(define-public vaptvupt-gui
  (package
    (name "vaptvupt-gui")
    (version "1.3.0")
    (source (package-source vaptvupt))
    (build-system copy-build-system)
    (arguments
     (list
      #:install-plan
      #~'(("gui/src/zupt_gui.py" "lib/vaptvupt-gui/")
          ("gui/assets/zupt-icon.png"
           "share/icons/hicolor/256x256/apps/vaptvupt-gui.png")
          ("gui/README.md" "share/doc/vaptvupt-gui/")
          ("gui/LICENSE-GUI" "share/doc/vaptvupt-gui/"))
      #:phases
      #~(modify-phases %standard-phases
          (add-after 'install 'make-launcher
            (lambda* (#:key inputs outputs #:allow-other-keys)
              (let* ((out     (assoc-ref outputs "out"))
                     (bin     (string-append out "/bin"))
                     (gui     (string-append
                               out "/lib/vaptvupt-gui/zupt_gui.py"))
                     (sh      (search-input-file inputs "/bin/sh"))
                     (python3 (search-input-file inputs "/bin/python3"))
                     (cli     (search-input-file inputs "/bin/vaptvupt"))
                     (pyside  (assoc-ref inputs "python-pyside-6"))
                     (site    (car (find-files pyside "^site-packages$"
                                               #:directories? #t)))
                     (qtbase  (assoc-ref inputs "qtbase"))
                     (qtwl    (assoc-ref inputs "qtwayland")))
                (mkdir-p bin)
                (call-with-output-file (string-append bin "/vaptvupt-gui")
                  (lambda (port)
                    (format port "#!~a
export VAPTVUPT_BIN=\"~a\"
export GUIX_PYTHONPATH=\"~a${GUIX_PYTHONPATH:+:}$GUIX_PYTHONPATH\"
export QT_PLUGIN_PATH=\"~a/lib/qt6/plugins:~a/lib/qt6/plugins${QT_PLUGIN_PATH:+:}$QT_PLUGIN_PATH\"
exec \"~a\" \"~a\" \"$@\"\n"
                            sh cli site qtbase qtwl python3 gui)))
                (chmod (string-append bin "/vaptvupt-gui") #o755)
                (symlink "vaptvupt-gui" (string-append bin "/zupt-gui")))))
          (add-after 'make-launcher 'install-desktop-file
            (lambda* (#:key outputs #:allow-other-keys)
              (let* ((out  (assoc-ref outputs "out"))
                     (apps (string-append out "/share/applications")))
                (mkdir-p apps)
                (call-with-output-file
                    (string-append apps "/vaptvupt-gui.desktop")
                  (lambda (port)
                    (format port "[Desktop Entry]
Type=Application
Name=VaptVupt
GenericName=Post-Quantum Backup
Comment=Compress, encrypt and restore .zupt archives
Exec=~a/bin/vaptvupt-gui %F
Icon=vaptvupt-gui
Terminal=false
Categories=Utility;Archiving;Security;
MimeType=application/x-zupt;
Keywords=backup;encryption;post-quantum;compression;zupt;\n"
                            out)))))))))
    (inputs
     (list bash-minimal python python-pyside-6 qtbase qtwayland vaptvupt))
    (home-page "https://git.securityops.co/cristiancmoises/vaptvupt")
    (synopsis "Desktop frontend for VaptVupt (PySide6/Qt6 GUI)")
    (description
     "PySide6 (Qt 6) graphical frontend for VaptVupt: create, inspect and
extract @code{.zupt} archives.  The launcher pins the matching CLI via
@env{VAPTVUPT_BIN}.")
    (license license:agpl3+)))
