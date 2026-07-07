;;; esquema.scm — Esquema: a rootless, Guile-native container runtime.
;;;
;;; C sandbox primitives (user/mount/PID/UTS/IPC/net/cgroup namespaces,
;;; pivot_root, capability drop, seccomp-BPF allowlist, NO_NEW_PRIVS) exposed
;;; to a Guile FFI + Scheme runtime.  Upstream: git.securityops.co/cristiancmoises/esquema
;;;
;;; The in-tree source is vendored under esquema-src/ for a fully offline,
;;; reproducible build.  The Makefile has no install rule, so we install by
;;; hand: libesquema.so → lib/, the Scheme modules → the Guile site dir, and we
;;; export ESQUEMA_LIBDIR so the FFI resolves the .so from the profile.
;;;
;;; © Cristian Cezar Moisés · sac@securityops.co · AGPL-3.0-or-later
(define-module (securityos packages esquema)
  #:use-module (guix packages)
  #:use-module (guix gexp)
  #:use-module (guix utils)                 ; cc-for-target
  #:use-module (guix build-system gnu)
  #:use-module ((guix licenses) #:prefix license:)
  #:use-module (gnu packages)
  #:use-module (gnu packages guile)
  #:use-module (gnu packages linux)         ; libseccomp, libcap
  #:use-module (gnu packages pkg-config)
  #:export (esquema))

(define esquema
  (package
    (name "esquema")
    (version "1.0.0")
    (source (local-file "esquema.tar.gz"))   ; vendored, offline, reproducible
    (build-system gnu-build-system)
    (arguments
     (list
      #:tests? #f                     ; suite needs live kernel namespaces (not in the build sandbox)
      #:make-flags #~(list (string-append "CC=" #$(cc-for-target)))
      #:phases
      #~(modify-phases %standard-phases
          (delete 'configure)         ; plain Makefile, no ./configure
          (replace 'install
            (lambda _
              (let* ((lib (string-append #$output "/lib"))
                     (scm (string-append #$output "/share/guile/site/3.0"))
                     (doc (string-append #$output "/share/doc/esquema-" #$version)))
                (mkdir-p lib) (mkdir-p scm) (mkdir-p doc)
                (install-file "libesquema.so" lib)     ; the FFI dlopen()s this
                (copy-recursively "scheme/esquema"
                                  (string-append scm "/esquema"))
                (install-file "README.md" doc)
                (install-file "LICENSE" doc)
                (copy-recursively "examples" (string-append doc "/examples"))))))))
    (native-inputs (list pkg-config guile-3.0))
    (inputs (list guile-3.0 libseccomp libcap))
    (native-search-paths
     ;; the FFI dlopen()s $ESQUEMA_LIBDIR/libesquema.so — never a writable cwd
     (list (search-path-specification
            (variable "ESQUEMA_LIBDIR")
            (files '("lib")))))
    (synopsis "Rootless, Guile-native container runtime")
    (description
     "Esquema is a small, rootless container runtime written in C and Guile.
It builds isolated environments using unprivileged user namespaces together
with mount, PID, UTS, IPC, network and cgroup namespaces, @code{pivot_root},
full capability drop, a seccomp-BPF syscall allowlist and @code{NO_NEW_PRIVS}.
The C primitives are exposed to a Guile FFI and a small Scheme runtime so
containers can be declared and launched from Scheme.")
    (home-page "https://git.securityops.co/cristiancmoises/esquema")
    (license license:agpl3+)))

esquema
