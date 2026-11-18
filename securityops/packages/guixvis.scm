;; CodeMark v1 project=4c63e0fe-589c-4944-8449-97e211a38b72 file=57459816fb19580dbec55180abc00c6f owner="Cristian Cezar Mois\u00e9s"
;;; SPDX-License-Identifier: GPL-3.0-or-later
;;; Copyright © 2026 Cristian Cezar Moisés <ethicalhacker@riseup.net>
;;;
;;; Imported from securityops-channel 017b9e3aa09bbafca341dfba7c91ca96211e8020,
;;; securityops/packages/apps.scm.  Immutable, hash-verified origins avoid
;;; advancing the channel graph; Cargo jobs follow Guix build parallelism.

(define-module (securityops packages guixvis)
  #:use-module (guix packages)
  #:use-module (guix download)
  #:use-module (guix gexp)
  #:use-module (guix utils)
  #:use-module (guix build-system gnu)
  #:use-module (gnu packages rust)
  #:use-module ((guix licenses) #:prefix license:))

(define %archive-base
  "https://git.securityops.com.br/cristiancmoises/securityops-channel/raw/commit/017b9e3aa09bbafca341dfba7c91ca96211e8020/securityops/packages/sources/")

(define-public guixvis
  (package
    (name "guixvis")
    (version "0.8.0")
    (source
     (origin
       (method url-fetch)
       (uri (string-append %archive-base "guixvis-0.8.0-src.tar"))
       (sha256
        (base32 "0ladbkqzy8i4c8r6nnb4c2hfsry545phb3bpr6nljl9497valjzn"))))
    (build-system gnu-build-system)
    (arguments
     (list
      #:phases
      #~(modify-phases %standard-phases
          ;; Cargo verifies original vendor checksums; leave shebangs intact.
          (delete 'patch-source-shebangs)
          (delete 'patch-generated-file-shebangs)
          (replace 'configure
            (lambda* (#:key inputs #:allow-other-keys)
              (invoke "tar" "xf" (assoc-ref inputs "vendor"))
              (setenv "CARGO_HOME" (string-append (getcwd) "/.cargo"))
              (setenv "CC" #$(cc-for-target))))
          (replace 'build
            (lambda* (#:key (parallel-build? #t) #:allow-other-keys)
              (invoke "cargo" "build" "--frozen" "--offline" "--release"
                      "--features" "web" "--jobs"
                      (number->string
                       (if parallel-build? (parallel-job-count) 1)))))
          (replace 'check
            (lambda* (#:key tests? (parallel-build? #t) #:allow-other-keys)
              (when tests?
                (invoke "cargo" "test" "--frozen" "--offline"
                        "--features" "web" "--jobs"
                        (number->string
                         (if parallel-build? (parallel-job-count) 1))))))
          (replace 'install
            (lambda _
              (let ((bin (string-append #$output "/bin"))
                    (doc (string-append #$output "/share/doc/guixvis")))
                (install-file "target/release/guixvis" bin)
                (for-each (lambda (file) (install-file file doc))
                          '("README.md" "README.pt-BR.md" "LICENSE"
                            "SECURITY.md"))
                (install-file "elisp/guixvis.el"
                              (string-append #$output "/share/emacs/site-lisp"))
                (copy-recursively "assets" (string-append doc "/assets"))
                (copy-recursively "docs" (string-append doc "/docs"))))))))
    (native-inputs
     `(("rust" ,rust)
       ("rust:cargo" ,rust "cargo")
       ("vendor"
        ,(origin
           (method url-fetch)
           (uri (string-append %archive-base "guixvis-0.1.0-vendor.tar.gz"))
           (sha256
            (base32 "10z198li476x3zs829k85ngyq3rllikqnzbd3ldzg5x8qvnc1cky"))))))
    (supported-systems '("x86_64-linux"))
    (home-page "https://codeberg.org/berkeley/guixvis")
    (synopsis "Interactive package explorer and dependency visualizer for GNU Guix")
    (description
     "guixvis indexes GNU Guix packages for a keyboard-first terminal UI, a
local web application, and an Emacs library.  The terminal has per-tab filters,
exact dependency and reverse-dependency searches, and quieter dependency
graphs.  The web UI (@command{guixvis web}) serves bubble and rectangle graph
views on 127.0.0.1 with right-click Back navigation, deep links, and browser
history.  The Emacs library provides terminal, browser, and native package
search commands.")
    (license license:gpl3+)))
