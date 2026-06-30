;; -*- mode: scheme; -*-
;;; SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Evelin-Commercial
;;; (securityos packages evelin) — Evelin post-quantum transport toolkit.
;;;
;;; Ships the OFFICIAL prebuilt static-musl 4.1.1 release binaries (client,
;;; server, agent, ev, keygen, keyscan, multisig-verify).  They are fully static
;;; (musl, link-self-contained) so they need no Guix runtime inputs, no patchelf
;;; and no grafting — copy-build-system is all that's required.  No secrets are
;;; embedded; the tarball is the public signed release.
(define-module (securityos packages evelin)
  #:use-module (guix packages)
  #:use-module (guix gexp)
  #:use-module (guix build-system copy)
  #:use-module ((guix licenses) #:prefix license:)
  #:export (evelin))

(define-public evelin
  (package
    (name "evelin")
    (version "4.1.1")
    (source (local-file "evelin-v4.1.1-linux-x86_64-musl.tar.gz"))
    (build-system copy-build-system)
    (arguments
     (list
      #:install-plan
      #~'(("bin/"   "bin/")
          ("share/" "share/"))
      #:phases
      #~(modify-phases %standard-phases
          ;; static musl binaries: nothing to strip / no runpath to validate
          (delete 'strip)
          (delete 'validate-runpath))))
    (supported-systems '("x86_64-linux"))
    (synopsis "Evelin post-quantum transport (prebuilt static release binaries)")
    (description "Client, server, agent and key tools from the official Evelin
4.1.1 x86_64 musl-static release: ML-KEM-1024 key exchange, ML-DSA-87
authentication, ChaCha20-Poly1305 AEAD.  Fully static — no runtime
dependencies.")
    (home-page "https://git.securityops.co/cristiancmoises/evelin")
    (license license:agpl3+)))
