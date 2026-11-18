;; CodeMark v1 project=4c63e0fe-589c-4944-8449-97e211a38b72 file=92734bc4ffab5649aceb0b3affffbd3a owner="Cristian Cezar Mois\u00e9s"
;;; CADCraft official Linux binaries, repackaged for SecurityOps.
;;; Upstream and third-party notices are installed under share/doc/cadcraft.
(define-module (securityops packages cadcraft)
  #:use-module (guix packages)
  #:use-module (guix licenses)
  #:use-module (guix download)
  #:use-module (guix gexp)
  #:use-module (guix build-system copy)
  #:use-module (gnu packages base)
  #:use-module (gnu packages bash)
  #:use-module (gnu packages gcc)
  #:use-module (gnu packages gl)
  #:use-module ((gnu packages freedesktop) #:prefix freedesktop:)
  #:use-module (gnu packages xdisorg)
  #:use-module (gnu packages xorg))

(define artcraft-license
  (license "ArtCraft proprietary"
           "https://github.com/storytold/cadcraft"
           "Official upstream binary; source code is MIT or Apache-2.0 while the ArtCraft brand assets carry separate non-free terms."))

(define-public cadcraft
  (package
    (name "cadcraft")
    (version "0.7.0")
    (source
     (origin
       (method url-fetch)
       (uri (string-append
             "https://github.com/storytold/cadcraft/releases/download/v"
             version "/cadcraft-" version "-linux-x86_64.tar.gz"))
       (sha256
        (base32 "1h2wjmn08hw5apqmg4hj7cgpvqgfycnwvrhafzmk8vq4dnl4m3fg"))))
    (build-system copy-build-system)
    (inputs
     `(("glibc" ,glibc)
       ("gcc:lib" ,gcc "lib")
       ("bash-minimal" ,bash-minimal)
       ("libx11" ,libx11)
       ("libxcb" ,libxcb)
       ("libxcursor" ,libxcursor)
       ("libxi" ,libxi)
       ("libxrandr" ,libxrandr)
       ("libxkbcommon" ,libxkbcommon)
       ("mesa" ,mesa)
       ("wayland" ,freedesktop:wayland)))
    (native-inputs
     (list
      (list "acadrust-source"
            (origin
              (method url-fetch)
              (uri (string-append
                    "https://static.crates.io/crates/acadrust/"
                    "acadrust-0.6.4.crate"))
              (sha256
               (base32 "1xiq7qi6f758iyj88cl1aclp26nd2si03a1k0knq5qmnra4j31ll"))))
      (list "source-docs"
            (origin
              (method url-fetch)
              (uri (string-append
                    "https://github.com/storytold/cadcraft/archive/"
                    "refs/tags/v0.7.0.tar.gz"))
              (sha256
               (base32 "0qsaclgmqfpz5vlhk42ixy8ahm9ya84q9q4bv0iqqwv1yl6p1v0l"))))
      (list "accesskit-chromium-notice"
            (origin
              (method url-fetch)
              (uri (string-append
                    "https://raw.githubusercontent.com/AccessKit/accesskit/"
                    "f40dfc01a0c0e76de535969f82fb35e19513737d/"
                    "LICENSE.chromium"))
              (sha256
               (base32 "024kxp0d8n75ib3x7nar6c7jkv3lnv2d6k5slr0vn6nvq7h24l44"))))
      (list "egui-font-notices"
            (origin
              (method url-fetch)
              (uri (string-append
                    "https://static.crates.io/crates/epaint_default_fonts/"
                    "epaint_default_fonts-0.36.2.crate"))
              (sha256
               (base32 "04zs5mqa62jpfzgl2q4fsvjcqhgifxhyvl1rgs4fznyhdp4sjgvp"))))))
    (arguments
     (list
      #:install-plan
      #~'(("bin/" "libexec/cadcraft/")
          ("share/" "share/"))
      #:phases
      #~(modify-phases %standard-phases
          (delete 'strip)
          (delete 'validate-runpath)
          (add-after 'install 'install-source-notices
            (lambda* (#:key inputs #:allow-other-keys)
              (use-modules (guix build utils))
              (let ((doc (string-append #$output "/share/doc/cadcraft"))
                    (source-docs (assoc-ref inputs "source-docs")))
                (unless source-docs
                  (error "fixed CADCraft source archive missing"))
                (mkdir-p doc)
                (invoke "tar" "-xzf" source-docs "-C" doc
                        "--strip-components=1"
                        "cadcraft-0.7.0/NOTICE"
                        "cadcraft-0.7.0/ATTRIBUTION.md"
                        "cadcraft-0.7.0/LICENSE-MIT"
                        "cadcraft-0.7.0/LICENSE-APACHE"
                        "cadcraft-0.7.0/docs/brand/LICENSE-brand.txt"))))
          (add-after 'install-source-notices 'install-chromium-notice
            (lambda* (#:key inputs #:allow-other-keys)
              (use-modules (guix build utils))
              (let ((doc (string-append #$output
                                        "/share/doc/cadcraft/accesskit"))
                    (notice (assoc-ref inputs "accesskit-chromium-notice")))
                (unless notice
                  (error "fixed AccessKit Chromium notice missing"))
                (mkdir-p doc)
                (copy-file notice (string-append doc "/LICENSE.chromium")))))
          (add-after 'install-chromium-notice 'install-font-notices
            (lambda* (#:key inputs #:allow-other-keys)
              (use-modules (guix build utils))
              (let ((doc (string-append #$output
                                        "/share/doc/cadcraft/crates/"
                                        "epaint_default_fonts-0.36.2"))
                    (fonts (assoc-ref inputs "egui-font-notices")))
                (unless fonts
                  (error "fixed epaint font source missing"))
                (mkdir-p doc)
                (invoke "tar" "-xzf" fonts "-C" doc "--strip-components=1"
                        "epaint_default_fonts-0.36.2/fonts/Hack-Regular.txt"
                        "epaint_default_fonts-0.36.2/fonts/OFL.txt"
                        "epaint_default_fonts-0.36.2/fonts/UFL.txt"
                        (string-append
                         "epaint_default_fonts-0.36.2/fonts/"
                         "emoji-icon-font-mit-license.txt")))))
          (add-after 'install-font-notices 'install-acadrust-source
            (lambda* (#:key inputs #:allow-other-keys)
              (use-modules (guix build utils))
              (let* ((doc (string-append #$output "/share/doc/cadcraft"))
                     (source (assoc-ref inputs "acadrust-source"))
                     (source-dir (string-append doc "/sources"))
                     (license-dir (string-append doc "/crates/acadrust-0.6.4")))
                (unless source
                  (error "fixed acadrust source archive missing"))
                (mkdir-p source-dir)
                (mkdir-p license-dir)
                (copy-file source
                           (string-append source-dir "/acadrust-0.6.4.crate"))
                (invoke "tar" "-xzf" source "-C" license-dir
                        "--strip-components=1" "acadrust-0.6.4/LICENSE")
                (call-with-output-file (string-append doc "/SOURCES.txt")
                  (lambda (port)
                    (display
                     (string-append
                      "CADCraft 0.7.0 official upstream binary, "
                      "repackaged with dependency source notices.\n"
                      "CADCraft DWG bridge uses acadrust 0.6.4 "
                      "on non-wasm targets.\n"
                      "acadrust source: "
                      "https://static.crates.io/crates/acadrust/"
                      "acadrust-0.6.4.crate\n"
                      "SHA-256: 94862189cab6e282ed0433a801a216cd"
                      "1a712953813284a48fa81c67223e38f6\n"
                      "Local copy: sources/acadrust-0.6.4.crate\n"
                      "License: crates/acadrust-0.6.4/LICENSE\n"
                      "This crate is not proof of exact official "
                      "ELF provenance.\n")
                     port))))))
          (add-after 'install-acadrust-source 'create-launchers
            (lambda* (#:key inputs #:allow-other-keys)
              (use-modules (guix build utils) (ice-9 format) (srfi srfi-13))
              (let* ((out #$output)
                     (shell (search-input-file inputs "/bin/sh"))
                     (loader (search-input-file inputs
                                                "/lib/ld-linux-x86-64.so.2"))
                     (gcc-lib (search-input-file inputs "/lib/libgcc_s.so.1"))
                     (library-path
                      (string-join
                       (append
                        (list (dirname loader) (dirname gcc-lib))
                        (map (lambda (name)
                               (string-append (assoc-ref inputs name) "/lib"))
                             '("libx11" "libxcb" "libxcursor" "libxi"
                               "libxrandr" "libxkbcommon" "mesa" "wayland")))
                       ":"))
                     (bin (string-append out "/bin"))
                     (desktop (string-append out
                                             "/share/applications/"
                                             "ai.storyteller.cadcraft.desktop")))
                (mkdir-p bin)
                (for-each
                 (lambda (name)
                   (let ((launcher (string-append bin "/" name))
                         (original (string-append out "/libexec/cadcraft/" name)))
                     (unless (file-exists? original)
                       (error "official binary missing" name))
                     (call-with-output-file launcher
                       (lambda (port)
                         (format port
                                 (string-append
                                  "#!~a~%"
                                  "LD_LIBRARY_PATH=~a; export LD_LIBRARY_PATH~%"
                                  "exec ~a --library-path ~a ~a \"$@\"~%")
                                 shell library-path loader library-path
                                 original)))
                     (chmod launcher #o755)))
                 '("cadcraft" "cadcraft-cli"))
                (substitute* desktop
                  (("^Exec=cadcraft %F$")
                   (string-append "Exec=" bin "/cadcraft %F"))
                  (("^TryExec=cadcraft$")
                   (string-append "TryExec=" bin "/cadcraft"))))))
          (add-after 'create-launchers 'smoke-versions
            (lambda _
              (invoke (string-append #$output "/bin/cadcraft") "--version")
              (invoke (string-append #$output "/bin/cadcraft-cli")
                      "--version"))))))
    (supported-systems '("x86_64-linux"))
    (synopsis "CADCraft CAD editor")
    (description
     "Official CADCraft 0.7.0 Linux binaries, repacked without modification
and installed with the upstream source and third-party license notices.  The
application source is MIT or Apache-2.0; ArtCraft brand assets use separate
non-free terms.")
    (home-page "https://github.com/storytold/cadcraft")
    (license artcraft-license)))
