;; CodeMark v1 project=4c63e0fe-589c-4944-8449-97e211a38b72 file=9c99f97a39bd5ac9a1d545f07f542a80 owner="Cristian Cezar Mois\u00e9s"
;;; FigCraft official Linux binaries, repackaged for SecurityOps.
;;; Upstream and third-party notices are installed under share/doc/figcraft.
(define-module (securityops packages figcraft)
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
           "https://github.com/storytold/figcraft"
           "Official upstream binary; source code is MIT or Apache-2.0 while the ArtCraft brand assets carry separate non-free terms."))

(define-public figcraft
  (package
    (name "figcraft")
    (version "0.6.0")
    (source
     (origin
       (method url-fetch)
       (uri (string-append
             "https://github.com/storytold/figcraft/releases/download/v"
             version "/figcraft-" version "-linux-x86_64.tar.gz"))
       (sha256
        (base32 "0q06m9mppjv2x6qchcgln7ldnk6mfj4icw4jbwklxrayz9lglvdn"))))
    (build-system copy-build-system)
    (inputs
     `(("glibc" ,glibc)
       ("gcc:lib" ,gcc "lib")
       ("bash-minimal" ,bash-minimal)
       ("libx11" ,libx11)
       ("libxcb" ,libxcb)
       ("libxcursor" ,libxcursor)
       ("libxi" ,libxi)
       ("libxkbcommon" ,libxkbcommon)
       ("mesa" ,mesa)
       ("wayland" ,freedesktop:wayland)))
    (native-inputs
     (list
      (list "imbl-source"
            (origin
              (method url-fetch)
              (uri "https://static.crates.io/crates/imbl/imbl-7.0.2.crate")
              (sha256
               (base32 "1v2g3z3sm0pk2pqkmwa4kmx8jfrfrj468l5qk29ysqxlp4rdifj6"))))
      (list "imbl-sized-chunks-source"
            (origin
              (method url-fetch)
              (uri (string-append
                    "https://static.crates.io/crates/imbl-sized-chunks/"
                    "imbl-sized-chunks-0.2.0.crate"))
              (sha256
               (base32 "1im99y02lklvq9brfn403fvfhjcml6gp961jjmbzhlr56fz1621a"))))
      (list "source-docs"
            (origin
              (method url-fetch)
              (uri (string-append
                    "https://github.com/storytold/figcraft/archive/refs/"
                    "tags/v0.6.0.tar.gz"))
              (sha256
               (base32 "0asdgsfffkwlk1fjwn5fzw7f3a8pm0cm26xpyralz0jfpzpj210k"))))
      (list "egui-font-notices"
            (origin
              (method url-fetch)
              (uri (string-append
                    "https://static.crates.io/crates/epaint_default_fonts/"
                    "epaint_default_fonts-0.36.2.crate"))
              (sha256
               (base32 "04zs5mqa62jpfzgl2q4fsvjcqhgifxhyvl1rgs4fznyhdp4sjgvp"))))
      (list "accesskit-chromium-notice"
            (origin
              (method url-fetch)
              (uri (string-append
                    "https://raw.githubusercontent.com/AccessKit/accesskit/"
                    "f40dfc01a0c0e76de535969f82fb35e19513737d/"
                    "LICENSE.chromium"))
              (sha256
               (base32 "024kxp0d8n75ib3x7nar6c7jkv3lnv2d6k5slr0vn6nvq7h24l44"))))))
    (arguments
     (list
      #:install-plan
      #~'(("bin/" "libexec/figcraft/")
          ("share/" "share/"))
      #:phases
      #~(modify-phases %standard-phases
          (delete 'strip)
          (delete 'validate-runpath)
          (add-after 'install 'install-notices
            (lambda* (#:key inputs #:allow-other-keys)
              (use-modules (guix build utils))
              (let ((doc (string-append #$output "/share/doc/figcraft"))
                    (source-docs (assoc-ref inputs "source-docs"))
                    (fonts (assoc-ref inputs "egui-font-notices")))
                (unless source-docs
                  (error "fixed FigCraft source archive missing"))
                (unless fonts
                  (error "fixed epaint font source missing"))
                (mkdir-p doc)
                (invoke "tar" "-xzf" source-docs "-C" doc
                        "--strip-components=1"
                        "figcraft-0.6.0/ATTRIBUTION.md"
                        "figcraft-0.6.0/assets/app-icon/LICENSE.txt")
                (let ((font-doc (string-append
                                 doc "/crates/epaint_default_fonts-0.36.2")))
                  (mkdir-p font-doc)
                  (invoke "tar" "-xzf" fonts "-C" font-doc
                          "--strip-components=1"
                          "epaint_default_fonts-0.36.2/fonts/Hack-Regular.txt"
                          "epaint_default_fonts-0.36.2/fonts/OFL.txt"
                          "epaint_default_fonts-0.36.2/fonts/UFL.txt"
                          (string-append
                           "epaint_default_fonts-0.36.2/fonts/"
                           "emoji-icon-font-mit-license.txt"))))))
          (add-after 'install-notices 'install-chromium-notice
            (lambda* (#:key inputs #:allow-other-keys)
              (use-modules (guix build utils))
              (let ((doc (string-append #$output
                                        "/share/doc/figcraft/accesskit"))
                    (notice (assoc-ref inputs "accesskit-chromium-notice")))
                (unless notice
                  (error "fixed AccessKit Chromium notice missing"))
                (mkdir-p doc)
                (copy-file notice (string-append doc "/LICENSE.chromium")))))
          (add-after 'install-chromium-notice 'install-imbl-notices
            (lambda* (#:key inputs #:allow-other-keys)
              (use-modules (guix build utils))
              (let* ((doc (string-append #$output "/share/doc/figcraft"))
                     (source-dir (string-append doc "/sources")))
                (mkdir-p source-dir)
                (for-each
                 (lambda (item)
                   (let* ((name (car item))
                          (version (cadr item))
                          (input-name (caddr item))
                          (source (assoc-ref inputs input-name))
                          (stem (string-append name "-" version))
                          (license-dir (string-append doc "/crates/" stem)))
                     (unless source
                       (error "fixed imbl crate source missing" input-name))
                     (mkdir-p license-dir)
                     (copy-file source (string-append source-dir "/" stem ".crate"))
                     (invoke "tar" "-xzf" source "-C" license-dir
                             "--strip-components=1"
                             (string-append stem "/LICENCE.md"))))
                 '(("imbl" "7.0.2" "imbl-source")
                   ("imbl-sized-chunks" "0.2.0" "imbl-sized-chunks-source")))
                (call-with-output-file (string-append doc "/SOURCES.txt")
                  (lambda (port)
                    (display
                     (string-append
                      "FigCraft 0.6.0 official upstream binary, repackaged with dependency source notices.\n"
                      "imbl 7.0.2 crate source: "
                      "https://static.crates.io/crates/imbl/imbl-7.0.2.crate\n"
                      "Local copy: sources/imbl-7.0.2.crate\n"
                      "License: crates/imbl-7.0.2/LICENCE.md\n"
                      "imbl-sized-chunks 0.2.0 crate source: "
                      "https://static.crates.io/crates/imbl-sized-chunks/"
                      "imbl-sized-chunks-0.2.0.crate\n"
                      "Local copy: sources/imbl-sized-chunks-0.2.0.crate\n"
                      "License: crates/imbl-sized-chunks-0.2.0/LICENCE.md\n"
                      "These crate archives are not proof of exact official ELF provenance.\n")
                     port))))))
          (add-after 'install-imbl-notices 'create-launchers
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
                               "libxkbcommon" "mesa" "wayland")))
                       ":"))
                     (bin (string-append out "/bin")))
                (mkdir-p bin)
                (for-each
                 (lambda (name)
                   (let ((launcher (string-append bin "/" name))
                         (original (string-append
                                    out "/libexec/figcraft/" name)))
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
                 '("figcraft" "figcraft-cli")))))
          (add-after 'create-launchers 'smoke-versions
            (lambda _
              (invoke (string-append #$output "/bin/figcraft") "--version")
              (invoke (string-append #$output "/bin/figcraft-cli")
                      "--version"))))))
    (supported-systems '("x86_64-linux"))
    (synopsis "FigCraft interface design app")
    (description
     "Official FigCraft 0.6.0 Linux binaries, repacked without modification
and installed with the upstream source and third-party license notices.  The
application source is MIT or Apache-2.0; ArtCraft brand assets use separate
non-free terms.")
    (home-page "https://github.com/storytold/figcraft")
    (license artcraft-license)))
