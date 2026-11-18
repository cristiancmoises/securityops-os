;; CodeMark v1 project=4c63e0fe-589c-4944-8449-97e211a38b72 file=1c3317bb75e05f4e8d19212d26a1eb12 owner="Cristian Cezar Mois\u00e9s"
;;; GridCraft official Linux binaries, repackaged for SecurityOps.
;;; Upstream and third-party notices are installed under share/doc/gridcraft.
(define-module (securityops packages gridcraft)
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
           "https://github.com/storytold/gridcraft"
           "Official upstream binary; source code is MIT or Apache-2.0 while the ArtCraft brand assets carry separate non-free terms."))

(define-public gridcraft
  (package
    (name "gridcraft")
    (version "0.7.0")
    (source
     (origin
       (method url-fetch)
       (uri (string-append
             "https://github.com/storytold/gridcraft/releases/download/v"
             version "/gridcraft-" version "-linux-x86_64.tar.gz"))
       (sha256
        (base32 "074yndlw09h6w41s2my1aa2khn1zbald9zhdh59nymcm8bfc46y0"))))
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
      (list "source-docs"
            (origin
              (method url-fetch)
              (uri (string-append
                    "https://github.com/storytold/gridcraft/archive/refs/tags/"
                    "v0.7.0.tar.gz"))
              (sha256
               (base32 "08q1wqlb841qw28yahp6z9xlfza98xx7rw9mp3dd0i1h3vr5v6z7"))))
      (list "craft-libs-notices"
            (origin
              (method url-fetch)
              (uri (string-append
                    "https://github.com/storytold/craft-libs/archive/"
                    "d27646a5f7c8b4fc85d9dd3213b8c88b58e0088d.tar.gz"))
              (sha256
               (base32 "13rih8b25yjwf1aw85b6hlm0q8z6zdrzq8sh2nna8pjzmhrff4ph"))))
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
      #~'(("bin/" "libexec/gridcraft/")
          ("share/" "share/"))
      #:phases
      #~(modify-phases %standard-phases
          (delete 'strip)
          (delete 'validate-runpath)
          (add-after 'install 'install-source-notices
            (lambda* (#:key inputs #:allow-other-keys)
              (use-modules (guix build utils))
              (let ((doc (string-append #$output "/share/doc/gridcraft"))
                    (source-docs (assoc-ref inputs "source-docs")))
                (unless source-docs
                  (error "fixed GridCraft source archive missing"))
                (mkdir-p doc)
                (invoke "tar" "-xzf" source-docs "-C" doc
                        "--strip-components=1"
                        "gridcraft-0.7.0/NOTICE"
                        "gridcraft-0.7.0/ATTRIBUTION.md"
                        "gridcraft-0.7.0/assets/app-icon/LICENSE.txt"))))
          (add-after 'install-source-notices 'install-craft-libs-notices
            (lambda* (#:key inputs #:allow-other-keys)
              (use-modules (guix build utils))
              (let ((doc (string-append
                          #$output "/share/doc/gridcraft/craft-libs"))
                    (libs (assoc-ref inputs "craft-libs-notices")))
                (unless libs
                  (error "fixed craft-libs archive missing"))
                (mkdir-p doc)
                (invoke "tar" "-xzf" libs "-C" doc
                        "--strip-components=1"
                        "craft-libs-d27646a5f7c8b4fc85d9dd3213b8c88b58e0088d/NOTICE"
                        (string-append
                         "craft-libs-d27646a5f7c8b4fc85d9dd3213b8c88b58e0088d/"
                         "ATTRIBUTION.md")
                        (string-append
                         "craft-libs-d27646a5f7c8b4fc85d9dd3213b8c88b58e0088d/"
                         "LICENSE-MIT")
                        (string-append
                         "craft-libs-d27646a5f7c8b4fc85d9dd3213b8c88b58e0088d/"
                         "LICENSE-APACHE")))))
          (add-after 'install-craft-libs-notices 'install-font-notices
            (lambda* (#:key inputs #:allow-other-keys)
              (use-modules (guix build utils))
              (let ((doc (string-append
                          #$output
                          "/share/doc/gridcraft/crates/epaint_default_fonts-0.36.2"))
                    (fonts (assoc-ref inputs "egui-font-notices")))
                (unless fonts
                  (error "fixed epaint font source missing"))
                (mkdir-p doc)
                (invoke
                 "tar" "-xzf" fonts "-C" doc "--strip-components=1"
                 "epaint_default_fonts-0.36.2/fonts/Hack-Regular.txt"
                 "epaint_default_fonts-0.36.2/fonts/OFL.txt"
                 "epaint_default_fonts-0.36.2/fonts/UFL.txt"
                 (string-append
                  "epaint_default_fonts-0.36.2/fonts/"
                  "emoji-icon-font-mit-license.txt")))))
          (add-after 'install-font-notices 'install-chromium-notice
            (lambda* (#:key inputs #:allow-other-keys)
              (use-modules (guix build utils))
              (let ((doc (string-append #$output
                                        "/share/doc/gridcraft/accesskit"))
                    (notice (assoc-ref inputs "accesskit-chromium-notice")))
                (unless notice
                  (error "fixed AccessKit Chromium notice missing"))
                (mkdir-p doc)
                (copy-file notice (string-append doc "/LICENSE.chromium")))))
          (add-after 'install-chromium-notice 'create-launchers
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
                                    out "/libexec/gridcraft/" name)))
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
                 '("gridcraft" "gridcraft-cli")))))
          (add-after 'create-launchers 'smoke-versions
            (lambda _
              (invoke (string-append #$output "/bin/gridcraft") "--version")
              (invoke (string-append #$output "/bin/gridcraft-cli")
                      "--version")
              (invoke (string-append #$output "/bin/gridcraft-cli")
                      "eval" "=SUM(1,2,3)"))))))
    (supported-systems '("x86_64-linux"))
    (synopsis "GridCraft spreadsheet")
    (description
     "Official GridCraft 0.7.0 Linux binaries, repacked without modification
and installed with the upstream source and third-party license notices.  The
application source is MIT or Apache-2.0; ArtCraft brand assets use separate
non-free terms.")
    (home-page "https://github.com/storytold/gridcraft")
    (license artcraft-license)))
