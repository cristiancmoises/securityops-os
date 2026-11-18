;; CodeMark v1 project=4c63e0fe-589c-4944-8449-97e211a38b72 file=dda05767b84e5434ab70fe2ffe2384ce owner="Cristian Cezar Mois\u00e9s"
;;; PhotoCraft official Linux binaries, repackaged for SecurityOps.
;;; Upstream and third-party notices are installed under share/doc/photocraft.
(define-module (securityops packages photocraft)
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
           "https://github.com/storytold/photocraft"
           "Official upstream binary; source code is MIT or Apache-2.0 while the ArtCraft brand assets carry separate non-free terms."))

(define-public photocraft
  (package
    (name "photocraft")
    (version "0.9.0")
    (source
     (origin
       (method url-fetch)
       (uri (string-append
             "https://github.com/storytold/photocraft/releases/download/v"
             version "/photocraft-" version "-linux-x86_64.tar.gz"))
       (sha256
        (base32 "03drzpy4mmws61ch58xjpmzaqxqfr4qma22bc0whhwddhla0qc4i"))))
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
      (list "source-notices"
            (origin
              (method url-fetch)
              (uri (string-append
                    "https://github.com/storytold/photocraft/"
                    "archive/refs/tags/v0.9.0.tar.gz"))
              (sha256
               (base32 "0fmv4nszqb6fcq31rm9c3jshp51q8k62221jydwbnm77y02bdm5d"))))
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
               (base32 "024kxp0d8n75ib3x7nar6c7jkv3lnv2d6k5slr0vn6nvq7h24l44"))))
      (list "craft-libs-print-notices"
            (origin
              (method url-fetch)
              (uri (string-append
                    "https://codeload.github.com/storytold/craft-libs/tar.gz/"
                    "3d37da389a3618ab9b76109da11416e9ca4ea719"))
              (sha256
               (base32 "14ajm8csmq0l59d11lvwp2s74whii2llmalghnpf9bq5mkkh6bwp"))))
      (list "craft-libs-ui-notices"
            (origin
              (method url-fetch)
              (uri (string-append
                    "https://codeload.github.com/storytold/craft-libs/tar.gz/"
                    "5c874d51eeb3de70e735c8ce87a59a7dedd47675"))
              (sha256
               (base32 "06055y33nmc8z1gzm5ahjxc11170j9jixdq62i5sjl22gymbh6kr"))))
      (list "winprint-gdi-license"
            (origin
              (method url-fetch)
              (uri (string-append
                    "https://codeload.github.com/storytold/winprint.rs/tar.gz/"
                    "417ac3c4d14d3da5485a99c7d5ce8f05664ec312"))
              (sha256
               (base32 "14c20i0ycpkhw9zwdih1pr652kiad75b6zdqs6grfm2rjbmkk25h"))))))
    (arguments
     (list
      #:install-plan
      #~'(("bin/" "libexec/photocraft/")
          ("share/" "share/"))
      #:phases
      #~(modify-phases %standard-phases
          (delete 'strip)
          (delete 'validate-runpath)
          (add-after 'install 'install-notices
            (lambda* (#:key inputs #:allow-other-keys)
              (use-modules (guix build utils))
              (let ((doc (string-append #$output "/share/doc/photocraft"))
                    (source (assoc-ref inputs "source-notices"))
                    (fonts (assoc-ref inputs "egui-font-notices")))
                (mkdir-p doc)
                (invoke
                 "tar" "-xzf" source "-C" doc "--strip-components=1"
                 "photocraft-0.9.0/NOTICE"
                 "photocraft-0.9.0/ATTRIBUTION.md"
                 "photocraft-0.9.0/assets/fonts/OFL-Inter.txt"
                 "photocraft-0.9.0/assets/fonts/OFL-JetBrainsMono.txt"
                 "photocraft-0.9.0/assets/icons/LICENSE-lucide.txt"
                 "photocraft-0.9.0/assets/icons/LICENSE-noun-magnetic-lasso.txt"
                 "photocraft-0.9.0/assets/icons/LICENSE-symmetry-axes.txt"
                 "photocraft-0.9.0/assets/dict/LICENSE-SCOWL.txt"
                 "photocraft-0.9.0/assets/app-icon/LICENSE.txt"
                 "photocraft-0.9.0/crates/ui-egui/src/LICENSE-solarized.txt"
                 "photocraft-0.9.0/crates/ui-egui/src/i18n/LICENSE-translations.txt"
                 "photocraft-0.9.0/docs/brand/LICENSE-brand.txt")
                (let ((font-doc
                       (string-append doc "/crates/epaint_default_fonts-0.36.2")))
                  (mkdir-p font-doc)
                  (invoke
                   "tar" "-xzf" fonts "-C" font-doc "--strip-components=1"
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
                                        "/share/doc/photocraft/accesskit"))
                    (notice (assoc-ref inputs "accesskit-chromium-notice")))
                (unless notice
                  (error "fixed AccessKit Chromium notice missing"))
                (mkdir-p doc)
                (copy-file notice (string-append doc "/LICENSE.chromium")))))
          (add-after 'install-chromium-notice 'install-git-notices
            (lambda* (#:key inputs #:allow-other-keys)
              (use-modules (guix build utils))
              (let ((base (string-append #$output
                                         "/share/doc/photocraft/git-sources")))
                (for-each
                 (lambda (entry)
                   (let* ((key (car entry))
                          (relative (cadr entry))
                          (prefix (caddr entry))
                          (names (cadddr entry))
                          (archive (assoc-ref inputs key))
                          (target (string-append base "/" relative)))
                     (unless archive
                       (error "pinned Git source notices missing" key))
                     (mkdir-p target)
                     (apply invoke
                            (append
                             (list "tar" "-xzf" archive "-C" target
                                   "--strip-components=1")
                             (map (lambda (name)
                                    (string-append prefix name))
                                  names)))))
                 '(("craft-libs-print-notices"
                    "craft-libs/3d37da389a3618ab9b76109da11416e9ca4ea719"
                    "craft-libs-3d37da389a3618ab9b76109da11416e9ca4ea719/"
                    ("NOTICE" "ATTRIBUTION.md" "LICENSE-MIT" "LICENSE-APACHE"))
                   ("craft-libs-ui-notices"
                    "craft-libs/5c874d51eeb3de70e735c8ce87a59a7dedd47675"
                    "craft-libs-5c874d51eeb3de70e735c8ce87a59a7dedd47675/"
                    ("NOTICE" "ATTRIBUTION.md" "LICENSE-MIT" "LICENSE-APACHE"))
                   ("winprint-gdi-license"
                    "winprint.rs/417ac3c4d14d3da5485a99c7d5ce8f05664ec312"
                    "winprint.rs-417ac3c4d14d3da5485a99c7d5ce8f05664ec312/"
                    ("LICENSE.md")))))))
          (add-after 'install-git-notices 'create-launchers
            (lambda* (#:key inputs #:allow-other-keys)
              (use-modules (guix build utils) (ice-9 format) (srfi srfi-13))
              (let* ((out #$output)
                     (shell (search-input-file inputs "/bin/sh"))
                     (loader (search-input-file inputs "/lib/ld-linux-x86-64.so.2"))
                     (gcc-lib (search-input-file inputs "/lib/libgcc_s.so.1"))
                     (library-path
                      (string-join
                       (append
                        (list (dirname loader) (dirname gcc-lib))
                        (map (lambda (name)
                               (string-append (assoc-ref inputs name) "/lib"))
                             '("libx11" "libxcb" "libxcursor" "libxi"
                               "libxkbcommon" "mesa" "wayland"))) ":"))
                     (bin (string-append out "/bin")))
                (mkdir-p bin)
                (for-each
                 (lambda (name)
                   (let ((launcher (string-append bin "/" name))
                         (original (string-append out "/libexec/photocraft/" name)))
                     (unless (file-exists? original)
                       (error "official binary missing" name))
                     (call-with-output-file launcher
                       (lambda (port)
                         (format port
                                 (string-append "#!~a~%"
                                                "LD_LIBRARY_PATH=~a; "
                                                "export LD_LIBRARY_PATH~%"
                                                "exec ~a --library-path ~a ~a \"$@\"~%")
                                 shell library-path loader library-path original)))
                     (chmod launcher #o755)))
                 '("photocraft" "photocraft-cli")))))
          (add-after 'create-launchers 'smoke-cli
            (lambda _
              (invoke (string-append #$output "/bin/photocraft-cli") "--version")
              (invoke (string-append #$output "/bin/photocraft") "--version"))))))
    (supported-systems '("x86_64-linux"))
    (synopsis "PhotoCraft native image editor")
    (description
     "Official PhotoCraft 0.9.0 Linux binaries, repacked without modification
and installed with the upstream source and third-party license notices.  The
application source is MIT or Apache-2.0; ArtCraft brand assets use separate
non-free terms.")
    (home-page "https://github.com/storytold/photocraft")
    (license artcraft-license)))

