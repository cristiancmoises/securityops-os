;; CodeMark v1 project=4c63e0fe-589c-4944-8449-97e211a38b72 file=025226e8a1015209a1bdd9548540219a owner="Cristian Cezar Mois\u00e9s"
;;; DesignCraft official Linux binaries, repackaged for SecurityOps.
;;; Upstream and third-party notices are installed under share/doc/designcraft.
(define-module (securityops packages designcraft)
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
           "https://github.com/storytold/designcraft"
           "Official upstream binary; source code is MIT or Apache-2.0 while the ArtCraft brand assets carry separate non-free terms."))

(define-public designcraft
  (package
    (name "designcraft")
    (version "0.8.0")
    (source
     (origin
       (method url-fetch)
       (uri (string-append
             "https://github.com/storytold/designcraft/releases/download/v"
             version "/designcraft-" version "-linux-x86_64.tar.gz"))
       (sha256
        (base32 "0xrd6b588v6ak2cy2y4wlqii221g3cp6b4zcgl5rgxpbi7ykba4n"))))
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
      (list "source-docs"
            (origin
              (method url-fetch)
              (uri (string-append
                    "https://github.com/storytold/designcraft/archive/"
                    "refs/tags/v0.8.0.tar.gz"))
              (sha256
               (base32 "1a0y76g2si7fxj06z285xzaxaw529y8zfakxvjr8sv6x4xl94yz4"))))
      (list "foxit-license"
            (origin
              (method url-fetch)
              (uri (string-append
                    "https://raw.githubusercontent.com/storytold/pdfcraft/"
                    "b5467d93a0ffaa5e5e6658bccdf8655a3ba689c9/"
                    "vendor/hayro-interpret/assets/LICENSE_FOXIT"))
              (sha256
               (base32 "1dwq3jiv1cg1qz0z876jy7aj08w16fam24mxa2jssh2q6k9csy5m"))))
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
      #~'(("bin/" "libexec/designcraft/")
          ("share/" "share/"))
      #:phases
      #~(modify-phases %standard-phases
          (delete 'strip)
          (delete 'validate-runpath)
          (add-after 'install 'install-source-notices
            (lambda* (#:key inputs #:allow-other-keys)
              (use-modules (guix build utils))
              (let ((doc (string-append #$output "/share/doc/designcraft"))
                    (source-docs (assoc-ref inputs "source-docs"))
                    (foxit-license (assoc-ref inputs "foxit-license")))
                (unless (and source-docs foxit-license)
                  (error "fixed DesignCraft notices missing"))
                (mkdir-p doc)
                (invoke "tar" "-xzf" source-docs "-C" doc
                        "--strip-components=1"
                        "designcraft-0.8.0/NOTICE"
                        "designcraft-0.8.0/ASSETS.md"
                        "designcraft-0.8.0/LICENSE-MIT"
                        "designcraft-0.8.0/LICENSE-APACHE")
                (invoke "tar" "-xzf" source-docs "-C" doc
                        "--strip-components=3"
                        "designcraft-0.8.0/docs/brand/LICENSE-brand.txt"
                        "designcraft-0.8.0/assets/app-icon/LICENSE.txt"
                        "designcraft-0.8.0/assets/fonts/OFL-Inter.txt"
                        "designcraft-0.8.0/assets/fonts/OFL-JetBrainsMono.txt"
                        "designcraft-0.8.0/assets/fonts/OFL-SourceSans3.txt"
                        "designcraft-0.8.0/assets/fonts/OFL-SourceSerif4.txt")
                (copy-file foxit-license
                           (string-append doc "/LICENSE_FOXIT")))))
          (add-after 'install-source-notices 'install-chromium-notice
            (lambda* (#:key inputs #:allow-other-keys)
              (use-modules (guix build utils))
              (let ((doc (string-append #$output
                                        "/share/doc/designcraft/accesskit"))
                    (notice (assoc-ref inputs "accesskit-chromium-notice")))
                (unless notice
                  (error "fixed AccessKit Chromium notice missing"))
                (mkdir-p doc)
                (copy-file notice (string-append doc "/LICENSE.chromium")))))
          (add-after 'install-chromium-notice 'install-font-notices
            (lambda* (#:key inputs #:allow-other-keys)
              (use-modules (guix build utils))
              (let ((doc (string-append #$output
                                        "/share/doc/designcraft/crates/"
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
          (add-after 'install-font-notices 'create-launchers
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
                                             "ai.storyteller.designcraft.desktop")))
                (mkdir-p bin)
                (for-each
                 (lambda (name)
                   (let ((launcher (string-append bin "/" name))
                         (original (string-append out "/libexec/designcraft/" name)))
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
                 '("designcraft" "designcraft-cli"))
                (substitute* desktop
                  (("^Exec=designcraft %F$")
                   (string-append "Exec=" bin "/designcraft %F"))
                  (("^TryExec=designcraft$")
                   (string-append "TryExec=" bin "/designcraft"))))))
          (add-after 'create-launchers 'smoke-versions
            (lambda _
              (invoke (string-append #$output "/bin/designcraft") "--version")
              (invoke (string-append #$output "/bin/designcraft-cli")
                      "--version"))))))
    (supported-systems '("x86_64-linux"))
    (synopsis "DesignCraft page layout editor")
    (description
     "Official DesignCraft 0.8.0 Linux binaries, repacked without modification
and installed with the upstream source and third-party license notices.  The
application source is MIT or Apache-2.0; ArtCraft brand assets use separate
non-free terms.")
    (home-page "https://github.com/storytold/designcraft")
    (license artcraft-license)))
