;; CodeMark v1 project=4c63e0fe-589c-4944-8449-97e211a38b72 file=e1866b9f6a5f5bc1b61c6ce79f80e651 owner="Cristian Cezar Mois\u00e9s"
;;; SoundCraft official Linux binaries, repackaged for SecurityOps.
;;; Upstream and third-party notices are installed under share/doc/soundcraft.
(define-module (securityops packages soundcraft)
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
  #:use-module (gnu packages linux)
  #:use-module (gnu packages xdisorg)
  #:use-module (gnu packages xorg))

(define artcraft-license
  (license "ArtCraft proprietary"
           "https://github.com/storytold/soundcraft"
           "Official upstream binary; source code is MIT or Apache-2.0 while the ArtCraft brand assets carry separate non-free terms."))

(define-public soundcraft
  (package
    (name "soundcraft")
    (version "0.5.0")
    (source
     (origin
       (method url-fetch)
       (uri (string-append
             "https://github.com/storytold/soundcraft/releases/download/v"
             version "/soundcraft-" version "-linux-x86_64.tar.gz"))
       (sha256
        (base32 "00z8c084lnjlgxg6mx6cd5kj7x1fcpgc0k880hr5df57gcd5nc5i"))))
    (build-system copy-build-system)
    (inputs
     `(("glibc" ,glibc)
       ("gcc:lib" ,gcc "lib")
       ("bash-minimal" ,bash-minimal)
       ("alsa-lib" ,alsa-lib)
       ("libx11" ,libx11)
       ("libxcb" ,libxcb)
       ("libxcursor" ,libxcursor)
       ("libxi" ,libxi)
       ("libxkbcommon" ,libxkbcommon)
       ("mesa" ,mesa)
       ("wayland" ,freedesktop:wayland)))
    (native-inputs
     (list
      (list "symphonia-source"
            (origin
              (method url-fetch)
              (uri "https://github.com/pdeljanov/Symphonia/archive/refs/tags/v0.5.5.tar.gz")
              (sha256
               (base32 "0h54mhsq4cd1pdwsdracyb1hrlwyp941rk5mnnw85wwy8lfqppn9"))))
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
      #~'(("bin/" "libexec/soundcraft/")
          ("share/" "share/"))
      #:phases
      #~(modify-phases %standard-phases
          (delete 'strip)
          (delete 'validate-runpath)
          (add-after 'install 'install-font-notices
            (lambda* (#:key inputs #:allow-other-keys)
              (use-modules (guix build utils))
              (let ((doc (string-append
                          #$output
                          "/share/doc/soundcraft/crates/epaint_default_fonts-0.36.2"))
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
                                        "/share/doc/soundcraft/accesskit"))
                    (notice (assoc-ref inputs "accesskit-chromium-notice")))
                (unless notice
                  (error "fixed AccessKit Chromium notice missing"))
                (mkdir-p doc)
                (copy-file notice (string-append doc "/LICENSE.chromium")))))
          (add-after 'install-chromium-notice 'install-symphonia-notices
            (lambda* (#:key inputs #:allow-other-keys)
              (use-modules (guix build utils))
              (let* ((doc (string-append #$output "/share/doc/soundcraft"))
                     (source (assoc-ref inputs "symphonia-source"))
                     (source-dir (string-append doc "/sources"))
                     (license-dir (string-append doc "/crates/symphonia-0.5.5")))
                (unless source
                  (error "fixed Symphonia source archive missing"))
                (mkdir-p source-dir)
                (mkdir-p license-dir)
                (copy-file source (string-append source-dir "/Symphonia-v0.5.5.tar.gz"))
                (invoke "tar" "-xzf" source "-C" license-dir
                        "--strip-components=1" "Symphonia-0.5.5/LICENSE")
                (call-with-output-file (string-append doc "/SOURCES.txt")
                  (lambda (port)
                    (display
                     (string-append
                      "SoundCraft 0.5.0 official upstream binary, repackaged with dependency source notices.\n"
                      "Symphonia 0.5.5 upstream tag source: "
                      "https://github.com/pdeljanov/Symphonia/archive/refs/tags/v0.5.5.tar.gz\n"
                      "Local copy: sources/Symphonia-v0.5.5.tar.gz\n"
                      "License: crates/symphonia-0.5.5/LICENSE\n"
                      "This upstream tag is not proof of exact official ELF provenance.\n")
                     port))))))
          (add-after 'install-symphonia-notices 'create-launchers
            (lambda* (#:key inputs #:allow-other-keys)
              (use-modules (guix build utils) (ice-9 format) (srfi srfi-13))
              (let* ((out #$output)
                     (shell (search-input-file inputs "/bin/sh"))
                     (loader (search-input-file inputs
                                                "/lib/ld-linux-x86-64.so.2"))
                     (gcc-lib (search-input-file inputs "/lib/libgcc_s.so.1"))
                     (alsa (search-input-file inputs "/lib/libasound.so.2"))
                     (library-path
                      (string-join
                       (append
                        (list (dirname loader) (dirname gcc-lib)
                              (dirname alsa))
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
                                    out "/libexec/soundcraft/" name)))
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
                 '("soundcraft" "soundcraft-cli")))))
          (add-after 'create-launchers 'smoke-versions
            (lambda _
              (invoke (string-append #$output "/bin/soundcraft") "--version")
              (invoke (string-append #$output "/bin/soundcraft-cli")
                      "--version"))))))
    (supported-systems '("x86_64-linux"))
    (synopsis "SoundCraft digital audio workstation")
    (description
     "Official SoundCraft 0.5.0 Linux binaries, repacked without modification
and installed with the upstream source and third-party license notices.  The
application source is MIT or Apache-2.0; ArtCraft brand assets use separate
non-free terms.")
    (home-page "https://github.com/storytold/soundcraft")
    (license artcraft-license)))
