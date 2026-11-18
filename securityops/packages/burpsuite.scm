;; CodeMark v1 project=4c63e0fe-589c-4944-8449-97e211a38b72 file=9c2463b78df8577dbe5ab1991b0513ef owner="Cristian Cezar Mois\u00e9s"
;;; SPDX-License-Identifier: GPL-3.0-or-later
;;; Copyright © 2026 Cristian Cezar Moisés <ethicalhacker@riseup.net>

;;; Burp Suite Community Edition, repackaged from the official Linux JAR.
;;; The unmodified JAR lives under libexec/burpsuite and is launched with
;;; OpenJDK 21, preserving the PortSwigger EULA under share/doc/burpsuite.
(define-module (securityops packages burpsuite)
  #:use-module (guix packages)
  #:use-module (guix licenses)
  #:use-module (guix download)
  #:use-module (guix gexp)
  #:use-module (guix build-system copy)
  #:use-module (gnu packages base)
  #:use-module (gnu packages bash)
  #:use-module (gnu packages cups)
  #:use-module (gnu packages gcc)
  #:use-module (gnu packages gl)
  #:use-module (gnu packages glib)
  #:use-module (gnu packages gtk)
  #:use-module (gnu packages java)
  #:use-module (gnu packages linux)
  #:use-module (gnu packages nss)
  #:use-module ((gnu packages xml) #:prefix xml:)
  #:use-module (gnu packages xdisorg)
  #:use-module (gnu packages xorg))

(define burpsuite-license
  (license "PortSwigger End-User License Agreement"
           "https://portswigger.net/burp/eula"
           "Official upstream binary; Community Edition terms apply."))

(define-public burpsuite
  (package
    (name "burpsuite")
    (version "2026.10.1")
    (source
     (origin
       (method url-fetch)
       (uri (string-append
             "https://portswigger.net/burp/releases/download"
             "?product=desktop&version=" version "&type=Jar"))
       (file-name (string-append "burpsuite-" version ".jar"))
       (sha256
        (base32 "1if30rjwg7jwgiwq0ln8w2xah21ydhmgrlh9ra8knr5i6xjhiaz8"))))
    (build-system copy-build-system)
    (inputs
     (list alsa-lib
           at-spi2-core
           bash-minimal
           cairo
           cups
           dbus
           eudev
           xml:expat
           glib
           libx11
           libxcb
           libxcomposite
           libxdamage
           libxext
           libxfixes
           libxkbcommon
           libxrandr
           mesa
           nspr
           nss
           pango
           `(,gcc "lib")
           `(,openjdk21 "jdk")))
    (arguments
     (list
      #:install-plan
      #~'(("burpsuite-2026.10.1.jar" "libexec/burpsuite/burpsuite.jar"))
      #:phases
      #~(modify-phases %standard-phases
          (delete 'strip)
          (delete 'validate-runpath)
          (add-after 'install 'install-notices
            (lambda _
              (use-modules (guix build utils))
              (let ((doc (string-append #$output
                                        "/share/doc/burpsuite")))
                (mkdir-p doc)
                (call-with-output-file (string-append doc "/NOTICE.txt")
                  (lambda (port)
                    (display
                     (string-append
                      "Burp Suite Community Edition 2026.10.1\n"
                      "Official upstream JAR, repacked without modification.\n"
                      "Copyright (c) PortSwigger Ltd.\n"
                      "License: " "https://portswigger.net/burp/eula\n")
                     port))))))
          (add-after 'install-notices 'create-launcher
            (lambda* (#:key inputs #:allow-other-keys)
              (use-modules (guix build utils) (ice-9 format)
                           (srfi srfi-1))
              (let* ((out #$output)
                     (java (search-input-file inputs "/bin/java"))
                     (shell (search-input-file inputs "/bin/sh"))
                     (jar (string-append out
                                         "/libexec/burpsuite/"
                                         "burpsuite.jar"))
                     (anchors
                      '("libglib-2.0.so.0"
                        "libnspr4.so"
                        "libatk-1.0.so.0"
                        "libdbus-1.so.3"
                        "libcups.so.2"
                        "libexpat.so.1"
                        "libxcb.so.1"
                        "libxkbcommon.so.0"
                        "libasound.so.2"
                        "libgbm.so.1"
                        "libX11.so.6"
                        "libXext.so.6"
                        "libXcomposite.so.1"
                        "libXdamage.so.1"
                        "libXfixes.so.3"
                        "libXrandr.so.2"
                        "libcairo.so.2"
                        "libpango-1.0.so.0"
                        "libudev.so.1"
                        "libgcc_s.so.1"))
                     (libdirs
                      (delete-duplicates
                       (map (lambda (file)
                              (dirname
                               (search-input-file inputs
                                                  (string-append "/lib/" file))))
                            anchors)))
                     (nssdir
                      (dirname (search-input-file inputs
                                                  "/lib/nss/libnss3.so")))
                     (ld-library-path
                      (string-join (append libdirs (list nssdir)) ":"))
                     (bin (string-append out "/bin"))
                     (launcher (string-append bin "/burpsuite")))
                (mkdir-p bin)
                (call-with-output-file launcher
                  (lambda (port)
                    (format port
                            (string-append
                             "#!~a~%"
                             "export LD_LIBRARY_PATH=~a${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}~%"
                             "exec \"~a\" "
                             "--add-opens=java.desktop/javax.swing=ALL-UNNAMED "
                             "--add-opens=java.base/java.lang=ALL-UNNAMED "
                             "-jar \"~a\" \"$@\"~%")
                            shell ld-library-path java jar)))
                (chmod launcher #o755)))))))
    (supported-systems '("x86_64-linux"))
    (synopsis "Burp Suite Community Edition web security testing toolkit")
    (description
     "Burp Suite Community Edition is PortSwigger's free web security testing
toolkit, repackaged here from the official Linux JAR and launched with OpenJDK
21.  The PortSwigger EULA is installed under @file{share/doc/burpsuite}.")
    (home-page "https://portswigger.net/burp/communitydownload")
    (license burpsuite-license)))
