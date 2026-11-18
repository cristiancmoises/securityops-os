;; CodeMark v1 project=4c63e0fe-589c-4944-8449-97e211a38b72 file=3227e7f21af85fdfb103e8f0f2cd947c owner="Cristian Cezar Mois\u00e9s"
;;; SPDX-License-Identifier: GPL-3.0-or-later
;;; Copyright © 2026 Cristian Cezar Moisés <ethicalhacker@riseup.net>
;;;
;;; Maltego Graph (Desktop) — official Linux distribution repacked for Guix.

(define-module (securityops packages maltego)
  #:use-module (guix packages)
  #:use-module (guix download)
  #:use-module (guix gexp)
  #:use-module (guix build-system copy)
  #:use-module ((guix licenses) #:prefix license:)
  #:use-module (gnu packages base)
  #:use-module (gnu packages bash)
  #:use-module (gnu packages compression)
  #:use-module (gnu packages gawk)
  #:use-module (gnu packages java))

(define maltego-license
  (license:license "Maltego proprietary EULA"
                   "https://www.maltego.com/eula/"
                   "Official Maltego Graph binary; Maltego Technologies GmbH owns the product and brand."))

(define-public maltego
  (package
    (name "maltego")
    (version "4.14.0")
    (source
     (origin
       (method url-fetch)
       (uri (string-append
             "https://downloads.maltego.com/maltego-v4/linux/"
             "Maltego.v" version ".linux.zip"))
       (sha256
        (base32 "02qhcb7znzaqrxy832mfkif6cys0s767j2xcyf0328bynbgrn9jg"))))
    (build-system copy-build-system)
    (arguments
     (list
      #:install-plan
      #~'(("./" "share/maltego/"))
      #:phases
      #~(modify-phases %standard-phases
          (delete 'strip)
          (delete 'validate-runpath)
          (add-after 'install 'install-packaging-notice
            (lambda _
              (let ((doc (string-append #$output "/share/doc/maltego")))
                (mkdir-p doc)
                (call-with-output-file
                    (string-append doc "/PACKAGING-NOTICE")
                  (lambda (port)
                    (display
                     "Guix packaging notes for Maltego Graph 4.14.0

This package installs the official Maltego.v4.14.0.linux.zip distribution
without rebuilding it.  It adds this notice and a launcher that runs the
upstream application with the OpenJDK 21 runtime from Guix.

Upstream: https://downloads.maltego.com/maltego-v4/info.json
License: https://www.maltego.com/eula/
Maltego Technologies GmbH owns the Maltego product and brand.
"
                     port))))))
          (add-after 'install-packaging-notice 'create-launcher
            (lambda* (#:key inputs #:allow-other-keys)
              (use-modules (guix build utils) (ice-9 format))
              (let* ((out #$output)
                     (java (search-input-file inputs "/bin/java"))
                     (bash (search-input-file inputs "/bin/bash"))
                     (awk (search-input-file inputs "/bin/awk"))
                     (java-bin (dirname java))
                     (java-home (dirname java-bin))
                     (app-dir (string-append out "/share/maltego"))
                     (bin (string-append out "/bin"))
                     (launcher (string-append bin "/maltego")))
                ;; The upstream launcher hard-codes /usr/bin/awk, which does
                ;; not exist on Guix System.  Point it at gawk instead.
                (substitute* (string-append app-dir "/bin/maltego")
                  (("/usr/bin/awk") awk))
                (mkdir-p bin)
                (call-with-output-file launcher
                  (lambda (port)
                    (format port
                            "#!~a~%export JAVA_HOME=~a~%export PATH=~a:~a:~a:$PATH~%conf=\"$HOME/.maltego/v4.14.0/etc/maltego.conf\"~%if [ ! -f \"$conf\" ]; then~%  mkdir -p \"$(dirname \"$conf\")\"~%  printf 'jdkhome=\"%s\"\\n' \"$JAVA_HOME\" > \"$conf\"~%fi~%exec ~a/bin/maltego \"$@\"~%"
                            bash java-home java-bin (dirname bash)
                            (dirname awk) app-dir)))
                (chmod launcher #o755))))
          (add-after 'create-launcher 'check-package
            (lambda _
              (unless (and (file-exists?
                            (string-append #$output "/bin/maltego"))
                           (access?
                            (string-append #$output "/bin/maltego")
                            X_OK)
                           (file-exists?
                            (string-append
                             #$output
                             "/share/maltego/bin/maltego")))
                (error "Maltego launcher or upstream binary is missing")))))))
    (native-inputs (list unzip))
    (inputs (list openjdk21 bash-minimal gawk coreutils))
    (supported-systems '("x86_64-linux"))
    (home-page "https://www.maltego.com")
    (synopsis "Interactive data mining and link analysis tool")
    (description
     "Maltego Graph is an interactive data mining tool that renders directed
graphs for link analysis.  This package installs the official Maltego Graph
Linux distribution with a Guix launcher that supplies the OpenJDK 21 runtime.")
    (license maltego-license)))
