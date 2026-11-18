;;; branding.scm --- Security Ops OS distribution identity -*- scheme -*-
;; CodeMark v1 project=4c63e0fe-589c-4944-8449-97e211a38b72 file=c75a661dce6a5c7c88aa1c7f674de768 owner="Cristian Cezar Mois\u00e9s"
;;;
;;; Copyright (C) 2026 Cristian Cezar Moisés
;;; SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-SecurityOps-Commercial
;;;
;;; This module provides the distribution-owned identity files and the
;;; source-built Coreutils variant used by Security Ops OS.  The Coreutils
;;; source and resulting binaries remain GPL-3.0-or-later; the Security Ops
;;; dual-license does not relicense third-party GNU software.

(define-module (securityops branding)
  #:use-module (gnu packages base)
  #:use-module (gnu services)
  #:use-module (gnu services base)
  #:use-module (gnu system)
  #:use-module (guix gexp)
  #:use-module (guix packages)
  #:use-module (guix utils)
  #:use-module (srfi srfi-1)
  #:use-module (securityops settings)
  #:export (%securityops-uname-operating-system
            %securityops-os-release-text
            %securityops-os-release
            %securityops-issue
            securityops-coreutils
            securityops-operating-system-essential-services))

;; GNU Coreutils' -o/--operating-system option is a GNU extension, separate
;; from the kernel fields returned by uname(2).  Brand only that field.  The
;; default invocation and -s continue to report "Linux", -r continues to
;; report the real kernel release, and -m continues to report the real machine.
(define %securityops-uname-operating-system
  "Security Ops OS")

(define securityops-coreutils
  (package
    (inherit coreutils)
    ;; Keep the package name identical so the curated profile's deterministic
    ;; de-duplication replaces, rather than collides with, %base-packages'
    ;; unmodified Coreutils output.
    (name "coreutils")
    (arguments
     (substitute-keyword-arguments (package-arguments coreutils)
       ((#:phases phases #~%standard-phases)
        #~(modify-phases #$phases
            (add-after 'unpack 'brand-uname-operating-system
              (lambda _
                (use-modules (ice-9 textual-ports))
                (let* ((file "src/uname.c")
                       (needle "print_element (HOST_OPERATING_SYSTEM);")
                       (replacement
                        #$(string-append
                           "print_element (\""
                           %securityops-uname-operating-system
                           "\");"))
                       (source (call-with-input-file file get-string-all)))
                  ;; Fail closed when an upstream update changes this code.
                  ;; A silent no-op would put misleading Guix branding back in
                  ;; the release while appearing to build successfully.
                  (unless (string-contains source needle)
                    (error "Coreutils uname branding anchor changed" file))
                  (substitute* file
                    (("print_element \\(HOST_OPERATING_SYSTEM\\);")
                     replacement)))))
            (add-after 'unpack 'skip-deep-path-tests
              (lambda _
                ;; Two upstream Coreutils tests construct a 52-level
                ;; hierarchy of 200-byte directory names.  This build
                ;; container resolves paths only to about 8 KiB, so both
                ;; tests fail at set-up with ENAMETOOLONG before exercising
                ;; Coreutils.  They pass on ordinary filesystems; skip them
                ;; here so the rest of the suite still runs.
                (for-each
                 (lambda (file)
                   (substitute* file
                     (("require_perl_")
                      "require_perl_\nskip_ 'container path-depth limit prevents this test setup'\n")))
                 '("tests/rm/deep-2.sh"
                   "tests/du/long-from-unreadable.sh"))))
            (add-after 'build 'check-securityops-uname-identity
              (lambda _
                (use-modules (ice-9 popen)
                             (ice-9 textual-ports)
                             (srfi srfi-13))
                (define (capture . arguments)
                  (let* ((port (apply open-pipe* OPEN_READ
                                      "./src/uname" arguments))
                         (output (get-string-all port))
                         (status (close-pipe port)))
                    (unless (zero? (status:exit-val status))
                      (error "built uname failed" arguments status))
                    (string-trim-right output)))
                (let ((kernel-name (capture "-s"))
                      (default-name (capture))
                      (operating-system (capture "-o"))
                      (all-fields (capture "-a"))
                      (expected #$%securityops-uname-operating-system))
                  (unless (string=? default-name kernel-name)
                    (error "uname default kernel semantics changed"
                           default-name kernel-name))
                  (unless (string=? operating-system expected)
                    (error "uname -o is not branded"
                           operating-system expected))
                  (unless (string-suffix? expected all-fields)
                    (error "uname -a does not carry the OS identity"
                           all-fields expected)))))))))
    (synopsis "GNU Coreutils with truthful Security Ops OS uname identity")
    (description
     "This is GNU Coreutils with one distribution patch: the GNU-specific
@command{uname -o} field identifies Security Ops OS.  Kernel and hardware
fields retain their upstream semantics, and the upstream Coreutils test suite
is retained except two deep-path tests that are skipped in this build
environment.  GNU/Linux and Guix provenance is recorded separately in the
distribution identity files.")
    ;; Inherited from Coreutils.  This deliberately remains GPL-3.0-or-later.
    (license (package-license coreutils))))

(define %securityops-os-release-text
  (string-append
   "NAME=\"Security Ops OS\"\n"
   "ID=securityops\n"
   "ID_LIKE=guix\n"
   "PRETTY_NAME=\"Security Ops OS " %release-version "\"\n"
   "VERSION=\"" %release-version " (" %build-revision ")\"\n"
   "VERSION_ID=\"" %release-version "\"\n"
   "BUILD_ID=\"" %build-revision "\"\n"
   "ANSI_COLOR=\"0;36\"\n"
   "HOME_URL=\"https://securityops.co\"\n"
   "DOCUMENTATION_URL=\"https://git.securityops.co/cristiancmoises/securityops-os\"\n"
   "SUPPORT_URL=\"https://git.securityops.co/cristiancmoises/securityops-os/issues\"\n"
   "BUG_REPORT_URL=\"https://git.securityops.co/cristiancmoises/securityops-os/issues\"\n"
   ;; Namespaced extension fields preserve the implementation provenance for
   ;; support tools without presenting Guix System as the distribution name.
   "SECURITYOPS_SYSTEM_MANAGER=\"GNU Guix\"\n"
   "SECURITYOPS_KERNEL=\"Linux\"\n"))

(define %securityops-os-release
  (plain-file "securityops-os-release" %securityops-os-release-text))

(define %securityops-issue
  (string-append
   "\nSecurity Ops OS " %release-version " (" %build-revision ")\n"
   "GNU/Linux with declarative GNU Guix system management.\n"))

(define (replace-os-release entries)
  (unless (= 1 (count (lambda (entry)
                       (string=? (car entry) "os-release"))
                     entries))
    (error "expected exactly one base /etc/os-release entry"))
  (map (lambda (entry)
         (if (string=? (car entry) "os-release")
             (list "os-release" %securityops-os-release)
             entry))
       entries))

(define (securityops-operating-system-essential-services os)
  "Return OS's normal essential services with only /etc/os-release replaced.

This uses the public operating-system service API rather than activation-time
mutation or a writable-file race.  It deliberately leaves Guix's other
essential services unchanged."
  (let ((services (operating-system-default-essential-services os)))
    (unless (= 1 (count (lambda (service)
                         (eq? (service-kind service) etc-service-type))
                       services))
      (error "expected exactly one essential etc service"))
    (map (lambda (item)
           (if (eq? (service-kind item) etc-service-type)
               (service etc-service-type
                        (replace-os-release (service-value item)))
               item))
         services)))
