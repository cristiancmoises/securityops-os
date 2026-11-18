;; CodeMark v1 project=4c63e0fe-589c-4944-8449-97e211a38b72 file=ea24e02ddb0e5a3680d5c63498781832 owner="Cristian Cezar Mois\u00e9s"
;;; Security Ops OS -- per-boot live credential provisioning
;;; SPDX-License-Identifier: AGPL-3.0-or-later

(define-module (securityops services live-credentials)
  #:use-module (gnu packages admin)
  #:use-module (gnu services shepherd)
  #:use-module (guix gexp)
  #:export (%securityops-live-credential-file
            securityops-live-credential-program
            securityops-live-credential-service))

;; This root-only recovery copy lives on the volatile /run tmpfs.  It is never
;; a file-like object and therefore can never be copied to /gnu/store by the
;; service declaration.  The password is shown only on the physical VT1 trusted
;; path; ordinary users and applications cannot read this file.
(define %securityops-live-credential-file
  "/run/securityops/live-console-credential")

(define* (securityops-live-credential-program #:optional
                                               (user "securityops"))
  "Return a root-only boot program that assigns USER a fresh local-console
password.  The password travels only through an anonymous pipe to chpasswd and
the physical VT1 trusted path.  A root-only volatile copy supports recovery."
  (program-file
   "provision-securityops-live-credential"
   #~(begin
       ;; Keep runtime imports inside Guile's own closure.  Importing
       ;; (guix build utils) here works in a developer checkout but is absent
       ;; from the minimal program-file closure on the live image, causing the
       ;; credential service—and therefore greetd—to fail before provisioning.
       (use-modules (ice-9 binary-ports)
                    (ice-9 popen)
                    (ice-9 textual-ports))

       (define runtime-directory "/run/securityops")
       (define credential-file #$%securityops-live-credential-file)
       (define alphabet
         "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789")

       (define (fresh-password)
         ;; Rejection sampling avoids modulo bias because the alphabet length
         ;; does not divide 256.  EOF from /dev/urandom is a fatal boot error.
         (let ((port (open-file "/dev/urandom" "rb"))
               (limit (* (quotient 256 (string-length alphabet))
                         (string-length alphabet))))
           (let loop ((characters '()))
             (if (= (length characters) 24)
                 (begin
                   (close-port port)
                   (list->string (reverse characters)))
                 (let ((byte (get-u8 port)))
                   (when (eof-object? byte)
                     (error "could not obtain a complete live credential"))
                   (if (< byte limit)
                       (loop
                        (cons (string-ref alphabet
                                          (modulo byte
                                                  (string-length alphabet)))
                              characters))
                       (loop characters)))))))

       (define (safe-runtime-directory)
         (when (false-if-exception (lstat runtime-directory))
           (when (eq? 'symlink (stat:type (lstat runtime-directory)))
             (error "refusing symlink live-credential directory")))
         (unless (file-exists? runtime-directory)
           (mkdir runtime-directory #o750))
         (unless (eq? 'directory (stat:type (lstat runtime-directory)))
           (error "live-credential runtime path is not a directory"))
         (chown runtime-directory 0 0)
         (chmod runtime-directory #o700))

       (define (display-on-trusted-console password)
         ;; Do not use /dev/console: it may be redirected to a serial capture or
         ;; persistent log.  VT1 is the local trusted recovery path; greetd runs
         ;; on VT7 and directs the operator here.
         (let ((terminal "/dev/tty1"))
           (unless (and (file-exists? terminal)
                        (eq? 'char-special (stat:type (stat terminal))))
             (error "trusted local VT1 is unavailable"))
           (call-with-output-file terminal
             (lambda (port)
               (display "\nSecurity Ops OS live-console credential\n" port)
               (display "  user: securityops\n  one-boot password: " port)
               (display password port)
               (display "\nReturn to the login screen with Ctrl+Alt+F7.\n\n"
                        port)
               (force-output port)))))

       (define (set-password password)
         (let ((pipe (open-pipe* OPEN_WRITE
                                 #$(file-append shadow "/sbin/chpasswd"))))
           (display #$user pipe)
           (display ":" pipe)
           (display password pipe)
           (newline pipe)
           (force-output pipe)
           (let ((status (close-pipe pipe)))
             (unless (zero? (status:exit-val status))
               (error "chpasswd rejected the per-boot live credential")))))

       (let ((password (fresh-password)))
         (safe-runtime-directory)
         (when (false-if-exception (lstat credential-file))
           (error "refusing to replace an existing live credential"))
         ;; chpasswd hashes the value into the volatile live /etc/shadow.  It
         ;; receives the plaintext on stdin, never argv or the environment.
         (set-password password)
         (call-with-output-file credential-file
           (lambda (port)
             (display password port)
             (newline port)))
         (chown credential-file 0 0)
         (chmod credential-file #o400)
         (display-on-trusted-console password)
         ;; Do not print or log PASSWORD outside the dedicated physical VT.
         (set! password #f)))))

(define* (securityops-live-credential-service #:optional
                                               (user "securityops"))
  "Provision one fresh live-console credential before the greeter starts."
  (let ((provisioner (securityops-live-credential-program user)))
    (shepherd-service
     (provision '(securityops-live-credential))
     (requirement '(user-processes))
     (one-shot? #t)
     (documentation
      "Generate the non-reusable Security Ops OS live-console credential.")
     ;; An asynchronous process constructor reports the child PID before chpasswd and the
     ;; trusted-console write complete.  Wait synchronously so greetd's service
     ;; requirement is a real postcondition, not a race-prone spawn event.
     (start #~(lambda _
                (let ((status (system* #$provisioner)))
                  (and (zero? status) #t))))
     (stop #~(lambda _ #t)))))
