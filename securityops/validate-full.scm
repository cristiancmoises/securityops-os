;; CodeMark v1 project=4c63e0fe-589c-4944-8449-97e211a38b72 file=ce35c3e8ad7751528af85c1303c61942 owner="Cristian Cezar Mois\u00e9s"
;; Internal entry for securityopsctl validate --full, run by pinned guix repl.
;; repl -L changes imports, unlike build -L which also discovers packages
;; recursively.  Never expose the checkout root to package enumeration.
;; This is a discovery boundary, NOT a sandbox for explicitly imported Scheme.
(use-modules (gnu packages) (guix describe) (guix ui)
             (ice-9 match) (srfi srfi-1))

(define %validation-substitutes
  "--substitute-urls=https://substitutes.securityops.com.br https://substitutes.securityops.co https://ci.guix.gnu.org")

(define (canonical-directory? path)
  (and (string-prefix? "/" path)
       (not (string=? path "/"))
       (string=? path (canonicalize-path path))
       (eq? 'directory (stat:type (lstat path)))))

(define (private-installer-config? path)
  (and (string-prefix? "/" path)
       (string=? (basename path) "installer-config.scm")
       (string=? path (canonicalize-path path))
       (let ((file (lstat path)) (directory (lstat (dirname path))))
         (and (eq? 'regular (stat:type file))
              (= 1 (stat:nlink file))
              (= (getuid) (stat:uid file) (stat:uid directory))
              (= #o600 (stat:perms file))
              (= #o700 (stat:perms directory))))))

(define (validation-command? root command)
  (let ((common (list "--dry-run" %validation-substitutes "--fallback")))
    (or (equal? command
                (append '("build") common
                        '("-e" "(@ (securityops kernel) linux-securityops)")))
        (equal? command
                (append '("system" "image") common
                        (list "-t" "iso9660" "--label=SECURITY_OPS_LIVE"
                              (string-append root "/config.scm"))))
        (match command
          (("system" "build" "--dry-run" substitutes "--fallback" config)
           (and (string=? substitutes %validation-substitutes)
                (private-installer-config? config)))
          (_ #f)))))

(match (cdr (command-line))
  ((root command ...)
   (unless (and (canonical-directory? root)
                (canonical-directory? (string-append root "/securityops/packages"))
                (= 1 (count (lambda (path) (string=? path root)) %load-path))
                (validation-command? root command))
     (error "invalid full-validation root or command"))
   (let ((channels (append %default-package-module-path (package-path-entries))))
     ;; An unexpected entry must not survive as an alternate route into out/.
     (unless (equal? (%package-module-path) channels)
       (error "unexpected full-validation discovery path"))
     (parameterize ((%package-module-path
                     (cons (cons root "securityops/packages") channels)))
       (apply run-guix command))))
  (_ (error "invalid full-validation arguments")))
