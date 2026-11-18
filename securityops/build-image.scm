;; CodeMark v1 project=4c63e0fe-589c-4944-8449-97e211a38b72 file=2959bfef24bf5a68b3f5a0c768fa0da3 owner="Cristian Cezar Mois\u00e9s"
;; Internal build.sh entry.  repl -L preserves imports without exposing the
;; whole checkout (including out/cache) to recursive package discovery.
;; This is not a sandbox for explicitly imported Scheme or mutable sources.
(use-modules (gnu packages) (guix describe) (guix ui)
             (ice-9 match) (srfi srfi-1) (srfi srfi-13))

(define (canonical-directory? path)
  (and (string-prefix? "/" path)
       (not (string=? path "/"))
       (string=? path (canonicalize-path path))
       (eq? 'directory (stat:type (lstat path)))))

(define (resource-argument? argument)
  (any (lambda (prefix)
         (and (string-prefix? prefix argument)
              (let ((value (substring argument (string-length prefix))))
                (and (positive? (string-length value))
                     (char<=? #\1 (string-ref value 0) #\9)
                     (string-every (lambda (digit) (char<=? #\0 digit #\9))
                                   value)))))
       '("--max-jobs=" "--cores=")))

(match (cdr (command-line))
  ((root resources ...)
   (unless (and (canonical-directory? root)
                (canonical-directory? (string-append root "/securityops/packages"))
                (= 1 (count (lambda (path) (string=? path root)) %load-path))
                (every resource-argument? resources))
     (error "invalid image-build root or resources"))
   (let ((channels (append %default-package-module-path (package-path-entries))))
     (unless (equal? (%package-module-path) channels)
       (error "unexpected image-build discovery path"))
     (parameterize ((%package-module-path
                     (cons (cons root "securityops/packages") channels)))
       (apply run-guix
              (append '("system" "image") resources
                      (list "-t" "iso9660" "--label=SECURITY_OPS_LIVE"
                            "--substitute-urls=https://substitutes.securityops.com.br https://substitutes.securityops.co https://ci.guix.gnu.org"
                            "--fallback" (string-append root "/config.scm")))))))
  (_ (error "invalid image-build arguments")))
