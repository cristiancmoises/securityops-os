;; CodeMark v1 project=4c63e0fe-589c-4944-8449-97e211a38b72 file=f82127ee5c345b418d4ff92180d39505 owner="Cristian Cezar Mois\u00e9s"
;; Test-only dispatch boundary: execute discovery, but never build an OS.
(use-modules (gnu packages) (guix discovery) (guix packages) (guix ui))
(define args (cdr (command-line)))
(define mode (car args))
(define entry (cadr args))
(define root (caddr args))
(define forwarded (cdddr args))
(define image? (string-prefix? "image" mode))
(define expected
  (if image?
      (append '("system" "image") forwarded
              (list "-t" "iso9660" "--label=SECURITY_OPS_LIVE"
                    "--substitute-urls=https://substitutes.securityops.com.br https://substitutes.securityops.co https://ci.guix.gnu.org"
                    "--fallback" (string-append root "/config.scm")))
      forwarded))
(define original-path (%package-module-path))
(when (member mode '("unexpected-path" "image-unexpected-path"))
  (%package-module-path (cons root original-path)))
(when (string=? mode "image-duplicate-root")
  (set! %load-path (cons root %load-path)))
(module-set! (resolve-module '(guix ui)) 'run-guix
  (lambda actual
    (unless (equal? actual expected) (error "arguments changed"))
    (unless (equal? (%package-module-path)
                   (cons (cons root "securityops/packages") original-path))
      (error "channel order or discovery scope changed"))
    (let ((modules (all-modules (list (car (%package-module-path))))))
      (unless (equal? (map module-name modules)
                     '((securityops packages probe)))
        (error "unexpected discovery result"))
      (let ((package (module-ref (car modules) 'discovery-fixture)))
        (unless (and (package? package)
                     (string=? (package-name package) "discovery-fixture"))
          (error "local package resolution failed"))))
    (unless (= 42 (module-ref (resolve-interface '(securityops explicit)) 'value))
      (error "explicit import lost"))
    (display "DISPATCH_CHECKED\n")
    (when (member mode '("exit-7" "image-exit-7")) (exit 7))))
(set-program-arguments (cons entry (cons root forwarded)))
(primitive-load entry)
