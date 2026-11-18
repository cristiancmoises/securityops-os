;; CodeMark v1 project=4c63e0fe-589c-4944-8449-97e211a38b72 file=df91e96925e25b978fca121e538d355d owner="Cristian Cezar Mois\u00e9s"
;;; Exercise the recipe's real imported-module closure, not a kernel build.
(use-modules (guix packages) (guix gexp) (guix store) (guix derivations)
             (securityops kernel))

(define imports
  (apply (lambda* (#:key imported-modules #:allow-other-keys) imported-modules)
         (package-arguments linux-securityops)))
(define policy (@@ (securityops kernel) %securityops-kernel-configs))
(define probe
  (with-imported-modules imports
    #~(begin
        (use-modules (securityops kernel-config) (srfi srfi-1))
        ;; Only synthetic builder-local inputs. No checkout is on %load-path.
        (unless (string-prefix? "/gnu/store/"
                  (search-path %load-path "securityops/kernel-config.scm"))
          (error "guard source is not in the Store"))
        (define required '#$policy)
        (define (write-config lines)
          (call-with-output-file ".config"
            (lambda (port)
              (for-each (lambda (line) (display line port) (newline port)) lines))))
        (write-config required)
        (unless (verify-required-kconfig ".config" required)
          (error "valid synthetic config rejected"))
        (for-each
         (lambda (entry)
           (unless (member entry required) (error "critical requirement absent"))
           (write-config (delete entry required))
           (unless (catch #t
                     (lambda () (verify-required-kconfig ".config" required) #f)
                     (lambda _ #t))
             (error "missing critical requirement accepted")))
         '("CONFIG_HZ=1000" "# CONFIG_VFIO_NOIOMMU is not set"
           "CONFIG_IOMMU_DEFAULT_DMA_STRICT=y"))
        (call-with-output-file #$output
          (lambda (port) (display "positive=1\nnegative=3\n" port))))))

(with-store store
  (let ((drv (run-with-store store
               (gexp->derivation "securityops-kernel-guard-fixture" probe))))
    (unless (build-derivations store (list drv)) (error "guard fixture build failed"))
    (display (derivation->output-path drv)) (newline)))
