;; CodeMark v1 project=4c63e0fe-589c-4944-8449-97e211a38b72 file=c3ebedc63b0a5c5aa6e9d2fb0faa47a8 owner="Cristian Cezar Mois\u00e9s"
;; Strict builder-side checking of the explicit Security Ops Kconfig policy.
;; Expected values are supplied by kernel.scm, not duplicated in this module.
(define-module (securityops kernel-config)
  #:use-module (ice-9 rdelim)
  #:use-module (ice-9 regex)
  #:use-module (srfi srfi-1)
  #:export (verify-required-kconfig))

(define (config-key line)
  ;; Whitespace is tolerated only to identify conflicting aliases. The full
  ;; line must still equal the canonical requested line, without normalization.
  (let ((match
         (or (string-match "^[ \t]*(CONFIG_[A-Za-z0-9_]+)[ \t]*=" line)
             (string-match
              "^[ \t]*#[ \t]*(CONFIG_[A-Za-z0-9_]+)[ \t]+is[ \t]+not[ \t]+set[ \t\r]*$"
              line))))
    (and match (match:substring match 1))))

(define (verify-required-kconfig file required)
  "Require exactly one literal value for every REQUIRED key in resolved FILE.
Missing disabled symbols are errors, unlike Guix verify-config. Unrelated
kernel defaults are allowed; this checks explicit policy, not the entire tree."
  (let* ((keys (map config-key required))
         (lines
          (call-with-input-file file
            (lambda (port)
              (let ((metadata (stat port)))
                (unless (and (eq? 'regular (stat:type metadata))
                             (<= (stat:size metadata) (* 4 1024 1024)))
                  (error "invalid or oversized resolved Kconfig")))
              (let loop ((lines '()) (bytes 0))
                (let ((line (read-line port)))
                  (if (eof-object? line)
                      (reverse lines)
                      (let ((size (+ bytes (string-length line) 1)))
                        (when (> size (* 4 1024 1024))
                          (error "resolved Kconfig grew beyond limit"))
                        (loop (cons line lines) size)))))))))
    (unless (and (pair? required) (every identity keys)
                 (= (length keys) (length (delete-duplicates keys))))
      (error "invalid or duplicate required Kconfig keys"))
    (for-each
     (lambda (expected key)
       (let ((matches (filter (lambda (line)
                                (equal? key (config-key line)))
                              lines)))
         (unless (equal? matches (list expected))
           (error "required Kconfig missing, conflicting, or mismatched" key))))
     required keys)
    (format #t "Security Ops Kconfig: ~a explicit values verified~%"
            (length required))
    #t))
