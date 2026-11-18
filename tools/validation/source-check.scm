;; CodeMark v1 project=4c63e0fe-589c-4944-8449-97e211a38b72 file=7f37a1fd2d395be6afd96368f7393ed2 owner="Cristian Cezar Mois\u00e9s"
;; Enumerate with the ISO's actual selector; never dereference directory links.
(use-modules (securityops source-selection) (ice-9 ftw) (json))
(define root (cadr (command-line)))
(define prefix-length (+ 1 (string-length root)))
(define (keep path metadata result)
  (or (string=? path root) (securityops-source-file? path metadata)))
(define (leaf path metadata result)
  (if (securityops-source-file? path metadata)
      (begin
        (when (>= (length result) 4096) (error "inventory limit"))
        (cons (substring path prefix-length) result))
      result))
(define (unchanged path metadata result) result)
(define files
  (file-system-fold keep leaf unchanged unchanged unchanged
                    (lambda args (error "source traversal failed")) '() root lstat))
(scm->json (list->vector (sort files string<?)))
(newline)
