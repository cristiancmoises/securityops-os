;; CodeMark v1 project=4c63e0fe-589c-4944-8449-97e211a38b72 file=1038cbd96bb55385916883a9827ddcf1 owner="Cristian Cezar Mois\u00e9s"
;;; Compare the time-machine profile metadata with the admitted channel file.
;;; This is identity evidence, not an independent source-authority admission.
(use-modules (guix channels) (guix describe) (ice-9 match) (srfi srfi-1))

(define (identity channel)
  (let ((intro (channel-introduction channel)))
    (list (channel-name channel) (channel-url channel) (channel-branch channel)
          (channel-commit channel)
          (and intro
               (list (channel-introduction-first-signed-commit intro)
                     (channel-introduction-first-commit-signer intro))))))

(match (command-line)
  ((_ channels result)
   (unless (and (absolute-file-name? channels) (absolute-file-name? result))
     (error "PINNED_ARGUMENTS"))
   (let ((expected (load channels))
         (observed (current-channels)))
     (unless (and (pair? expected) (list? expected) (every channel? expected)
                  (equal? (map identity expected) (map identity observed)))
       (error "PINNED_CHANNEL_MISMATCH")))
   (let ((port (open result (logior O_WRONLY O_CREAT O_EXCL O_NOFOLLOW) #o600)))
     (display (canonicalize-path (current-profile)) port)
     (newline port)
     (close-port port)))
  (_ (error "PINNED_ARGUMENTS")))
