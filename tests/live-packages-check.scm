;; CodeMark v1 project=4c63e0fe-589c-4944-8449-97e211a38b72 file=1946873a32db525995521f122a820cf2 owner="Cristian Cezar Mois\u00e9s"
;; Evaluate actual OS package objects; never realize an image or launch apps.
(use-modules (gnu system) (gnu packages) (gnu packages xfce)
             (guix packages) (guix describe) (srfi srfi-1)
             (securityops packages guix-center) (securityops packages installer2)
             (guix base32) (guix download) (gnu packages rust)
             ((securityops packages tor) #:prefix sop-tor:)
             ((nongnu packages game-client) #:prefix nong:)
             ((securityops packages games) #:prefix games:))
(define root (cadr (command-line)))
(define configuration (caddr (command-line)))
(unless (and (string=? (package-version nong:heroic) "2.22.1")
             (string=? (package-version games:steam) "1.0.0.87"))
  (error "reviewed gaming package version changed"))
(unless (string=? (package-version sop-tor:torbrowser) "16.0.1")
  (error "reviewed SecurityOps Tor Browser version changed"))
(define (check-guixvis-origin source filename hash)
  (unless (and (origin? source)
               (eq? (origin-method source) url-fetch)
               (string=? (origin-uri source)
                         (string-append
                          "https://git.securityops.com.br/cristiancmoises/securityops-channel/raw/commit/017b9e3aa09bbafca341dfba7c91ca96211e8020/securityops/packages/sources/"
                          filename))
               (equal? (content-hash-value (origin-hash source))
                       (nix-base32-string->bytevector hash)))
    (error "guixvis origin is not the reviewed immutable archive" filename)))
(define (check-guixvis-package guixvis)
  (check-guixvis-origin
   (package-source guixvis) "guixvis-0.8.0-src.tar"
   "0ladbkqzy8i4c8r6nnb4c2hfsry545phb3bpr6nljl9497valjzn")
  (check-guixvis-origin
   (cadr (assoc "vendor" (package-native-inputs guixvis)))
   "guixvis-0.1.0-vendor.tar.gz"
   "10z198li476x3zs829k85ngyq3rllikqnzbd3ldzg5x8qvnc1cky")
  (unless (and (eq? (cadr (assoc "rust" (package-native-inputs guixvis))) rust)
               (equal? (cdr (assoc "rust:cargo" (package-native-inputs guixvis)))
                       (list rust "cargo"))
               (string=? (package-version rust) "1.98.1"))
    (error "guixvis compiler is not the reviewed pinned Rust/Cargo")))
(parameterize ((%package-module-path
                (cons (cons root "securityops/packages")
                      (append %default-package-module-path (package-path-entries)))))
  (let* ((os (load configuration))
         (packages (operating-system-packages os))
         ;; Import the oracle's provider only AFTER real configuration loading,
         ;; so a prior import cannot hide missing package discovery.
         (guixvis (module-ref (resolve-interface '(securityops packages guixvis))
                              'guixvis)))
    (check-guixvis-package guixvis)
    (for-each
     (lambda (expected)
       (let ((matches
              (filter (lambda (item)
                        (string=? (package-name (if (pair? item) (car item) item))
                                  (package-name expected))) packages)))
         (unless (and (= 1 (length matches))
                      (eq? (if (pair? (car matches)) (caar matches) (car matches))
                           expected)
                      (or (package? (car matches))
                          (equal? (cdar matches) '("out"))))
           (error "reviewed package missing, shadowed or duplicated"
                  (package-name expected)))
         (format #t "SELECTED ~a ~a~%" (package-name expected) (package-version expected))))
     (list thunar securityops-guix-center security-ops-installer2
           nong:heroic games:steam sop-tor:torbrowser guixvis))
    (display "PACKAGE_SELECTION_OK\n")))
