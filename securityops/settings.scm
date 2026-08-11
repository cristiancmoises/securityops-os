;;; settings.scm --- validated maintainer settings for Security Ops OS -*- scheme -*-
;;;
;;; This module is the Guix-facing adapter for settings.json.  Maintainers use
;;; ./securityopsctl rather than editing this module.  Keeping mutable data in
;;; JSON lets the CLI update one file atomically while Guix still receives
;;; ordinary Scheme values from a stable, reviewable module.

(define-module (securityops settings)
  #:use-module (json)
  #:use-module (srfi srfi-1)
  #:use-module (srfi srfi-13)
  #:export (%release-version
            %build-revision
            %desktop-label
            %kernel-version
            %kernel-url
            %kernel-nix-base32
            %kernel-sha256
            %package-additions
            %package-removals))

(define (settings-error message . arguments)
  (error (apply format #f
                (string-append "securityops/settings.json: " message)
                arguments)))

(define (object-ref object key context)
  (unless (and (list? object) (every pair? object))
    (settings-error "~a must be a JSON object" context))
  (let ((entry (assoc key object)))
    (unless entry
      (settings-error "~a is missing key ~s" context key))
    (cdr entry)))

(define (validate-object-keys object expected context)
  (unless (and (list? object) (every pair? object))
    (settings-error "~a must be a JSON object" context))
  (let ((actual (map car object)))
    (unless (and (= (length actual) (length expected))
                 (every (lambda (key) (member key actual string=?)) expected))
      (settings-error "~a must contain exactly these keys: ~s"
                      context expected))))

(define (required-string object key context maximum)
  (let ((value (object-ref object key context)))
    (unless (and (string? value)
                 (<= 1 (string-length value) maximum)
                 (string-every
                  (lambda (character)
                    (let ((code (char->integer character)))
                      (and (>= code 32) (not (= code 127)))))
                  value))
      (settings-error
       "~a.~a must be a non-empty control-free string of at most ~a characters"
       context key maximum))
    value))

(define (ascii-digit? character)
  (char<=? #\0 character #\9))

(define (ascii-letter? character)
  (or (char<=? #\a character #\z)
      (char<=? #\A character #\Z)))

(define (canonical-decimal? value allow-zero?)
  (and (not (string-null? value))
       (string-every ascii-digit? value)
       (if allow-zero?
           (or (string=? value "0")
               (not (char=? (string-ref value 0) #\0)))
           (not (char=? (string-ref value 0) #\0)))))

(define (stable-version? value)
  (let ((parts (string-split value #\.)))
    (and (= (length parts) 3)
         (canonical-decimal? (list-ref parts 0) #f)
         (canonical-decimal? (list-ref parts 1) #t)
         (canonical-decimal? (list-ref parts 2) #t))))

(define (package-name? value)
  (and (string? value)
       (<= 1 (string-length value) 128)
       (let ((first (string-ref value 0)))
         (or (ascii-letter? first) (ascii-digit? first)))
       (string-every
        (lambda (character)
          (or (ascii-letter? character)
              (ascii-digit? character)
              (memv character '(#\+ #\- #\. #\_))))
        value)))

(define (package-suffix? value)
  (and (package-name? value) (<= (string-length value) 64)))

(define (package-specification-base value)
  (let ((at (string-index value #\@))
        (colon (string-index value #\:)))
    (substring value 0
               (cond ((and at colon) (min at colon))
                     (at at)
                     (colon colon)
                     (else (string-length value))))))

(define (package-specification-output value)
  (let ((colon (string-index value #\:)))
    (if colon (substring value (+ colon 1)) "out")))

(define (package-specification-key value)
  (string-append (package-specification-base value) ":"
                 (package-specification-output value)))

(define (package-specification? value)
  (and (string? value)
       (<= 1 (string-length value) 258)
       (let* ((at (string-index value #\@))
              (colon (string-index value #\:))
              (base (package-specification-base value))
              (version (and at (or (not colon) (< at colon))
                            (substring value (+ at 1)
                                       (or colon (string-length value)))))
              (output (and colon
                           (substring value (+ colon 1)))))
         (and (package-name? base)
              (or (not at) (and version (package-suffix? version)))
              (or (not colon) (package-suffix? output))
              (or (not at)
                  (= at (string-index-right value #\@)))
              (or (not colon)
                  (= colon (string-index-right value #\:)))))))

(define (required-package-list object key specifications?)
  (let ((value (object-ref object key "packages")))
    (unless (vector? value)
      (settings-error "packages.~a must be a JSON array" key))
    (let ((items (vector->list value)))
      (unless (every (if specifications?
                         package-specification?
                         package-name?)
                     items)
        (settings-error "packages.~a contains an invalid package ~a" key
                        (if specifications? "specification" "name")))
      (unless (= (length items)
                 (length (delete-duplicates items string=?)))
        (settings-error "packages.~a contains a duplicate" key))
      (unless (equal? items (sort (list-copy items) string<?))
        (settings-error "packages.~a must be sorted" key))
      (when specifications?
        (let ((keys (map package-specification-key items)))
          (unless (= (length keys)
                     (length (delete-duplicates keys string=?)))
            (settings-error
             "packages.~a contains multiple specifications for one package output"
             key))))
      items)))

(define (hash-string? value length alphabet)
  (and (string? value)
       (= (string-length value) length)
       (string-every (lambda (character)
                       (and (string-index alphabet character) #t))
                     value)))

(define %settings-file
  (or (search-path %load-path "securityops/settings.json")
      (settings-error "file is not reachable through Guile's load path")))

(define %settings
  (call-with-input-file %settings-file json->scm))

(validate-object-keys %settings
                      '("schema" "release" "kernel" "packages")
                      "root")

(let ((schema (object-ref %settings "schema" "root")))
  (unless (and (integer? schema) (= schema 1))
    (settings-error "schema must be the integer 1")))

(define %release-settings (object-ref %settings "release" "root"))
(validate-object-keys %release-settings
                      '("version" "build_revision" "desktop_label")
                      "release")

(define %release-version
  (required-string %release-settings "version" "release" 64))
(unless (stable-version? %release-version)
  (settings-error "release.version must be a stable X.Y.Z version"))

(define %build-revision
  (required-string %release-settings "build_revision" "release" 32))
(unless (and (string-prefix? "r" %build-revision)
             (> (string-length %build-revision) 1)
             (canonical-decimal? (substring %build-revision 1) #f))
  (settings-error "release.build_revision must look like r11"))

(define %desktop-label
  (required-string %release-settings "desktop_label" "release" 64))

(define %kernel-settings (object-ref %settings "kernel" "root"))
(validate-object-keys %kernel-settings
                      '("version" "url" "nix_base32" "sha256")
                      "kernel")

(define %kernel-version
  (required-string %kernel-settings "version" "kernel" 64))
(unless (stable-version? %kernel-version)
  (settings-error "kernel.version must be a stable X.Y.Z version"))

(define %kernel-url
  (required-string %kernel-settings "url" "kernel" 512))
(let* ((major (car (string-split %kernel-version #\.)))
       (expected (string-append
                  "https://cdn.kernel.org/pub/linux/kernel/v" major
                  ".x/linux-" %kernel-version ".tar.xz")))
  (unless (string=? %kernel-url expected)
    (settings-error "kernel.url must be the official kernel.org URL ~s"
                    expected)))

(define %kernel-nix-base32
  (required-string %kernel-settings "nix_base32" "kernel" 52))
(unless (hash-string? %kernel-nix-base32 52
                      "0123456789abcdfghijklmnpqrsvwxyz")
  (settings-error "kernel.nix_base32 is not a SHA-256 Nix-base32 hash"))

(define %kernel-sha256
  (required-string %kernel-settings "sha256" "kernel" 64))
(unless (hash-string? %kernel-sha256 64 "0123456789abcdef")
  (settings-error "kernel.sha256 is not a lowercase hexadecimal SHA-256"))

(define %package-settings (object-ref %settings "packages" "root"))
(validate-object-keys %package-settings '("add" "remove") "packages")

(define %package-additions
  (required-package-list %package-settings "add" #t))
(define %package-removals
  (required-package-list %package-settings "remove" #f))

(when (any (lambda (specification)
             (member (package-specification-base specification)
                     %package-removals string=?))
           %package-additions)
  (settings-error "packages.add and packages.remove overlap"))
