#!/run/current-system/profile/bin/guile -s
;; CodeMark v1 project=4c63e0fe-589c-4944-8449-97e211a38b72 file=6c6212503008519e828ea1795d8167f8 owner="Cristian Cezar Mois\u00e9s"
!#
;;; cow-system-init.scm -- isolated Guix system-init store overlay
;;;
;;; Copyright © 2018, 2020 Mathieu Othacehe <m.othacehe@gmail.com>
;;; Copyright © 2019, 2020, 2022 Ludovic Courtès <ludo@gnu.org>
;;; Copyright © 2024, 2026 Janneke Nieuwenhuizen <janneke@gnu.org>
;;; Copyright © 2026 Cristian Cezar Moisés
;;; SPDX-License-Identifier: GPL-3.0-or-later
;;;
;;; The mount-namespace and Guix-database lifecycle follows GNU Guix's
;;; (gnu installer final) install-system implementation.  This narrowly adapted
;;; helper accepts the Security Ops authenticated time-machine command directly;
;;; it does not read the upstream installer's predictable /tmp options file.

(define-module (securityops installer cow-system-init)
  #:use-module (gnu build install)
  #:use-module (gnu build linux-container)
  #:use-module (gnu services herd)
  #:use-module (gcrypt hash)
  #:use-module (guix base16)
  #:use-module (guix build syscalls)
  #:use-module (guix build utils)
  #:use-module (ice-9 format)
  #:use-module (ice-9 match)
  #:use-module (ice-9 popen)
  #:use-module (ice-9 regex)
  #:use-module (ice-9 rdelim)
  #:use-module (shepherd system)
  #:use-module (sqlite3)
  #:use-module (srfi srfi-1))

(define (fail format-string . arguments)
  (apply format (current-error-port)
         (string-append "cow-system-init: " format-string "~%")
         arguments)
  (primitive-exit 2))

(define (absolute-path? value)
  (and (string? value)
       (> (string-length value) 1)
       (char=? #\/ (string-ref value 0))))

(define (safe-root-owned-path? path expected-type expected-permissions)
  (and (absolute-path? path)
       (file-exists? path)
       (let ((metadata (lstat path)))
         (and (eq? expected-type (stat:type metadata))
              (= 0 (stat:uid metadata))
              (= 0 (stat:gid metadata))
              (= expected-permissions (logand #o777 (stat:perms metadata)))))))

(define (canonical-path? path)
  (and (absolute-path? path)
       (false-if-exception (string=? path (canonicalize-path path)))))

(define (immutable-store-executable? path)
  (and (canonical-path? path)
       (> (string-length path) (string-length "/gnu/store/"))
       (string=? "/gnu/store/"
                 (substring path 0 (string-length "/gnu/store/")))
       (let ((metadata (lstat path)))
         (and (eq? 'regular (stat:type metadata))
              (= 0 (stat:uid metadata))
              (zero? (logand #o022 (stat:perms metadata)))
              (not (zero? (logand #o111 (stat:perms metadata))))))))

(define (direct-runtime-child? path basename-pattern)
  (and (canonical-path? path)
       (string=? "/run/securityops-installer" (dirname path))
       (regexp-exec (make-regexp basename-pattern) (basename path))))

(define %private-environment-directory-names
  '("home" "xdg-config" "xdg-cache" "xdg-data" "xdg-state"
    "xdg-runtime" "tmp"))

(define (configure-child-environment certificate-file certificate-directory
                                     private-root)
  ;; run-container deliberately purifies the environment before calling its
  ;; thunk.  Restore only fixed, validated values; never fall back to /root or
  ;; to configuration inherited from the invoking live user.
  (for-each
   (lambda (directory)
     (unless (safe-root-owned-path? directory 'directory #o700)
       (error "unsafe private child-environment directory" directory)))
   (map (lambda (name) (string-append private-root "/" name))
        %private-environment-directory-names))
  (unless (safe-root-owned-path? certificate-file 'regular #o444)
    (error "unsafe CA certificate bundle" certificate-file))
  (unless (safe-root-owned-path? certificate-directory 'directory #o555)
    (error "unsafe CA certificate directory" certificate-directory))
  (for-each (match-lambda
              ((name . value) (setenv name value)))
            `(("PATH" . ,(string-append
                           "/run/privileged/bin:/run/setuid-programs:"
                           "/run/current-system/profile/bin:"
                           "/run/current-system/profile/sbin"))
              ("HOME" . ,(string-append private-root "/home"))
              ("XDG_CONFIG_HOME" . ,(string-append private-root "/xdg-config"))
              ("XDG_CACHE_HOME" . ,(string-append private-root "/xdg-cache"))
              ("XDG_DATA_HOME" . ,(string-append private-root "/xdg-data"))
              ("XDG_STATE_HOME" . ,(string-append private-root "/xdg-state"))
              ("XDG_RUNTIME_DIR" . ,(string-append private-root "/xdg-runtime"))
              ("TMPDIR" . ,(string-append private-root "/tmp"))
              ("LC_ALL" . "en_US.UTF-8")
              ("LANG" . "en_US.UTF-8")
              ("SSL_CERT_FILE" . ,certificate-file)
              ("SSL_CERT_DIR" . ,certificate-directory)
              ("GIT_SSL_CAINFO" . ,certificate-file))))

(define (validate-arguments arguments)
  (unless (= (length arguments) 13)
    (fail "expected TARGET CONFIG CHANNELS SOURCE SUBSTITUTE-URLS DB-BACKUP CERT-FILE CERT-DIR PRIVATE-ROOT INSTALLER-PID INSTALLER-START TRUSTED-FLOCK GUIX"))
  (for-each (lambda (value)
              (unless (absolute-path? value)
                (fail "path argument is not absolute: ~s" value)))
            (append (take arguments 4) (take (drop arguments 5) 4)))
  (let ((target (list-ref arguments 0))
        (config (list-ref arguments 1))
        (channels (list-ref arguments 2))
        (source (list-ref arguments 3))
        (backup (list-ref arguments 5))
        (certificate-file (list-ref arguments 6))
        (certificate-directory (list-ref arguments 7))
        (private-root (list-ref arguments 8))
        (installer-pid (list-ref arguments 9))
        (installer-start (list-ref arguments 10))
        (trusted-flock (list-ref arguments 11))
        (guix-executable (list-ref arguments 12)))
    (unless (string=? target "/mnt")
      (fail "target must be /mnt"))
    (unless (and (string=? config "/mnt/etc/config.scm")
                 (canonical-path? config)
                 (safe-root-owned-path? config 'regular #o600))
      (fail "configuration is missing or not the fixed target path"))
    (unless (and (canonical-path? channels) (canonical-path? source)
                 (safe-root-owned-path? channels 'regular #o444)
                 (safe-root-owned-path? source 'directory #o555))
      (fail "pinned channels or Security Ops source is missing"))
    (unless (direct-runtime-child? backup "^guix-db\\.[A-Za-z0-9]+$")
      (fail "database backup is outside the private runtime directory"))
    (let ((metadata (lstat backup)))
      (unless (and (eq? 'regular (stat:type metadata))
                   (= 0 (stat:uid metadata))
                   (= 0 (stat:gid metadata))
                   (= #o600 (logand #o777 (stat:perms metadata))))
        (fail "database backup path has unsafe metadata")))
    (unless (and (canonical-path? certificate-file)
                 (canonical-path? certificate-directory)
                 (safe-root-owned-path? certificate-file 'regular #o444)
                 (safe-root-owned-path? certificate-directory 'directory #o555))
      (fail "CA certificate paths have unsafe metadata"))
    (unless (and (direct-runtime-child? private-root
                                         "^session\\.[A-Za-z0-9]+$")
                 (safe-root-owned-path? private-root 'directory #o700))
      (fail "private environment root has unsafe metadata"))
    (unless (pid-matches? installer-pid installer-start)
      (fail "declared installer process identity is stale or malformed"))
    (verify-lifecycle-supervisor! trusted-flock)
    (unless (immutable-store-executable? guix-executable)
      (fail "Guix executable is not an immutable trusted store path"))))

(define %termination-signals (list SIGINT SIGTERM SIGHUP SIGQUIT))
(define %journal "/run/securityops-installer/cow-system-init.state")
(define %lifecycle-lock "/run/securityops-installer/cow-system-init.lock")
(define %lifecycle-lock-port #f)

(define (process-start-time pid)
  (false-if-exception
   (call-with-input-file (format #f "/proc/~a/stat" pid)
     (lambda (port)
       ;; FIELD 2 is parenthesized and may contain spaces.  Everything after
       ;; its final ')' starts at field 3; starttime is field 22 (index 19).
       (let* ((line (read-line port))
              (close (string-rindex line #\)))
              (fields (string-tokenize (substring line (+ close 2)))))
         (and (>= (length fields) 20) (list-ref fields 19)))))))

(define (safe-runtime-backup? path)
  (and (direct-runtime-child? path "^guix-db\\.[A-Za-z0-9]+$")
       (safe-root-owned-path? path 'regular #o600)))

(define (sync-file! path)
  (let ((port (open path O_RDONLY)))
    (fsync port)
    (close-port port)))

(define (sync-directory! path)
  (let ((port (open path (logior O_RDONLY O_DIRECTORY))))
    (fsync port)
    (close-port port)))

(define (path-entry-exists? path)
  ;; Unlike file-exists?, this also notices a dangling symlink so an attacker
  ;; cannot make recovery silently skip an unsafe journal path.
  (false-if-exception (begin (lstat path) #t)))

(define (sqlite-database-ok? path)
  (catch #t
    (lambda ()
      ;; immutable=1 prevents validation from creating or consulting WAL/SHM
      ;; sidecars.  These fixed root-owned paths contain no URI metacharacters.
      (let ((database (sqlite-open (string-append "file:" path "?immutable=1")
                                   (logior SQLITE_OPEN_READONLY
                                           SQLITE_OPEN_URI))))
        (dynamic-wind
          (lambda () #t)
          (lambda ()
            (let ((statement (sqlite-prepare database "PRAGMA quick_check")))
              (dynamic-wind
                (lambda () #t)
                (lambda ()
                  (equal? (sqlite-map identity statement)
                          (list (vector "ok"))))
                (lambda () (sqlite-finalize statement)))))
          (lambda () (sqlite-close database)))))
    (lambda _ #f)))

(define (write-journal phase backup database-digest backup-ready?
                       container-pid container-start
                       command-pid command-start
                       worker-pid worker-start)
  (let ((temporary (format #f "~a.new.~a" %journal (getpid))))
    (when (file-exists? temporary)
      (fail "refusing pre-existing journal temporary: ~a" temporary))
    (let ((port (open temporary (logior O_WRONLY O_CREAT O_EXCL) #o600)))
      (format port "version=2~%phase=~a~%backup=~a~%database-sha256=~a~%backup-ready=~a~%container-pid=~a~%container-start=~a~%command-pid=~a~%command-start=~a~%worker-pid=~a~%worker-start=~a~%"
              phase backup (or database-digest "") (if backup-ready? "1" "0")
              (or container-pid "") (or container-start "")
              (or command-pid "") (or command-start "")
              (or worker-pid "") (or worker-start ""))
      (force-output port)
      (fsync port)
      (close-port port))
    (rename-file temporary %journal)
    (sync-directory! (dirname %journal))))

(define (read-journal)
  (unless (and (canonical-path? %journal)
               (safe-root-owned-path? %journal 'regular #o600)
               (<= (stat:size (lstat %journal)) 4096))
    (fail "recovery journal has unsafe metadata"))
  (call-with-input-file %journal
    (lambda (port)
      (let loop ((result '()))
        (let ((line (read-line port)))
          (cond
           ((eof-object? line) result)
           (else
            (let ((separator (string-index line #\=)))
              (unless separator (fail "malformed recovery journal"))
              (let ((key (substring line 0 separator))
                    (value (substring line (+ separator 1))))
                (unless (member key '("version" "phase" "backup"
                                      "database-sha256" "backup-ready"
                                      "container-pid" "container-start"
                                      "command-pid" "command-start"
                                      "worker-pid" "worker-start"))
                  (fail "unknown recovery-journal field: ~a" key))
                (when (assoc key result)
                  (fail "duplicate recovery-journal field: ~a" key))
                (loop (acons key value result)))))))))))

(define (journal-ref journal key)
  (match (assoc key journal)
    ((_ . value) value)
    (#f (fail "recovery journal is missing ~a" key))))

(define (pid-matches? pid-text start-time)
  (and (string-match "^[1-9][0-9]*$" pid-text)
       (string-match "^[0-9]+$" start-time)
       (let ((pid (string->number pid-text)))
         (and (> pid 1)
              (file-exists? (format #f "/proc/~a" pid))
              (equal? start-time (process-start-time pid))
              pid))))

(define (verify-lifecycle-supervisor! trusted-flock)
  (unless (immutable-store-executable? trusted-flock)
    (fail "trusted flock path is not an immutable executable"))
  (unless (and (canonical-path? %lifecycle-lock)
               (safe-root-owned-path? %lifecycle-lock 'regular #o600))
    (fail "COW lifecycle lock has unsafe metadata"))
  ;; `flock --no-fork' opens and locks the file, then execs this Guile process.
  ;; Locate that inherited open-file description, prove this exact PID owns the
  ;; matching kernel FLOCK, and mark it close-on-exec.  It stays open in the
  ;; helper, mount-container, and persistent command supervisor, but closes in
  ;; the actual Guix worker at execve(2).
  (let* ((matching-fds
          (filter-map
           (lambda (fd)
             (let ((resolved
                    (false-if-exception
                     (canonicalize-path (format #f "/proc/self/fd/~a" fd)))))
               (and resolved (string=? resolved %lifecycle-lock) fd)))
           (iota 253 3)))
         (metadata (lstat %lifecycle-lock))
         (inode (stat:ino metadata)))
    (unless (= 1 (length matching-fds))
      (fail "helper did not inherit exactly one COW lifecycle lock descriptor"))
    (let ((fd (car matching-fds)))
      (fcntl fd F_SETFD FD_CLOEXEC)
      (set! %lifecycle-lock-port (fdopen fd "r")))
    (call-with-values
        (lambda () (device-number->major+minor (stat:dev metadata)))
      (lambda (major minor)
        (let ((identity (format #f "~2,'0x:~2,'0x:~a"
                                major minor inode)))
          (unless
              (call-with-input-file "/proc/locks"
                (lambda (port)
                  (let loop ()
                    (let ((line (read-line port)))
                      (cond
                       ((eof-object? line) #f)
                       (else
                        (let ((fields (string-tokenize line)))
                          (if (and (>= (length fields) 6)
                                   (string=? "FLOCK" (list-ref fields 1))
                                   (string=? "ADVISORY" (list-ref fields 2))
                                   (string=? "WRITE" (list-ref fields 3))
                                   (string=? (number->string (getpid))
                                             (list-ref fields 4))
                                   (string=? identity (list-ref fields 5)))
                              #t
                              (loop)))))))))
            (fail "helper does not own the exact COW lifecycle lock")))))))

(define (process-group-alive? pgid)
  (and pgid
       (false-if-exception
        (begin
          (kill (- pgid) 0)
          #t))))

(define (wait-process-group-gone pgid attempts)
  (let loop ((remaining attempts))
    (cond
     ((not (process-group-alive? pgid)) #t)
     ((zero? remaining) #f)
     (else
      (usleep 100000)
      (loop (- remaining 1))))))

(define (terminate-process-group pid)
  ;; PID is the authenticated, persistent supervisor and process-group leader.
  ;; Keeping that leader alive until teardown prevents descendants from escaping
  ;; merely by outliving/replacing an already-reaped command leader.
  (when pid
    (unless (false-if-exception (= pid (getpgid pid)))
      (error "recorded command supervisor is not its process-group leader" pid))
    (false-if-exception (kill (- pid) SIGTERM))
    ;; Never SIGKILL the persistent supervisor: it owns the lifecycle-lock
    ;; capability and is the only process that can authenticate, kill, and reap
    ;; its separate Guix worker group.  If it cannot finish, retain the lock and
    ;; fail closed instead of releasing an unknown worker.
    (unless (wait-process-group-gone pid 100)
      (error "command supervisor did not terminate safely" pid))))

(define (validated-recorded-group pid-text start-time label)
  ;; PID is also the PGID by construction.  A dead leader with live descendants
  ;; is valid and still must be terminated.  A reused leader PID is ambiguous,
  ;; however, so never signal or restore host state after a start-time mismatch.
  (cond
   ((and (string=? pid-text "") (string=? start-time "")) #f)
   ((or (not (string-match "^[1-9][0-9]*$" pid-text))
        (not (string-match "^[0-9]+$" start-time)))
    (error "malformed recorded process-group identity" label))
   (else
   (let* ((pid (string->number pid-text))
           (current-start (process-start-time pid)))
      (unless (> pid 1)
        (error "recorded process-group PID is not safely signalable" label pid))
      (when (and current-start (not (string=? current-start start-time)))
        (error "recorded process-group leader PID was reused" label pid))
      (when (and current-start
                 (not (false-if-exception (= pid (getpgid pid)))))
        (error "recorded process is no longer its process-group leader"
               label pid))
      pid))))

(define (terminate-worker-process-group pid-text start-time)
  (let ((pgid (validated-recorded-group pid-text start-time 'guix-worker)))
    (when (and pgid (process-group-alive? pgid))
      (false-if-exception (kill (- pgid) SIGTERM))
      (unless (wait-process-group-gone pgid 100)
        (false-if-exception (kill (- pgid) SIGKILL))
        (unless (wait-process-group-gone pgid 100)
          (error "journaled Guix worker group did not terminate" pgid))))))

(define (guix-daemon-state)
  ;; current-service returns #f for unavailable or malformed Shepherd replies.
  ;; Such an unknown state is never equivalent to stopped: proceeding could run
  ;; two daemons against the same store/database boundary.
  (let ((service (current-service 'guix-daemon)))
    (unless (live-service? service)
      (error "could not obtain a valid guix-daemon Shepherd status"))
    (let ((running (live-service-running service)))
      (cond
       ((eq? running #f) 'stopped)
       ((unspecified? running)
        (error "guix-daemon Shepherd status has an unspecified running value"))
       (else 'running)))))

(define (wait-for-guix-daemon-state expected)
  (let loop ((attempts 100))
    (let ((actual (guix-daemon-state)))
      (cond
       ((eq? actual expected) #t)
       ((zero? attempts)
        (error "guix-daemon did not reach required state" expected actual))
       (else
        (usleep 100000)
        (loop (- attempts 1)))))))

(define (stop-guix-daemon!)
  (case (guix-daemon-state)
    ((stopped) #t)
    ((running)
     (unless (stop-service 'guix-daemon)
       (error "Shepherd rejected guix-daemon stop"))
     (wait-for-guix-daemon-state 'stopped))))

(define* (start-guix-daemon! #:optional (arguments '()))
  (case (guix-daemon-state)
    ((running) #t)
    ((stopped)
     (unless (start-service 'guix-daemon arguments)
       (error "Shepherd rejected guix-daemon start"))
     (wait-for-guix-daemon-state 'running))))

(define (ensure-guix-daemon-running!)
  (start-guix-daemon!))

(define (valid-database-digest? digest)
  (and (string? digest) (string-match "^[0-9a-f]{64}$" digest)))

(define (validated-backup? backup digest)
  (and (safe-runtime-backup? backup)
       (valid-database-digest? digest)
       (string=? digest
                 (bytevector->base16-string (file-sha256 backup)))
       (sqlite-database-ok? backup)
       ;; Hash again after SQLite has closed to prove validation itself did not
       ;; change the supposedly immutable snapshot.
       (string=? digest
                 (bytevector->base16-string (file-sha256 backup)))))

(define (restore-database! backup database-file database-digest)
  ;; Keep the verified backup and journal authoritative until an atomic rename
  ;; has installed a separately verified temporary copy.  SIGKILL/power loss at
  ;; any earlier point therefore remains recoverable on the next preflight.
  (unless (validated-backup? backup database-digest)
    (error "Guix database backup failed digest or SQLite validation"))
  (let* ((database-directory (dirname database-file))
         (temporary (format #f "~a/.securityops-db-restore.~a"
                            database-directory (getpid))))
    (when (path-entry-exists? temporary)
      (error "refusing pre-existing database restore temporary" temporary))
    (dynamic-wind
      (lambda () #t)
      (lambda ()
        (copy-file backup temporary)
        (chmod temporary #o644)
        (sync-file! temporary)
        (unless (and (string=? database-digest
                               (bytevector->base16-string
                                (file-sha256 temporary)))
                     (sqlite-database-ok? temporary)
                     (string=? database-digest
                               (bytevector->base16-string
                                (file-sha256 temporary))))
          (error "temporary Guix database restore failed validation"))
        ;; A stale WAL/SHM from the namespaced daemon must not be replayed onto
        ;; the restored database.  Directory fsyncs bound both sidecar removal
        ;; and the final rename before backup-ready is cleared in the journal.
        (for-each (lambda (suffix)
                    (let ((sidecar (string-append database-file suffix)))
                      (when (path-entry-exists? sidecar)
                        (delete-file sidecar))
                      (when (path-entry-exists? sidecar)
                        (error "could not remove stale SQLite sidecar" sidecar))))
                  '("-wal" "-shm"))
        (sync-directory! database-directory)
        (rename-file temporary database-file)
        (sync-directory! database-directory)
        (unless (and (string=? database-digest
                               (bytevector->base16-string
                                (file-sha256 database-file)))
                     (sqlite-database-ok? database-file)
                     (string=? database-digest
                               (bytevector->base16-string
                                (file-sha256 database-file))))
          (error "restored Guix database failed final validation")))
      (lambda ()
        (when (path-entry-exists? temporary)
          (false-if-exception (delete-file temporary)))))))

(define (recover-prior-run! database-file)
  (when (path-entry-exists? %journal)
    (let* ((journal (read-journal))
           (version (journal-ref journal "version"))
           (phase (journal-ref journal "phase"))
           (backup (journal-ref journal "backup"))
           (database-digest (journal-ref journal "database-sha256"))
           (backup-ready? (string=? "1" (journal-ref journal "backup-ready")))
           (container (pid-matches?
                       (journal-ref journal "container-pid")
                       (journal-ref journal "container-start")))
           (command-pid-text (journal-ref journal "command-pid"))
           (command-start (journal-ref journal "command-start"))
           (command (pid-matches? command-pid-text command-start))
           (worker-pid-text (journal-ref journal "worker-pid"))
           (worker-start (journal-ref journal "worker-start")))
      (unless (string=? version "2")
        (fail "unsupported recovery-journal version"))
      (unless (member phase
                      '("spawn-intent" "child-ready"
                        "host-daemon-stop-intent" "host-daemon-stopped"
                        "database-copy-intent" "database-backup-ready"
                        "store-mount-intent" "store-mounted"
                        "container-daemon-start-intent"
                        "container-daemon-running" "command-running"
                        "command-worker-running"
                        "command-finished" "container-daemon-stopped"
                        "database-restored" "partial-backup-discarded"
                        "host-daemon-restarted" "store-unmounted"))
        (fail "unknown recovery phase: ~a" phase))
      (unless (safe-runtime-backup? backup)
        (fail "recovery backup is missing or unsafe: ~a" backup))
      ;; The command group is stopped first.  If the mount-container supervisor
      ;; survived an abrupt outer-helper death, ask it to run its own blocked,
      ;; idempotent cleanup and wait before touching the database here.
      (terminate-process-group command)
      ;; If the persistent supervisor was itself SIGKILLed/OOM-killed, its
      ;; separately journaled worker group remains independently identifiable.
      ;; Re-check start time after supervisor teardown before signalling it.
      ;; Even when the worker leader has exited, descendants may retain its
      ;; process group.  The durable PID/start pair authorizes that exact PGID;
      ;; a live leader with a different start time is treated as ambiguous.
      (terminate-worker-process-group worker-pid-text worker-start)
      (when container
        (false-if-exception (kill container SIGTERM))
        (let loop ((attempts 600))
          (when (and (> attempts 0)
                     (file-exists? (format #f "/proc/~a" container)))
            (usleep 100000)
            (loop (- attempts 1))))
        (when (file-exists? (format #f "/proc/~a" container))
          (false-if-exception (kill container SIGKILL))
          (let loop ((attempts 100))
            (when (and (> attempts 0)
                       (file-exists? (format #f "/proc/~a" container)))
              (usleep 100000)
              (loop (- attempts 1))))
          (when (file-exists? (format #f "/proc/~a" container))
            (fail "stale mount-container process did not terminate"))))
      (with-blocked-signals %termination-signals
        ;; A surviving container may have completed cleanup after TERM.  In
        ;; that case its atomic journal deletion is the completion witness.
        (if (not (path-entry-exists? %journal))
            (ensure-guix-daemon-running!)
            (begin
              (stop-guix-daemon!)
              (when backup-ready?
                (restore-database! backup database-file database-digest))
              (ensure-guix-daemon-running!)
              (delete-file %journal)
              (sync-directory! (dirname %journal))
              (delete-file backup)
              (sync-directory! (dirname backup))))))))

(define (call-with-mount-container thunk backup database-file
                                   installer-pid installer-start)
  ;; Block termination before clone(2), install forwarding handlers in both
  ;; supervisors, then unblock.  No signal can land in the spawn-before-handler
  ;; window.  The child has only a mount namespace and keeps the host network.
  (with-blocked-signals %termination-signals
    (write-journal 'spawn-intent backup #f #f #f #f #f #f #f #f)
    (let ((pid (catch #t
                 (lambda () (run-container "/" '() '(mnt) 1 thunk))
                 (lambda (key . arguments)
                   (recover-prior-run! database-file)
                   (apply throw key arguments))))
          (termination-forwarded? #f))
      (define (forward-signal signal)
        (set! termination-forwarded? #t)
        (false-if-exception (kill pid signal)))
      (unless (and (integer? pid) (> pid 1))
        (recover-prior-run! database-file)
        (error "mount-container spawn failed"))
      (for-each (lambda (signal)
                  (sigaction signal (lambda (_) (forward-signal signal))))
                %termination-signals)
      (unblock-signals %termination-signals)
      (let ((status
             (let loop ((termination-waits 0))
               ;; A targeted SIGKILL to the installer cannot run a Bash trap.
               ;; Detect reparenting here and ask the mount-container child to
               ;; execute its complete blocked cleanup before this helper exits.
               (when (and (not termination-forwarded?)
                          (not (pid-matches? installer-pid installer-start)))
                 (forward-signal SIGHUP))
               (match (waitpid pid WNOHANG)
                 ((0 . _)
                  (if (and termination-forwarded? (>= termination-waits 240))
                      (begin
                        (false-if-exception (kill pid SIGKILL))
                        (match (waitpid pid)
                          ((_ . result) result)))
                      (begin
                        (usleep 250000)
                        (loop (if termination-forwarded?
                                  (+ termination-waits 1)
                                  0)))))
                 ((_ . result) result)))))
        ;; A killed/failed child cannot defer host database/daemon repair until
        ;; some later installer run.  Once the child has been reaped, perform the
        ;; journal recovery synchronously with termination signals blocked.
        (with-blocked-signals %termination-signals
          (when (path-entry-exists? %journal)
            (recover-prior-run! database-file)))
        status))))

(define (run-install target config channels source substitute-urls backup
                     certificate-file certificate-directory private-root
                     installer-pid installer-start trusted-flock guix-executable)
  (define database-file "/var/guix/db/db.sqlite")
  (define backing-directory "/tmp/securityops-guix-inst")
  (define command
    (list guix-executable
          "time-machine" "-C" channels
          (string-append "--substitute-urls=" substitute-urls)
          "--fallback" "--"
          "system" "init" "-L" source
          (string-append "--substitute-urls=" substitute-urls)
          "--fallback" config target))
  (recover-prior-run! database-file)
  (call-with-mount-container
   (lambda ()
     (define command-ok? #f)
     (define cleanup-ok? #t)
     (define original-daemon-stop-intended? #f)
     (define container-daemon-start-intended? #f)
     (define backup-copy-intended? #f)
     (define backup-ready? #f)
     (define store-mount-intended? #f)
     (define command-pid #f)
     (define command-pgid #f)
     (define command-start #f)
     (define command-worker-pid #f)
     (define command-worker-start #f)
     (define database-digest #f)
     (define container-pid (getpid))
     (define container-start (process-start-time (getpid)))

     (define (record phase)
       (write-journal phase backup database-digest backup-ready?
                      container-pid container-start
                      command-pid command-start
                      command-worker-pid command-worker-start))

     (define (cleanup-step label thunk)
       (catch #t
         (lambda () (thunk))
         (lambda (key . arguments)
           (set! cleanup-ok? #f)
           (format (current-error-port)
                   "cow-system-init: cleanup failed (~a): ~s ~s~%"
                   label key arguments)
           #f)))

     (define (reap-command! block?)
       (and command-pid
            (let ((result (false-if-exception
                           (waitpid command-pid (if block? 0 WNOHANG)))))
              (and result
                   (not (zero? (car result)))
                   (begin
                     (set! command-pid #f)
                     (cdr result))))))

     (define (terminate-command!)
       (when (or command-pid command-pgid)
         (when command-pgid
           (false-if-exception (kill (- command-pgid) SIGTERM)))
         (let loop ((attempts 50))
           (reap-command! #f)
           (when (and (> attempts 0)
                      (process-group-alive? command-pgid))
             (usleep 100000)
             (loop (- attempts 1))))
         (when (process-group-alive? command-pgid)
           (error "owned Guix command supervisor exceeded cleanup deadline"
                  command-pgid))
         (when command-pid (reap-command! #t))
         (set! command-pid #f)
         (set! command-pgid #f)
         (set! command-start #f)))

     (define (terminate-command-worker!)
       ;; The worker identity is journaled before its exec gate opens.  If the
       ;; persistent supervisor dies before reporting that identity over its
       ;; pipe, recover it from the durable journal rather than allowing the
       ;; worker to outlive database/daemon restoration.
       (let* ((journal (and (path-entry-exists? %journal) (read-journal)))
              (pid-text (if command-worker-pid
                            (number->string command-worker-pid)
                            (if journal (journal-ref journal "worker-pid") "")))
              (start-time (or command-worker-start
                              (and journal (journal-ref journal "worker-start"))
                              "")))
         (terminate-worker-process-group pid-text start-time)
         (let ((pgid (and (string-match "^[1-9][0-9]*$" pid-text)
                          (string->number pid-text))))
           (when (and pgid (process-group-alive? pgid))
             (error "Guix worker group remains alive after teardown" pgid)))
         (set! command-worker-pid #f)
         (set! command-worker-start #f)))

     (define (command-boundary-clean?)
       (and (not command-pid) (not command-pgid) (not command-start)
            (not command-worker-pid) (not command-worker-start)))

     (define (run-owned-command)
       (let ((status-port #f))
         (with-blocked-signals %termination-signals
           (match (list (pipe) (pipe))
             (((read-port . write-port) (control-read . control-write))
              (let ((pid (primitive-fork)))
                (if (zero? pid)
                    ;; The persistent supervisor remains the process-group
                    ;; leader after the Guix worker exits.  Recovery can thus
                    ;; authenticate the group and remove any escaped descendants.
                    ;; No exception in either fork child may unwind through the
                    ;; parent's dynamic-wind cleanup.
                    (let ((worker #f)
                          (worker-pgid #f)
                          (worker-status #f)
                          (status-sent? #f)
                          (termination-signal #f)
                          (termination-waits 0)
                          (supervisor-parent (getppid))
                          (supervisor-parent-start
                           (process-start-time (getppid))))
                      (catch #t
                        (lambda ()
                          (close-port read-port)
                          (close-port control-write)
                          (setpgid 0 0)
                          (unless supervisor-parent-start
                            (error "could not bind command-supervisor parent"))
                          ;; Signals to the persistent supervisor are relayed to
                          ;; the actual worker group.  The supervisor keeps the
                          ;; lifecycle lock until that group is gone and reaped.
                          (for-each
                           (lambda (signal)
                             (sigaction
                              signal
                              (lambda (_)
                                (set! termination-signal signal)
                                (when worker-pgid
                                  (false-if-exception
                                   (kill (- worker-pgid) signal))))))
                           %termination-signals)
                          ;; Parent must durably journal the supervisor before it
                          ;; authorizes creation of any worker.
                          (match (read control-read)
                            ('ready #t)
                            (_ (primitive-exit 126)))
                          (close-port control-read)
                          (match (pipe)
                            ((gate-read . gate-write)
                             (set! worker (primitive-fork))
                             (if (zero? worker)
                                 (catch #t
                                   (lambda ()
                                     (close-port gate-write)
                                     (close-port write-port)
                                     (setpgid 0 0)
                                     ;; Do not exec until the supervisor has
                                     ;; journaled this exact PID/start identity.
                                     (match (read gate-read)
                                       ('ready #t)
                                       (_ (primitive-exit 126)))
                                     (close-port gate-read)
                                     (for-each
                                      (lambda (signal)
                                        (sigaction signal SIG_DFL))
                                      %termination-signals)
                                     (unblock-signals %termination-signals)
                                     (apply execl (car command) command))
                                   (lambda _ (primitive-exit 127)))
                                 (begin
                                   (close-port gate-read)
                                   (set! worker-pgid worker)
                                   (false-if-exception (setpgid worker worker))
                                   (unless (= worker (getpgid worker))
                                     (error "could not isolate Guix worker group"))
                                   (let ((worker-start
                                          (process-start-time worker)))
                                     (unless worker-start
                                       (error "could not bind Guix worker identity"))
                                     ;; This child-side write closes the SIGKILL
                                     ;; gap: worker signals remain blocked behind
                                     ;; GATE until its identity is on durable disk.
                                     (write-journal
                                      'command-worker-running backup
                                      database-digest backup-ready?
                                      container-pid container-start
                                      (getpid) (process-start-time (getpid))
                                      worker worker-start)
                                     (format write-port "worker=~a:~a~%"
                                             worker worker-start)
                                     (force-output write-port))
                                   (write 'ready gate-write)
                                   (newline gate-write)
                                   (close-port gate-write)
                                   (unblock-signals %termination-signals)
                                   (let monitor ()
                                     (unless (pid-matches?
                                              (number->string supervisor-parent)
                                              supervisor-parent-start)
                                       (unless termination-signal
                                         (set! termination-signal SIGHUP)
                                         (false-if-exception
                                          (kill (- worker-pgid) SIGHUP))))
                                     (unless worker-status
                                       (let ((result
                                              (false-if-exception
                                               (waitpid worker WNOHANG))))
                                         (when (and result
                                                    (not (zero? (car result))))
                                           (set! worker-status (cdr result)))))
                                     (when (and termination-signal
                                                (not worker-status))
                                       (set! termination-waits
                                             (+ termination-waits 1))
                                       (when (>= termination-waits 30)
                                         (false-if-exception
                                          (kill (- worker-pgid) SIGKILL))))
                                     (when (and worker-status
                                                (not status-sent?))
                                       (format write-port "status=~a~%"
                                               worker-status)
                                       (force-output write-port)
                                       (close-port write-port)
                                       (set! status-sent? #t))
                                     (cond
                                      ((and worker-status termination-signal)
                                       (primitive-exit 0))
                                      (else
                                       (usleep 100000)
                                       (monitor)))))))))
                        (lambda _
                          (when worker-pgid
                            (false-if-exception (kill (- worker-pgid) SIGKILL)))
                          (when (and worker (> worker 0) (not worker-status))
                            (false-if-exception (waitpid worker)))
                          (primitive-exit 127))))
                    (begin
                      (close-port write-port)
                      (close-port control-read)
                      (set! status-port read-port)
                      (set! command-pid pid)
                      (set! command-pgid pid)
                      (catch #t
                        (lambda ()
                          ;; Either side may win this race; both request the same
                          ;; private group and every other outcome is rejected.
                          (false-if-exception (setpgid pid pid))
                          (unless (= pid (getpgid pid))
                            (error "could not isolate Guix command supervisor"))
                          (set! command-start (process-start-time pid))
                          (unless command-start
                            (error "could not bind Guix command supervisor identity"))
                          (record 'command-running)
                          (write 'ready control-write)
                          (newline control-write)
                          (close-port control-write))
                        (lambda (key . arguments)
                          (false-if-exception (close-port control-write))
                          (false-if-exception (kill (- pid) SIGTERM))
                          (false-if-exception (waitpid pid))
                          (set! command-pid #f)
                          (set! command-pgid #f)
                          (set! command-start #f)
                          (close-port read-port)
                          (apply throw key arguments)))))))))
         (let* ((identity-line (read-line status-port))
                (identity-match
                 (and (string? identity-line)
                      (string-match
                       "^worker=([1-9][0-9]*):([0-9]+)$"
                       identity-line))))
           (unless identity-match
             (error "Guix supervisor returned no valid worker identity"))
           (set! command-worker-pid
                 (string->number (match:substring identity-match 1)))
           (set! command-worker-start (match:substring identity-match 2))
           (unless (and (pid-matches?
                         (number->string command-worker-pid)
                         command-worker-start)
                        (= command-worker-pid
                           (getpgid command-worker-pid)))
             (error "journaled Guix worker identity changed before exec")))
         (let* ((line (read-line status-port))
                (status-match
                 (and (string? line)
                      (string-match "^status=([0-9]+)$" line)))
                (raw-status (and status-match
                                 (string->number
                                  (match:substring status-match 1)))))
           (close-port status-port)
           (unless raw-status
             (error "Guix command supervisor returned no valid worker status"))
           (terminate-command!)
           (terminate-command-worker!)
           (zero? raw-status))))

     ;; Turn termination into a Scheme exception so dynamic-wind executes the
     ;; database restore and unmount path rather than abandoning a global daemon.
     (for-each
      (lambda (signal)
        (sigaction signal
                   (lambda (_)
                     (when command-pgid
                       (false-if-exception (kill (- command-pgid) signal)))
                     (throw 'installer-interrupted signal))))
      %termination-signals)
     (setvbuf (current-output-port) 'none)
     (setvbuf (current-error-port) 'none)
     (record 'child-ready)
     (unblock-signals %termination-signals)

     (catch #t
       (lambda ()
         (dynamic-wind
           (lambda () #t)
           (lambda ()
             (configure-child-environment certificate-file certificate-directory
                                          private-root)
             (with-blocked-signals %termination-signals
               (set! original-daemon-stop-intended? #t)
               (record 'host-daemon-stop-intent)
               (unless (eq? 'running (guix-daemon-state))
                 (error "host guix-daemon was not running at install start"))
               (stop-guix-daemon!)
               (for-each
                (lambda (suffix)
                  (when (path-entry-exists?
                         (string-append database-file suffix))
                    (error "Guix database sidecar remained after daemon stop"
                           suffix)))
                '("-wal" "-shm"))
               (set! database-digest
                     (bytevector->base16-string (file-sha256 database-file)))
               (record 'host-daemon-stopped))
             (with-blocked-signals %termination-signals
               (set! backup-copy-intended? #t)
               (record 'database-copy-intent)
               (copy-file database-file backup)
               (sync-file! backup)
               (unless (sqlite-database-ok? backup)
                 (error "Guix database backup failed SQLite quick_check"))
               (unless (string=? database-digest
                                 (bytevector->base16-string
                                  (file-sha256 backup)))
                 (error "Guix database backup digest mismatch"))
               (set! backup-ready? #t)
               (set! backup-copy-intended? #f)
               (record 'database-backup-ready))
             (with-blocked-signals %termination-signals
               (set! store-mount-intended? #t)
               (record 'store-mount-intent)
               (mount-cow-store target backing-directory)
               (record 'store-mounted))
             (with-blocked-signals %termination-signals
               (set! container-daemon-start-intended? #t)
               (record 'container-daemon-start-intent)
               (start-guix-daemon! (list (number->string (getpid))))
               (record 'container-daemon-running))
             (set! command-ok? (run-owned-command))
             (record 'command-finished))
           (lambda ()
             ;; Repeated signals remain blocked for the complete idempotent
             ;; cleanup path.  The outer supervisor can continue forwarding;
             ;; pending signals cannot interrupt database restoration.
             (block-signals %termination-signals)
             (cleanup-step 'terminate-command-supervisor terminate-command!)
             (cleanup-step 'terminate-command-worker terminate-command-worker!)
             (when (and (command-boundary-clean?)
                        container-daemon-start-intended?)
               (when (cleanup-step
                      'stop-container-daemon
                      (lambda () (stop-guix-daemon!)))
                 (set! container-daemon-start-intended? #f)
                 (record 'container-daemon-stopped)))
             (when (and (command-boundary-clean?) backup-ready?
                        (not container-daemon-start-intended?))
               (when (cleanup-step
                      'restore-database
                      (lambda ()
                        (restore-database! backup database-file database-digest)))
                 (set! backup-ready? #f)
                 (record 'database-restored)))
             ;; If copying failed before digest verification, the live DB was
             ;; never exposed to the COW daemon.  Discard the partial file;
             ;; copying it back would corrupt the host database.
             (when (and (command-boundary-clean?)
                        backup-copy-intended? (not backup-ready?)
                        (not container-daemon-start-intended?))
               (set! backup-copy-intended? #f)
               (record 'partial-backup-discarded))
             (when (and (command-boundary-clean?)
                        original-daemon-stop-intended?
                        (not backup-copy-intended?) (not backup-ready?)
                        (not container-daemon-start-intended?))
               (when (cleanup-step
                      'restart-host-daemon
                      (lambda ()
                        (ensure-guix-daemon-running!)))
                 (set! original-daemon-stop-intended? #f)
                 (record 'host-daemon-restarted)))
             (when (and (command-boundary-clean?) store-mount-intended?
                        (not container-daemon-start-intended?)
                        (not original-daemon-stop-intended?))
               (when (cleanup-step
                      'unmount-store
                      (lambda ()
                        (unmount-cow-store target backing-directory)))
                 (set! store-mount-intended? #f)
                 (record 'store-unmounted))))))
       (lambda (key . arguments)
         (set! command-ok? #f)
         (format (current-error-port)
                 "cow-system-init: install failed: ~s ~s~%" key arguments)))

     (when (and cleanup-ok? (command-boundary-clean?)
                (not backup-copy-intended?) (not backup-ready?)
                (not original-daemon-stop-intended?)
                (not container-daemon-start-intended?)
                (not store-mount-intended?))
       (when (path-entry-exists? %journal) (delete-file %journal))
       (sync-directory! (dirname %journal))
       (when (path-entry-exists? backup) (delete-file backup))
       (sync-directory! (dirname backup)))
     (primitive-exit (if (and command-ok? cleanup-ok?
                              (command-boundary-clean?)
                              (not original-daemon-stop-intended?)
                              (not container-daemon-start-intended?)
                              (not backup-copy-intended?) (not backup-ready?)
                              (not store-mount-intended?))
                         0
                         1)))
   backup database-file installer-pid installer-start))

(define (main arguments)
  (let ((arguments (cdr arguments)))
    (match arguments
      (("--recover-only" installer-pid installer-start trusted-flock)
       ;; Run before the guided disk UI/resource preflight.  It either repairs a
       ;; retained authenticated journal completely or fails closed before the
       ;; user can select, confirm, or modify a target disk.
       (unless (pid-matches? installer-pid installer-start)
         (fail "declared recovery installer process is stale or malformed"))
       (verify-lifecycle-supervisor! trusted-flock)
       (recover-prior-run! "/var/guix/db/db.sqlite")
       (primitive-exit 0))
      (_
       (validate-arguments arguments)
       (let ((status (apply run-install arguments)))
         (primitive-exit
          (if (zero? status)
              0
              1)))))))

;; This file lives below the repository's Guile load path so Guix can capture it
;; as an authenticated local-file input.  Some source-closure traversals load
;; `.scm' files while evaluating the OS; never run the privileged program in
;; that context.  The installed launcher invokes the fixed basename directly.
(when (string=? "cow-system-init.scm" (basename (car (command-line))))
  (main (command-line)))
