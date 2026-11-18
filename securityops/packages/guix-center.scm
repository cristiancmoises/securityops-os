;; CodeMark v1 project=4c63e0fe-589c-4944-8449-97e211a38b72 file=20f15fda7234576289078f0f46e71829 owner="Cristian Cezar Mois\u00e9s"
;;; SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-SecurityOps-Commercial
(define-module (securityops packages guix-center)
  #:use-module (guix packages)
  #:use-module (guix gexp)
  #:use-module (guix utils)
  #:use-module (guix build-system trivial)
  #:use-module (gnu packages bash)
  #:use-module (gnu packages python)
  #:use-module (gnu packages qt)
  #:use-module ((guix licenses) #:prefix license:)
  #:export (securityops-guix-center))

(define %guix-center-frontend
  (or (search-path %load-path
                   "securityops/guix-center/securityops_guix_center.py")
      (error "Security Ops Guix Center frontend is missing from %load-path")))

(define %guix-center-backend
  (or (search-path %load-path
                   "securityops/guix-center/guix_backend.py")
      (error "Security Ops Guix Center backend is missing from %load-path")))

(define %guix-center-phase37
  (or (search-path %load-path
                   "securityops/guix-center/phase37_guix_center.py")
      (error "Security Ops Guix Center Phase 37 runtime is missing from %load-path")))

(define %guix-center-phase38
  (or (search-path %load-path
                   "securityops/guix-center/phase38_execution.py")
      (error "Security Ops Guix Center Phase 38 runtime is missing from %load-path")))

(define %guix-center-phase39
  (or (search-path %load-path
                   "securityops/guix-center/phase39_owner_execution.py")
      (error "Security Ops Guix Center Phase 39 runtime is missing from %load-path")))

(define %guix-center-phase40
  (or (search-path %load-path
                   "securityops/guix-center/phase40_owner_trust.py")
      (error "Security Ops Guix Center Phase 40 trust runtime is missing from %load-path")))

(define %guix-center-phase40-gate1
  (or (search-path %load-path
                   "securityops/guix-center/phase40_gate1_admission.py")
      (error "Security Ops Guix Center Phase 40 Gate 1 runtime is missing from %load-path")))

(define %guix-center-phase40-bootstrap
  (or (search-path %load-path
                   "securityops/guix-center/phase40_bootstrap.py")
      (error "Security Ops Guix Center Phase 40 bootstrap runner is missing from %load-path")))

(define %guix-center-phase41-ceremony
  (or (search-path %load-path
                   "securityops/guix-center/phase41_owner_ceremony.py")
      (error "Security Ops Guix Center Phase 41 ceremony runtime is missing from %load-path")))

(define %guix-center-phase41-gate1
  (or (search-path %load-path
                   "securityops/guix-center/phase41_gate1_execution.py")
      (error "Security Ops Guix Center Phase 41 Gate 1 runtime is missing from %load-path")))

(define %guix-center-phase41-bootstrap
  (or (search-path %load-path
                   "securityops/guix-center/phase41_bootstrap.py")
      (error "Security Ops Guix Center Phase 41 ceremony runner is missing from %load-path")))

(define %guix-center-phase42-media
  (or (search-path %load-path
                   "securityops/guix-center/phase42_media.py")
      (error "Security Ops Guix Center Phase 42 media runtime is missing from %load-path")))

(define %guix-center-phase42-ceremony
  (or (search-path %load-path
                   "securityops/guix-center/phase42_offline_ceremony.py")
      (error "Security Ops Guix Center Phase 42 ceremony runtime is missing from %load-path")))

(define %guix-center-phase42-bootstrap
  (or (search-path %load-path
                   "securityops/guix-center/phase42_bootstrap.py")
      (error "Security Ops Guix Center Phase 42 ceremony runner is missing from %load-path")))

(define %guix-center-phase43-custody
  (or (search-path %load-path
                   "securityops/guix-center/phase43_offline_custody.py")
      (error "Security Ops Guix Center Phase 43 custody runtime is missing from %load-path")))

(define %guix-center-phase43-bootstrap
  (or (search-path %load-path
                   "securityops/guix-center/phase43_bootstrap.py")
      (error "Security Ops Guix Center Phase 43 custody runner is missing from %load-path")))

(define %guix-center-phase44-closure
  (or (search-path %load-path
                   "securityops/guix-center/phase44_gate1_closure.py")
      (error "Security Ops Guix Center Phase 44 Gate 1 closure runtime is missing from %load-path")))

(define %guix-center-phase44-bootstrap
  (or (search-path %load-path
                   "securityops/guix-center/phase44_bootstrap.py")
      (error "Security Ops Guix Center Phase 44 Gate 1 closure runner is missing from %load-path")))

(define %guix-center-phase44-dossier
  (or (search-path %load-path
                   "securityops/guix-center/phase44_gate1_dossier.py")
      (error "Security Ops Guix Center Phase 44 Gate 1 dossier runtime is missing from %load-path")))

(define %guix-center-phase44-dossier-bootstrap
  (or (search-path %load-path
                   "securityops/guix-center/phase44_dossier_bootstrap.py")
      (error "Security Ops Guix Center Phase 44 dossier runner is missing from %load-path")))

;; Phase 44 package markers: offline station attestations; content-addressed evidence vault; Gate 1 admission dossier.
(define %guix-center-phase44-admission
  (or (search-path %load-path
                   "securityops/guix-center/phase44_offline_admission.py")
      (error "Security Ops Guix Center Phase 44 offline admission runtime is missing from %load-path")))

(define %guix-center-phase44-admission-bootstrap
  (or (search-path %load-path
                   "securityops/guix-center/phase44_admission_bootstrap.py")
      (error "Security Ops Guix Center Phase 44 offline admission runner is missing from %load-path")))

;; Phase 45 executes concrete portable checks and capability-gates every real
;; Guix, Qt, kernel, VM, installer, AF_VSOCK, and ISO operation.
(define %guix-center-phase45-execution
  (or (search-path %load-path
                   "securityops/guix-center/phase45_execution.py")
      (error "Security Ops Guix Center Phase 45 execution runtime is missing from %load-path")))

(define %guix-center-process-groups
  (or (search-path %load-path
                   "securityops/guix-center/process_groups.py")
      (error "Security Ops Guix Center process-group runtime is missing from %load-path")))

(define %guix-center-phase45-bootstrap
  (or (search-path %load-path
                   "securityops/guix-center/phase45_bootstrap.py")
      (error "Security Ops Guix Center Phase 45 execution runner is missing from %load-path")))

(define %guix-center-phase46-execution
  (or (search-path %load-path
                   "securityops/guix-center/phase46_guix_execution.py")
      (error "Security Ops Guix Center Phase 46 Guix execution boundary is missing from %load-path")))

(define %guix-center-ui-model
  (or (search-path %load-path
                   "securityops/guix-center/phase37_ui_model.py")
      (error "Security Ops Guix Center Phase 37 UI model is missing from %load-path")))

(define %guix-center-matrix
  (or (search-path %load-path
                   "securityops/guix-center/phase37_matrix.py")
      (error "Security Ops Guix Center Phase 37 matrix is missing from %load-path")))

(define %guix-center-phase38-gate-runner
  (or (search-path %load-path
                   "securityops/guix-center/phase38_gate_runner.py")
      (error "Security Ops Guix Center Phase 38 gate runner is missing from %load-path")))

(define %guix-center-phase39-gate-runner
  (or (search-path %load-path
                   "securityops/guix-center/phase39_gate_runner.py")
      (error "Security Ops Guix Center Phase 39 gate runner is missing from %load-path")))

(define securityops-guix-center
  (package
    (name "securityops-guix-center")
    (version "0.2.0")
    (source #f)
    (build-system trivial-build-system)
    (inputs (list bash-minimal python python-pyside-6 python-shiboken-6 qtbase))
    (arguments
     (list
      #:modules '((guix build utils))
      #:builder
      #~(begin
          (use-modules (guix build utils) (ice-9 rdelim)
                       (ice-9 textual-ports))
          (let* ((bin (string-append #$output "/bin"))
                 (apps (string-append #$output "/share/applications"))
                 (meta (string-append #$output "/share/metainfo"))
                 (program (string-append bin "/securityops-guix-center"))
                 (frontend-module (string-append bin "/securityops_guix_center.py"))
                 (backend (string-append bin "/guix_backend.py"))
                 (phase37 (string-append bin "/phase37_guix_center.py"))
                 (phase38 (string-append bin "/phase38_execution.py"))
                 (phase39 (string-append bin "/phase39_owner_execution.py"))
                 (phase40 (string-append bin "/phase40_owner_trust.py"))
                 (phase40-gate1
                  (string-append bin "/phase40_gate1_admission.py"))
                 (phase40-bootstrap
                  (string-append bin "/securityops-phase40-bootstrap"))
                 (phase41-ceremony
                  (string-append bin "/phase41_owner_ceremony.py"))
                 (phase41-gate1
                  (string-append bin "/phase41_gate1_execution.py"))
                 (phase41-bootstrap
                  (string-append bin "/securityops-phase41-ceremony"))
                 (phase42-media
                  (string-append bin "/phase42_media.py"))
                 (phase42-ceremony
                  (string-append bin "/phase42_offline_ceremony.py"))
                 (phase42-bootstrap
                  (string-append bin "/securityops-phase42-ceremony"))
                 (phase43-custody
                  (string-append bin "/phase43_offline_custody.py"))
                 (phase43-bootstrap
                  (string-append bin "/securityops-phase43-custody"))
                 (phase44-closure
                  (string-append bin "/phase44_gate1_closure.py"))
                 (phase44-bootstrap
                  (string-append bin "/securityops-phase44-gate1"))
                 (phase44-dossier
                  (string-append bin "/phase44_gate1_dossier.py"))
                 (phase44-dossier-bootstrap
                  (string-append bin "/securityops-phase44-dossier"))
                 (phase44-admission
                  (string-append bin "/phase44_offline_admission.py"))
                 (phase44-admission-bootstrap
                  (string-append bin "/securityops-phase44-admission"))
                 (phase45-execution
                  (string-append bin "/phase45_execution.py"))
                 (process-groups
                  (string-append bin "/process_groups.py"))
                 (phase45-bootstrap
                  (string-append bin "/securityops-phase45-execute"))
                 (phase46-execution
                  (string-append bin "/phase46_guix_execution.py"))
                 (ui-model (string-append bin "/phase37_ui_model.py"))
                 (matrix (string-append bin "/securityops-phase37-matrix"))
                 (matrix-module (string-append bin "/phase37_matrix.py"))
                 (gate-runner (string-append bin "/securityops-phase38-gates"))
                 (phase39-gate-runner
                  (string-append bin "/securityops-phase39-gates"))
                 (executables
                  (list program matrix gate-runner phase39-gate-runner
                        phase40-bootstrap phase41-bootstrap phase42-bootstrap
                        phase43-bootstrap phase44-bootstrap
                        phase44-dossier-bootstrap phase44-admission-bootstrap
                        phase45-bootstrap))
                 (python-shebang
                  (string-append "#!" #$(file-append python "/bin/python3") " -I"))
                 (python-path
                  (list #$(file-append python-pyside-6
                                      (string-append "/lib/python"
                                       (version-major+minor (package-version python))
                                       "/site-packages"))
                        #$(file-append python-shiboken-6
                                      (string-append "/lib/python"
                                       (version-major+minor (package-version python))
                                       "/site-packages"))))
                 (qt-plugins #$(file-append qtbase "/lib/qt6/plugins")))
            (for-each
             (lambda (directory)
               (unless (file-is-directory? directory)
                 (error "Guix Center runtime directory is missing" directory)))
             (cons qt-plugins python-path))
            (mkdir-p bin)
            (mkdir-p apps)
            (mkdir-p meta)
            (copy-file #$(local-file %guix-center-frontend)
                       program)
            (copy-file #$(local-file %guix-center-backend)
                       backend)
            (copy-file #$(local-file %guix-center-frontend)
                       frontend-module)
            (copy-file #$(local-file %guix-center-phase37)
                       phase37)
            (copy-file #$(local-file %guix-center-phase38)
                       phase38)
            (copy-file #$(local-file %guix-center-phase39)
                       phase39)
            (copy-file #$(local-file %guix-center-phase40)
                       phase40)
            (copy-file #$(local-file %guix-center-phase40-gate1)
                       phase40-gate1)
            (copy-file #$(local-file %guix-center-phase40-bootstrap)
                       phase40-bootstrap)
            (copy-file #$(local-file %guix-center-phase41-ceremony)
                       phase41-ceremony)
            (copy-file #$(local-file %guix-center-phase41-gate1)
                       phase41-gate1)
            (copy-file #$(local-file %guix-center-phase41-bootstrap)
                       phase41-bootstrap)
            (copy-file #$(local-file %guix-center-phase42-media)
                       phase42-media)
            (copy-file #$(local-file %guix-center-phase42-ceremony)
                       phase42-ceremony)
            (copy-file #$(local-file %guix-center-phase42-bootstrap)
                       phase42-bootstrap)
            (copy-file #$(local-file %guix-center-phase43-custody)
                       phase43-custody)
            (copy-file #$(local-file %guix-center-phase43-bootstrap)
                       phase43-bootstrap)
            (copy-file #$(local-file %guix-center-phase44-closure)
                       phase44-closure)
            (copy-file #$(local-file %guix-center-phase44-bootstrap)
                       phase44-bootstrap)
            (copy-file #$(local-file %guix-center-phase44-dossier)
                       phase44-dossier)
            (copy-file #$(local-file %guix-center-phase44-dossier-bootstrap)
                       phase44-dossier-bootstrap)
            (copy-file #$(local-file %guix-center-phase44-admission)
                       phase44-admission)
            (copy-file #$(local-file %guix-center-phase44-admission-bootstrap)
                       phase44-admission-bootstrap)
            (copy-file #$(local-file %guix-center-phase45-execution)
                       phase45-execution)
            (copy-file #$(local-file %guix-center-process-groups)
                       process-groups)
            (copy-file #$(local-file %guix-center-phase45-bootstrap)
                       phase45-bootstrap)
            (copy-file #$(local-file %guix-center-phase46-execution)
                       phase46-execution)
            (copy-file #$(local-file %guix-center-ui-model)
                       ui-model)
            (copy-file #$(local-file %guix-center-matrix)
                       matrix)
            (copy-file #$(local-file %guix-center-matrix)
                       matrix-module)
            (copy-file #$(local-file %guix-center-phase38-gate-runner)
                       gate-runner)
            (copy-file #$(local-file %guix-center-phase39-gate-runner)
                       phase39-gate-runner)
            ;; Some CLI modules have no source shebang.  Install one for all
            ;; entry points, accepting only the known Python source interpreter.
            (for-each
             (lambda (executable)
               (let* ((source (call-with-input-file executable get-string-all))
                      (source-shebang "#!/usr/bin/env python3\n")
                      (body
                       (cond
                        ((string-prefix? source-shebang source)
                         (substring source (string-length source-shebang)))
                        ((string-prefix? "#!" source)
                         (error "Unexpected Guix Center source interpreter" executable))
                        (else source))))
                 ;; local-file copies retain read-only Store permissions.
                 ;; Final executable/module modes are set below.
                 (chmod executable #o600)
                 (call-with-output-file executable
                   (lambda (port)
                     (display python-shebang port)
                     (newline port)
                     (display body port)))))
             (cons frontend-module executables))
            (for-each
             (lambda (executable)
               (call-with-input-file executable
                 (lambda (port)
                   (unless (equal? (read-line port) python-shebang)
                     (error "Guix Center requires isolated Store Python" executable)))))
             (cons frontend-module executables))
            (chmod program #o555)
            (chmod frontend-module #o444)
            (chmod backend #o444)
            (chmod phase37 #o444)
            (chmod phase38 #o444)
            (chmod phase39 #o444)
            (chmod phase40 #o444)
            (chmod phase40-gate1 #o444)
            (chmod phase40-bootstrap #o555)
            (chmod phase41-ceremony #o444)
            (chmod phase41-gate1 #o444)
            (chmod phase41-bootstrap #o555)
            (chmod phase42-media #o444)
            (chmod phase42-ceremony #o444)
            (chmod phase42-bootstrap #o555)
            (chmod phase43-custody #o444)
            (chmod phase43-bootstrap #o555)
            (chmod phase44-closure #o444)
            (chmod phase44-bootstrap #o555)
            (chmod phase44-dossier #o444)
            (chmod phase44-dossier-bootstrap #o555)
            (chmod phase44-admission #o444)
            (chmod phase44-admission-bootstrap #o555)
            (chmod phase45-execution #o444)
            (chmod process-groups #o444)
            (chmod phase45-bootstrap #o555)
            (chmod phase46-execution #o444)
            (chmod ui-model #o444)
            (chmod matrix #o555)
            (chmod matrix-module #o444)
            (chmod gate-runner #o555)
            (chmod phase39-gate-runner #o555)
            ;; PySide/Qt are fixed Guix inputs.  User-site imports are disabled
            ;; by the launcher source and cannot replace the transaction backend.
            (for-each
             (lambda (executable)
               (wrap-program executable
                 #:sh #$(file-append bash-minimal "/bin/bash")
                 `("GUIX_PYTHONPATH" = ,python-path)
                 `("QT_PLUGIN_PATH" = (,qt-plugins))
                 `("PYTHONNOUSERSITE" = ("1"))
                 `("PYTHONDONTWRITEBYTECODE" = ("1"))
                 `("PYTHONSAFEPATH" = ("1"))))
             executables)
            (call-with-output-file
                (string-append apps "/co.securityops.GuixCenter.desktop")
              (lambda (port)
                (format port
                        "[Desktop Entry]~%Name=Security Ops Guix Center~%Comment=Transactional GNU Guix package management~%Exec=~a~%Icon=system-software-install~%Terminal=false~%Type=Application~%Categories=System;PackageManager;Qt;~%Keywords=Guix;Packages;Profiles;Rollback;~%StartupNotify=true~%StartupWMClass=co.securityops.GuixCenter~%"
                        program)))
            (call-with-output-file
                (string-append meta "/co.securityops.GuixCenter.metainfo.xml")
              (lambda (port)
                (display
                 "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<component type=\"desktop-application\">\n  <id>co.securityops.GuixCenter</id>\n  <name>Security Ops Guix Center</name>\n  <summary>Transactional GNU Guix package management</summary>\n  <metadata_license>CC0-1.0</metadata_license>\n  <project_license>AGPL-3.0-or-later</project_license>\n  <description><p>Manage per-user Guix profiles, generations, channels, updates and storage through reviewed transactions and crash-safe receipts.</p></description>\n  <launchable type=\"desktop-id\">co.securityops.GuixCenter.desktop</launchable>\n  <provides><binary>securityops-guix-center</binary></provides>\n</component>\n"
                 port)))))))
    (synopsis "Secure transactional GUI for GNU Guix package profiles")
    (description
     "Security Ops Guix Center is a Qt 6/PySide 6 graphical package manager for
GNU Guix.  It introduces users from other distributions to per-user profiles,
generations, rollback, channels and garbage collection.  Mutations require an
exact transaction preview; execution uses an immutable measured Guix binary,
fixed argument vectors, descriptor-bound execution, no shell or privilege
escalation, append-only receipt-bound recovery journals, integrity-checked
cancellation markers, a cancellation-aware 30-second per-profile mutation
queue, bounded background workers, SQLite integrity checks and mode-0600
digest-bound same-UID activity receipts.  Store-wide garbage collection is
disabled until a private disposable daemon and fresh digest-bound inventory
can be enforced.  Phase 38 adds descriptor-bound,
machine-readable cumulative validation receipts and a fail-closed measured
capability/gate evidence collector that cannot promote portable probes to Guix,
Qt, KVM, AF_VSOCK, boot, or ISO evidence.  Phase 39 adds a dual-signed,
replay-resistant owner/build-node receipt importer that remeasures exact logs
and artifacts before any ordered production gate can be approved.  Phase 40
adds a secret-free owner trust bootstrap, separate owner/build-node public-key
policy, a signed 35-artifact input closure, monotonic local trust state, and
semantic verification for the authenticated Guix/Qt environment gate.  Phase
41 adds owner-authorized initialization, rotation, build-node revocation,
externally anchored recovery, equivocation detection, and a monotonic Gate 1
decision ledger.  Phase 42 adds deterministic offline-media export/import,
non-overwriting atomic publication, exact streaming manifests, an independent
witness checkpoint ledger, externally anchored recovery drills, and a
signer-independent dual-signed ceremony transcript.  Phase 43 adds a
kernel-sealed, independently signed offline chain-of-custody ledger, strict
export/receive/verify/import role separation, quarantine, replay resistance,
and a cross-bound Gate 1 preflight that cannot itself approve Gate 1.  Phase 44
adds a descriptor-bound immutable twenty-document Gate 1 dossier, a six-role
out-of-band pin policy, owner-and-witness signed admission envelopes, four
independently signed offline station attestations, a content-addressed evidence
vault, an exact Gate 1 admission dossier, and monotonic final/admission ledgers.
Phase 45 adds a concrete execution harness that measures the current host,
executes the bounded Guix Center portable matrix, performs two independent
hardened native builds, validates Python sources and Git trees, and emits exact
private logs and machine-readable receipts.  It automatically leaves Guix,
Qt, Rust, Linux 7.2, KVM, AF_VSOCK, installer, desktop, and ISO gates blocked
unless their real prerequisites and ordered external receipts exist.  These
artifacts cannot create authority or bypass the Phase 41 decision.
Fixture ceremonies, custody records, pinsets, envelopes, station quorums,
vaults and dossiers remain unable to create owner authority or production
evidence.")
    (home-page "https://securityops.co")
    (license license:agpl3+)))
