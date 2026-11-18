;; -*- mode: scheme; -*-
;; CodeMark v1 project=4c63e0fe-589c-4944-8449-97e211a38b72 file=d1bca81a8a9f5393a3d0b796a83b2a29 owner="Cristian Cezar Mois\u00e9s"
;;; ===========================================================================
;;; (securityops kernel) — configurable hardened + performant Linux
;;; ===========================================================================
;;;
;;; Vanilla Linux from kernel.org, built with `customize-linux' on top of
;;; nonguix broad-driver config, with an explicit Security Ops performance and
;;; hardening overlay via `#:configs'.  Required values are checked after
;;; configuration and compilation; a recipe or config is not boot evidence.
;;; Named "SecurityOps" through the
;;; kernel's own CONFIG_LOCALVERSION.  Version, URL, and verified hashes live in
;;; securityops/settings.json and are maintained by `./securityopsctl kernel'.
;;;
;;; NOTE on securityops.defconfig: the maintainer's own defconfig (kept in this
;;; directory for reference) targets a *patched* kernel — it sets options such
;;; as CONFIG_MNATIVE_INTEL (the graysky/Clear-Linux µarch patch) that vanilla
;;; mainline does not provide, and is tuned for one LUKS-ext4 Intel laptop rather
;;; than a portable live image.  Its *spirit* (perf + hardening) is reproduced
;;; below with vanilla-safe options; the runtime perf knobs (preempt=full, THP,
;;; BBR/fq, zram) live on the kernel command line + sysctl (config.scm).
;;;
;;; The first uncached build compiles it from source.
;;; ===========================================================================

(define-module (securityops kernel)
  #:use-module (guix build-system gnu)
  #:use-module (guix packages)
  #:use-module (guix download)
  #:use-module (guix gexp)
  #:use-module (guix utils)
  #:use-module (gnu packages linux)        ; customize-linux
  #:use-module (nongnu packages linux)     ; linux (blob kernel — broad config)
  #:use-module (securityops settings)
  #:export (linux-securityops))

(define %linux-securityops-source
  (origin
    (method url-fetch)
    (uri %kernel-url)
    (sha256
     (base32 %kernel-nix-base32))))

;; One expected-value source for customization and the strict build guards.
;; Override both sides of the HZ choice; retain the base's dynamic preemption.
;; VFIO without an IOMMU is forbidden, even though the inherited base enables it.
(define %securityops-kernel-configs
  (list ;; --- deterministic release identity ---
        "CONFIG_LOCALVERSION=\"-SecurityOps\""
        "# CONFIG_LOCALVERSION_AUTO is not set"
        ;; HZ=1000 is the requested scheduling policy, not a benchmark claim.
        "# CONFIG_HZ_250 is not set"
        "CONFIG_HZ_1000=y"
        "CONFIG_HZ=1000"
        "# CONFIG_VFIO_NOIOMMU is not set"
        "CONFIG_CPU_MITIGATIONS=y"
        ;; Reject identity mappings and deferred DMA unmapping by default.
        "CONFIG_IOMMU_DEFAULT_DMA_STRICT=y"
        "# CONFIG_IOMMU_DEFAULT_DMA_LAZY is not set"
        "# CONFIG_IOMMU_DEFAULT_PASSTHROUGH is not set"
        ;; --- KSPP hardening (won't impede pentest/forensics tooling) ---
        "CONFIG_SLAB_FREELIST_HARDENED=y"
        "CONFIG_SLAB_FREELIST_RANDOM=y"
        "CONFIG_SHUFFLE_PAGE_ALLOCATOR=y"
        "CONFIG_HARDENED_USERCOPY=y"
        "CONFIG_STACKPROTECTOR_STRONG=y"
        "CONFIG_INIT_ON_ALLOC_DEFAULT_ON=y"
        "CONFIG_SECURITY_YAMA=y"
        "CONFIG_SECURITY_DMESG_RESTRICT=y"
        "CONFIG_BUG_ON_DATA_CORRUPTION=y"
        ;; r9 additions — all additive, mainline, dependency-light (SECURITY=y
        ;; is already on via YAMA, so Landlock/Fortify carry no new deps).
        "CONFIG_SECURITY_LANDLOCK=y"        ; unprivileged sandboxing LSM
        "CONFIG_FORTIFY_SOURCE=y"           ; compile-time buffer-overflow checks
        "CONFIG_SCHED_STACK_END_CHECK=y"    ; catch kernel stack overflow
        ;; --- performance (compressed swap + modern queueing/congestion) ---
        "CONFIG_ZRAM=m"
        "CONFIG_ZSWAP=y"
        "CONFIG_TCP_CONG_BBR=m"
        "CONFIG_NET_SCH_FQ=m"
        "CONFIG_NET_SCH_FQ_CODEL=y"
        "CONFIG_NET_SCH_CAKE=m"             ; modern bufferbloat-killing qdisc
        ;; Request MGLRU by default. Performance still needs measurements on
        ;; this exact kernel and workload; configuration is not a benchmark.
        "CONFIG_LRU_GEN_ENABLED=y"))

(define linux-securityops
  (let ((base (customize-linux
               #:name "securityops"
               #:linux linux
               #:source %linux-securityops-source
               #:configs %securityops-kernel-configs)))
    (package
      (inherit base)
      (version %kernel-version)
      (arguments
       (substitute-keyword-arguments (package-arguments base)
         ((#:imported-modules imported-modules %default-gnu-imported-modules)
          ;; This helper imports only Guile's standard library. The default
          ;; source-module-closure predicate excludes non-Guix namespaces.
          (cons '(securityops kernel-config) imported-modules))
         ((#:phases phases)
          #~(modify-phases #$phases
                ;; Guix verify-config accepts absent unset keys. Require their
                ;; actual resolved entries as well, so unknown keys fail closed.
                (add-after 'configure 'verify-securityops-config
                  (lambda _
                    (use-modules (securityops kernel-config))
                    (verify-required-kconfig
                     ".config" '#$%securityops-kernel-configs)))
                (add-after 'build 'verify-securityops-config-after-build
                  (lambda _
                    (use-modules (securityops kernel-config))
                    (verify-required-kconfig
                     ".config" '#$%securityops-kernel-configs)))))))
      (synopsis
       (string-append "SecurityOps — hardened, performant Linux "
                      %kernel-version " (kernel.org + blobs)"))
      (home-page "https://www.kernel.org/"))))
