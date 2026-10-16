;; -*- mode: scheme; -*-
;; CodeMark v1 project=4c63e0fe-589c-4944-8449-97e211a38b72 file=d1bca81a8a9f5393a3d0b796a83b2a29 owner="Cristian Cezar Mois\u00e9s"
;;; ===========================================================================
;;; (securityops kernel) — configurable hardened + performant Linux
;;; ===========================================================================
;;;
;;; Vanilla Linux from kernel.org, built with `customize-linux' on top of
;;; the proven nonguix blob-kernel config — which keeps the broad driver / Wi-Fi
;;; / iso9660 / usb-storage coverage a portable x86_64 live USB needs
;;; (this exact base is what boots the image; a minimal laptop defconfig does
;;; not).  A curated Clear-Linux / XanMod-flavoured performance + KSPP hardening
;;; overlay is layered on via `#:configs' (all additive / mainline, so the
;;; in-build `verify-config' cannot trip).  Named "SecurityOps" through the
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
  #:use-module (guix packages)
  #:use-module (guix download)
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

;; Performance + hardening overlay (Clear-Linux / XanMod flavour, KSPP).  Only
;; additive (=y/=m), mainline, dependency-light options — NO choice groups
;; (HZ/preempt/CPU-µarch are choice groups and would break verify-config; they
;; are handled by the proven base config + the kernel command line instead).
(define %securityops-kernel-configs
  (list ;; --- deterministic release identity ---
        "CONFIG_LOCALVERSION=\"-SecurityOps\""
        "# CONFIG_LOCALVERSION_AUTO is not set"
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
        ;; MGLRU on by default (was only enabled at boot via sysfs) — markedly
        ;; better page reclaim under memory pressure, which a RAM-overlay live
        ;; image lives under.  Faster, snappier desktop.
        "CONFIG_LRU_GEN_ENABLED=y"))

(define linux-securityops
  (package
    (inherit
     (customize-linux
      #:name "securityops"
      #:linux linux
      #:source %linux-securityops-source
      #:configs %securityops-kernel-configs))
    (version %kernel-version)
    (synopsis
     (string-append "SecurityOps — hardened, performant Linux "
                    %kernel-version " (kernel.org + blobs)"))
    (home-page "https://www.kernel.org/")))
