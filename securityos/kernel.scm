;; -*- mode: scheme; -*-
;;; ===========================================================================
;;; (securityos kernel) — "SecurityOps": hardened + performant Linux 7.1.3
;;; ===========================================================================
;;;
;;; Vanilla Linux 7.1.3 from kernel.org, built with `customize-linux' on top of
;;; the proven nonguix blob-kernel config — which keeps the broad driver / Wi-Fi
;;; / iso9660 / usb-storage coverage a "boots on any computer" live USB needs
;;; (this exact base is what boots the image; a minimal laptop defconfig does
;;; not).  A curated Clear-Linux / XanMod-flavoured performance + KSPP hardening
;;; overlay is layered on via `#:configs' (all additive / mainline, so the
;;; in-build `verify-config' cannot trip).  Named "SecurityOps" via
;;; `#:extra-version' → `uname -r' = 7.1.3-SecurityOps.
;;;
;;; NOTE on securityops.defconfig: the maintainer's own defconfig (kept in this
;;; directory for reference) targets a *patched* kernel — it sets options such
;;; as CONFIG_MNATIVE_INTEL (the graysky/Clear-Linux µarch patch) that vanilla
;;; 7.1.3 does not provide, and is tuned for one LUKS-ext4 Intel laptop rather
;;; than a portable live image.  Its *spirit* (perf + hardening) is reproduced
;;; below with vanilla-safe options; the runtime perf knobs (preempt=full, THP,
;;; BBR/fq, zram) live on the kernel command line + sysctl (config.scm).
;;;
;;; Built from source (not substitutable); the first build compiles it.
;;; ===========================================================================

(define-module (securityos kernel)
  #:use-module (guix packages)
  #:use-module (guix download)
  #:use-module (gnu packages linux)        ; customize-linux
  #:use-module (nongnu packages linux)     ; linux (blob kernel — broad config)
  #:export (linux-securityos))

(define %linux-7.1.3-source
  (origin
    (method url-fetch)
    (uri "https://cdn.kernel.org/pub/linux/kernel/v7.x/linux-7.1.3.tar.xz")
    (sha256
     (base32 "1p6iknvzmd04alrf49zn8mxw863v0yzgznyckfhl4llgx1lc0hdy"))))

;; Performance + hardening overlay (Clear-Linux / XanMod flavour, KSPP).  Only
;; additive (=y/=m), mainline, dependency-light options — NO choice groups
;; (HZ/preempt/CPU-µarch are choice groups and would break verify-config; they
;; are handled by the proven base config + the kernel command line instead).
(define %securityops-kernel-configs
  (list ;; --- KSPP hardening (won't impede pentest/forensics tooling) ---
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

(define linux-securityos
  (package
    (inherit
     (customize-linux
      #:name "securityops"
      #:linux linux
      #:source %linux-7.1.3-source
      #:extra-version "SecurityOps"
      #:configs %securityops-kernel-configs))
    (version "7.1.3")
    (synopsis "SecurityOps — hardened, performant Linux 7.1.3 (kernel.org + blobs)")
    (home-page "https://www.kernel.org/")))
