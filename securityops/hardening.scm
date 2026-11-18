;; CodeMark v1 project=4c63e0fe-589c-4944-8449-97e211a38b72 file=e8973db721c45452aea201d91bc3b79d owner="Cristian Cezar Mois\u00e9s"
;;; Portable runtime policy shared by the live image and installed systems.
;;; These requested settings are not evidence of kernel or hardware enforcement.
(define-module (securityops hardening)
  #:use-module (srfi srfi-1)
  #:export (%securityops-kernel-hardening-arguments
            %securityops-hardening-sysctls
            securityops-harden-sysctls))

(define %securityops-kernel-hardening-arguments
  '("mitigations=auto"
    "init_on_alloc=1" "slab_nomerge" "page_alloc.shuffle=1"
    "randomize_kstack_offset=on" "vsyscall=none"
    "lsm=landlock,yama,bpf"
    ;; AMD uses firmware discovery; amd_iommu=on is not a supported value.
    ;; No identity-map default or delayed DMA unmapping on either vendor.
    "intel_iommu=on" "iommu.passthrough=0" "iommu.strict=1"))

(define %securityops-hardening-sysctls
  '(("kernel.kptr_restrict" . "2")
    ("kernel.dmesg_restrict" . "1")
    ("kernel.yama.ptrace_scope" . "1")
    ("kernel.kexec_load_disabled" . "1")
    ("kernel.perf_event_paranoid" . "3")
    ("kernel.unprivileged_bpf_disabled" . "1")
    ("net.core.bpf_jit_harden" . "2")
    ("kernel.randomize_va_space" . "2")
    ("fs.protected_symlinks" . "1")
    ("fs.protected_hardlinks" . "1")
    ("fs.protected_fifos" . "2")
    ("fs.protected_regular" . "2")
    ("fs.suid_dumpable" . "0")
    ;; Loose RPF preserves VPN/asymmetric-routing compatibility.
    ("net.ipv4.conf.all.rp_filter" . "2")
    ("net.ipv4.conf.default.rp_filter" . "2")
    ("net.ipv4.tcp_syncookies" . "1")
    ("net.ipv4.conf.all.accept_redirects" . "0")
    ("net.ipv4.conf.default.accept_redirects" . "0")
    ("net.ipv4.conf.all.secure_redirects" . "0")
    ("net.ipv4.conf.default.secure_redirects" . "0")
    ("net.ipv4.conf.all.send_redirects" . "0")
    ("net.ipv4.conf.default.send_redirects" . "0")
    ("net.ipv4.conf.all.accept_source_route" . "0")
    ("net.ipv4.conf.default.accept_source_route" . "0")
    ("net.ipv6.conf.all.accept_redirects" . "0")
    ("net.ipv6.conf.default.accept_redirects" . "0")
    ;; Linux accepts Routing Header Type 2 at zero; -1 rejects all types.
    ("net.ipv6.conf.all.accept_source_route" . "-1")
    ("net.ipv6.conf.default.accept_source_route" . "-1")))

(define (securityops-harden-sysctls defaults)
  ;; Emit exactly one value for each policy key, without dropping unrelated
  ;; Guix defaults. Do not depend on the service's duplicate-key ordering.
  (append (filter (lambda (setting)
                    (not (assoc (car setting) %securityops-hardening-sysctls)))
                  defaults)
          %securityops-hardening-sysctls))
