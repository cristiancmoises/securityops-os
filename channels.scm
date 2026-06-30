;; channels.scm — channels for a reproducible SecurityOS Live build.
;;
;; Upstream guix + nonguix, plus the maintainer's two personal channels:
;;   * guix-xlibre  — the XLibre X server + forked input/video drivers used
;;                    instead of X.Org (the (xlibre) module).
;;   * securityops  — the curated app set (kitty, tor, torbrowser, mullvad,
;;                    google-chrome, …) and the torando service.
;;
;; Build reproducibly with:
;;   guix time-machine -C channels.scm -- system image -L . -t iso9660 config.scm
;;
;; NOTE: the day-to-day build (./build.sh, no --pinned) uses your ALREADY-PULLED
;; guix (`guix describe`), which is where these channels are resolved from; this
;; file is the public, shareable pin.  git.securityops.co serves the maintainer's
;; mirrors of everything.

(list
 (channel
  (name 'guix)
  (url "https://git.savannah.gnu.org/git/guix.git")
  (branch "master")
  (commit "d1e9e23fd441fce828fa74616271b00b90853cee")
  (introduction
   (make-channel-introduction
    "9edb3f66fd807b096b48283debdcddccfea34bad"
    (openpgp-fingerprint
     "BBB0 2DDF 2CEA F6A8 0D1D  E643 A2A0 6DF2 A33A 54FA"))))

 (channel
  (name 'nonguix)
  (url "https://gitlab.com/nonguix/nonguix")
  (commit "bf39542ca537fde8839b209ac21d6f3254469b15")
  (introduction
   (make-channel-introduction
    "897c1a470da759236cc11798f4e0a5f7d4d59fbc"
    (openpgp-fingerprint
     "2A39 3FFF 68F4 EF7A 3D29  12AF 6F51 20A0 22FB B2D5"))))

 ;; XLibre X server + forked input/video drivers — provides the (xlibre) module.
 (channel
  (name 'guix-xlibre)
  (url "https://git.securityops.co/cristiancmoises/guix-xlibre")
  (branch "master"))

 ;; securityops — the maintainer's curated channel (browsers, tor, mullvad,
 ;; kitty, torando service …).  Provides (securityops packages …) modules.
 (channel
  (name 'securityops)
  (url "https://git.securityops.co/cristiancmoises/securityops-channel")
  (branch "main")))
