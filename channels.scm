;; channels.scm — channels for a reproducible Security Ops live build.
;;
;; Upstream guix + nonguix, plus the channels used by the image:
;;   * sops-guix / gocix — authenticated transitive small-guix dependencies.
;;   * small-guix   — provides Mullvad VPN.
;;   * securityops  — the curated app set (kitty, Tor Browser, Torando, …).
;;
;; Build reproducibly with:
;;   ./build.sh --pinned
;;
;; Every channel is commit-pinned and authenticated where the channel publishes
;; an introduction.  The image and build wrapper use Security Ops as the first
;; substitute and GNU Guix CI as the second; channel Git repositories remain
;; source inputs.

(list
 (channel
  (name 'guix)
  ;; Authenticated mirror of the Savannah repository.  The installed
  ;; Guix/libgit2 hits a repeatable TLS syscall failure against Savannah; the
  ;; introduction and pinned commit still authenticate the channel contents.
  (url "https://codeberg.org/guix/guix.git")
  (branch "master")
  (commit "b9a35ee6b53438d53d66cbe3e82f26bb22a44b5b")
  (introduction
   (make-channel-introduction
    "9edb3f66fd807b096b48283debdcddccfea34bad"
    (openpgp-fingerprint
     "BBB0 2DDF 2CEA F6A8 0D1D  E643 A2A0 6DF2 A33A 54FA"))))

 (channel
  (name 'nonguix)
  (url "https://gitlab.com/nonguix/nonguix")
  ;; Compatibility pin declared by the Security Ops channel: newer Nonguix
  ;; changed make-google-chrome from (repo version hash) to (repo), which makes
  ;; the authenticated Security Ops head fail while compiling its profile.
  (commit "bf39542ca537fde8839b209ac21d6f3254469b15")
  (introduction
   (make-channel-introduction
    "897c1a470da759236cc11798f4e0a5f7d4d59fbc"
    (openpgp-fingerprint
     "2A39 3FFF 68F4 EF7A 3D29  12AF 6F51 20A0 22FB B2D5"))))

 ;; Explicitly pin small-guix's transitive dependency chain.  Leaving either
 ;; dependency implicit would let its mutable `main' branch change a future
 ;; time-machine build despite the top-level small-guix pin.
 (channel
  (name 'sops-guix)
  (url "https://github.com/fishinthecalculator/sops-guix")
  (branch "main")
  (commit "c53e27e533836ea8595626ba6796dee5362f8c4a")
  (introduction
   (make-channel-introduction
    "0bbaf1fdd25266c7df790f65640aaa01e6d2dbc9"
    (openpgp-fingerprint
     "8D10 60B9 6BB8 292E 829B  7249 AED4 1CC1 93B7 01E2"))))

 (channel
  (name 'gocix)
  (url "https://github.com/fishinthecalculator/gocix")
  (branch "main")
  (commit "5cbc7d0cb911dd27eb364d350ac5a1ef43308316")
  (introduction
   (make-channel-introduction
    "cdb78996334c4f63304ecce224e95bb96bfd4c7d"
    (openpgp-fingerprint
     "8D10 60B9 6BB8 292E 829B  7249 AED4 1CC1 93B7 01E2"))))

 ;; Mullvad VPN package used by config.scm.
 (channel
  (name 'small-guix)
  (url "https://codeberg.org/fishinthecalculator/small-guix.git")
  (branch "main")
  (commit "042722ed1c20f41e3b85e6eee022f19cc2d1646d")
  (introduction
   (make-channel-introduction
    "f260da13666cd41ae3202270784e61e062a3999c"
    (openpgp-fingerprint
     "8D10 60B9 6BB8 292E 829B  7249 AED4 1CC1 93B7 01E2"))))

 ;; securityops — the maintainer's curated channel (browsers, tor, mullvad,
 ;; kitty, torando service …).  Provides (securityops packages …) modules.
 (channel
  (name 'securityops)
  (url "https://git.securityops.com.br/cristiancmoises/securityops-channel.git")
  (branch "main")
  (commit "98df294f8e626cc16374a20785943c20eb1636ec")
  (introduction
   (make-channel-introduction
    "af46f5cce66179f3e53f87c86ca2538c8fc63f98"
    (openpgp-fingerprint
     "0CFA 43B9 AA96 42EA AF2B  E983 C4C6 61C9 ECFB 46E8")))))
