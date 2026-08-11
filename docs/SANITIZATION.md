# Sanitization audit — what was removed and why

The Security Ops OS image is built from the same workstation this repo lives on,
but it is meant to be **handed to other machines and other people**. So the live
`config.scm` is a *clean-room* derivative of the maintainer's installed-system
configs: every active host disk/network identifier and every credential was
stripped, and every runtime hardware assumption was generalized. Historical
changelog entries, reference configs, and upstream package documentation can
still name non-secret development hardware, example paths, or legacy public
project URLs; none of those strings configures the live system.

This file is the checklist. If you fork the image, re-audit against it.

## Removed — secrets / personally-identifying data

| Item in the workstation config | Why it is gone from the live image |
|---|---|
| **LUKS mapped devices and their UUIDs** | Identify the owner's encrypted disks; useless and disclosive on a live USB. The live root is a read-only ISO + RAM overlay, so no host LUKS mapping is referenced. |
| **File-system, ESP, and swap UUIDs** | Machine-specific; the image gets its own deterministic ISO identity and uses no disk-backed swap. Anonymous compressed zram swap is created at boot instead. |
| **Personal resolver addresses/profile** | A personalized DNS profile is linkable to its owner. The live image uses DHCP DNS unless the operator opts into Tor routing. |
| **Private channel checkouts / SSH URLs** | Replaced with public HTTPS channel URLs. The channel introductions and substitute signing keys are public build inputs, not credentials. |
| **Mullvad / WireGuard kill-switch firewall** (the AMD config's nftables with `$MULVADIP`, `wg0-mullvad`, Steam/torrent ports) | References the owner's VPN topology. Replaced with a generic stateful firewall that has **no addresses in it**. |
| **SSH keys & `~/.ssh/securityops`, personal `authorized_keys`** | Never copied; the live home is generated empty + a tiny skeleton. |
| **Personal shell aliases / scripts and private service endpoints** | The live shell configuration contains only public, generic aliases and a greeting. |
| **Hashed account passwords from the host** | The live user has a **public, documented** password (`securityops`) so the image is usable by design; it is not the owner's. |

## Generalized — hardware assumptions

| Workstation assumption | Live-image replacement |
|---|---|
| Host-tuned kernel requiring `/etc/securityops.defconfig` | Portable `linux-securityops`, derived from nonguix's broad driver config and layered only with mainline hardening/performance options; `securityops/securityops.defconfig` is reference-only. |
| NVIDIA proprietary stack (`nvidia-driver`, `nvda-580`, `nonguix-transformation-nvidia`, `nvidia_drm.modeset=1`) | Dropped entirely — Mesa drives Intel `i915` and AMD `amdgpu`; both modules ship in the kernel and autoload by PCI ID |
| Intel-VMD `initrd-modules '("vmd")`, Optimus/MUX Sway env | Dropped — not portable |
| Single-vendor microcode | No early microcode archive: the ISO uses `base-initrd` because the prepended microcode cpio broke GRUB's live-image initrd hand-off. |
| Host-specific laptop thermal/EPP and gaming/Steam/controller udev tuning | Dropped — irrelevant on unknown hardware; generic 6 GiB zram swap and best-effort `schedutil` pacing remain portable and are retained. |
| Aggressive host-only KSPP/lockdown cmdline | Portable hardening arguments are shared by all entries; lockdown/signature enforcement stay disabled for security tooling, and per-GPU/IOMMU flags remain isolated to hardware-specific entries. |

## Kept — and safe to ship

- The **Security Ops logo** (`assets/sec.png`) — the user's own art, used on GRUB
  and the desktop.
- The **security toolset, terminals, editors, fonts** — all public Guix/nonguix
  packages.
- A loopback Tor SOCKS service plus dormant TransPort/DNSPort/ControlPort
  listeners. No transparent rule is active by default; Torando can opt one local
  user into transparent routing and a killswitch.
- pt_BR locale + `br/abnt2` keyboard (the maintainer's defaults; trivially changed
  — see the README).

## How to re-verify quickly

```sh
# No host mappings, personalized resolvers, VPN topology, or vendor stack:
grep -nE 'mapped-device|NextDNS|wg0-mullvad|NVreg|nvidia' config.scm || echo "clean"
```
