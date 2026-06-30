# Sanitization audit — what was removed and why

The SecurityOps OS image is built from the same workstation this repo lives on,
but it is meant to be **handed to other machines and other people**. So the live
`config.scm` is a *clean-room* derivative of the installed system configs
(`predator-helios-intel/config.scm` and `ryzen-2200g-amd/config.scm`): every
host-specific identifier and every personal secret was stripped, and every
hardware assumption was generalized.

This file is the checklist. If you fork the image, re-audit against it.

## Removed — secrets / personally-identifying data

| Item in the workstation config | Why it is gone from the live image |
|---|---|
| **LUKS mapped-devices** (`cryptroot`/`crypthome` UUIDs `9f72…`, `70b7…`) | Identify the owner's encrypted disks; useless and disclosive on a live USB. The live root is a read-only ISO + RAM overlay, so no LUKS is referenced at all. |
| **File-system & ESP UUIDs** (`6447-6147`, `38467002-…`, `02E2-0AB2`, …) | Machine-specific; the image gets a deterministic ISO label/UUID instead. |
| **Swap UUID** (`85b7b3d8-…`) | Host-specific; the live image has no swap device. |
| **Personal NextDNS resolvers** (`45.90.28.213`, `45.90.30.213`, the IPv6 pair) | A NextDNS profile is linkable to its owner. The live image uses plain DHCP DNS (optionally Tor); no personalized resolver is baked in. |
| **Private forge URLs** (`git.securityops.co/...` mirrors of guix/nonguix/radix/…) | SSH-key-only and tied to the owner. `channels.scm` uses **public** upstreams only (`git.savannah.gnu.org`, `gitlab.com/nonguix`). |
| **Mullvad / WireGuard kill-switch firewall** (the AMD config's nftables with `$MULVADIP`, `wg0-mullvad`, Steam/torrent ports) | References the owner's VPN topology. Replaced with a generic stateful firewall that has **no addresses in it**. |
| **SSH keys & `~/.ssh/securityops`, personal `authorized_keys`** | Never copied; the live home is generated empty + a tiny skeleton. |
| **Personal shell aliases / scripts** (`~/scripts/*`, `yt.securityops.co`, torando, toggle-vpn, server endpoints) | The live `config.fish` is a 6-line greeting only. |
| **Hashed account passwords from the host** | The live user has a **public, documented** password (`securityops`) so the image is usable by design; it is not the owner's. |

## Generalized — hardware assumptions

| Workstation assumption | Live-image replacement |
|---|---|
| Custom-compiled `securityops` kernel needing `/etc/securityops.defconfig` | Stock nonguix `linux` (broad in-tree drivers, has substitutes) |
| NVIDIA proprietary stack (`nvidia-driver`, `nvda-580`, `nonguix-transformation-nvidia`, `nvidia_drm.modeset=1`) | Dropped entirely — Mesa drives Intel `i915` and AMD `amdgpu`; both modules ship in the kernel and autoload by PCI ID |
| Intel-VMD `initrd-modules '("vmd")`, Optimus/MUX Sway env | Dropped — not portable |
| Single-vendor microcode | `microcode-initrd` bundles **AMD + Intel** microcode for early load |
| Laptop thermal/EPP/zram tuning, gaming/Steam/controller udev | Dropped — irrelevant on unknown hardware |
| Aggressive KSPP/lockdown cmdline (host-tuned) | Minimal cmdline (`quiet`) so the image boots reliably on any machine; per-GPU flags live on the Intel/AMD GRUB entries |

## Kept — and safe to ship

- The **SecurityOps logo** (`assets/sec.png`) — the user's own art, used on GRUB,
  the SLiM login, and the desktop.
- The **security toolset, terminals, editors, fonts** — all public Guix/nonguix
  packages.
- A **plain Tor** SOCKS service and `torsocks` (no transparent-proxy redirection,
  to keep networking predictable on foreign hardware).
- pt_BR locale + `br/abnt2` keyboard (the maintainer's defaults; trivially changed
  — see the README).

## How to re-verify quickly

```sh
# No UUIDs, no private hosts, no NextDNS, no mapped-devices in the live config:
grep -nE 'uuid|mapped-device|luks|45\.90\.|securityops\.co|wg0-mullvad|NVreg|nvidia' config.scm || echo "clean"
```
