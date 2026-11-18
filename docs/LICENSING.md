# Security Ops OS licensing

The first-party Security Ops OS image definition is available under either
`AGPL-3.0-or-later` or a separate written commercial agreement signed by the
applicable copyright holder and licensee. The full public license is in
[`LICENSE`](../LICENSE) and [`LICENSE-AGPL-3.0`](../LICENSE-AGPL-3.0).
[`LICENSE-COMMERCIAL`](../LICENSE-COMMERCIAL) is only an inquiry and scope
notice; it is not a public commercial grant.

Two files are expressly outside that dual-license scope:
`securityops/installer/cow-system-init.scm` and `securityops/bootloader.scm`
are narrow derivatives of GNU Guix installer/bootloader code and are
distributed under `GPL-3.0-or-later` only. Security Ops does not assert a
commercial relicensing option for upstream-derived rights it does not
exclusively control.

“Commercial use” and “commercial license” are different. The AGPL permits
commercial use when its conditions are met. A separate commercial agreement
is an alternative for first-party code when a licensee needs different terms.
The exact rights exist only in the executed agreement.

## Aggregate-image boundary

Security Ops OS is a complete Linux distribution built and updated with GNU
Guix. Its ISO aggregates works from many copyright holders. Neither the AGPL
nor a Security Ops commercial agreement replaces the component licenses.
Linux, GNU Guix, bootloaders, desktop software, firmware, libraries,
applications, fonts, and every other package retain their own terms.

The inspected local first-party repositories declare these independent
options:

| Project | Public option | Separate commercial option |
|---|---|---|
| Security Ops OS first-party image definition | AGPL-3.0-or-later | Requires an executed Security Ops OS agreement |
| `securityops/installer/cow-system-init.scm` (GNU Guix-derived helper) | GPL-3.0-or-later | None asserted; upstream-derived rights are excluded |
| `securityops/bootloader.scm` (GNU Guix-derived branded EFI installer) | GPL-3.0-or-later | None asserted; upstream-derived rights are excluded |
| Evelin | AGPL-3.0-or-later | Requires an executed Evelin agreement |
| Esquema | GPL-3.0-or-later | None declared by the canonical source observed in Phase 30 |
| VaptVupt | AGPL application scope; GPL codec scope | May cover only controlled first-party rights under an executed agreement |
| VaptVupt Codec | GPL-3.0-or-later | May cover only controlled first-party rights under an executed agreement |
| libvuptsdk | AGPL-3.0-or-later | Requires an executed libvuptsdk agreement |
| Mirim | AGPL-3.0-only engine scope; explicitly marked support files remain MIT | Requires an executed Mirim agreement for controlled first-party rights |
| Cofre Soberano PQ | AGPL-3.0-or-later | Requires an executed Cofre Soberano PQ agreement |
| BTP | Apache-2.0 implementation; CC-BY-4.0 specification | No separate option declared by the inspected checkout |
| Security Ops Guix channel code | GPL-3.0-or-later | None declared by this checkout |

The table records the inspected local declarations; it does not grant rights.
A commercial agreement for one project does not cover another unless it says
so expressly. Unlisted Security Ops tools must be evaluated from their
canonical repository and executed agreement; common ownership, packaging in
Guix, or inclusion in this ISO does not create a commercial license.

The Guix package definition for a component records its distributable public
license option. It does not place a private commercial contract or key in the
Guix store and does not change upstream licensing.

Commercial licensing inquiries: `sac@securityops.co`. This document is a
repository policy summary, not legal advice.
