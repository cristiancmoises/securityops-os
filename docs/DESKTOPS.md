# Desktop choices

Security Ops OS exposes three explicit desktop sessions in the live greeter and
the guided installer:

| Choice | Display stack | Intended use |
|---|---|---|
| Sway | Native Wayland/wlroots | Default, smallest desktop attack surface and fastest recovery path |
| XMonad + XLibre | X11 on the pinned XLibre server | Keyboard-driven tiling and compatibility with X11 workflows |
| KDE Plasma | Native Wayland/KWin | Full integrated desktop |

At the live `tuigreet` screen, press **F3** to select a session. Sway is the
explicit default when no alternate session is selected. The username may be
remembered, but the password and session are not persisted; the live password
is regenerated on every boot and displayed only on trusted VT1.

The launchers are immutable Guix store objects. Sway starts the pinned Sway
binary, KDE starts `startplasma-wayland`, and the XMonad launcher starts
`xinit` against a wrapper constructed with `xlibre-configuration`. Ordinary
Xorg is never renamed or presented as XLibre. Session diagnostics are written
below `$XDG_STATE_HOME/securityops/sessions/`, not to predictable `/tmp` files.

## Installer behavior

The generated installed configuration contains only the selected desktop
package set. For `xmonad-xlibre`, the generated GDM service is explicitly
rewritten to use the pinned XLibre server and bounded XLibre driver set. If the
XLibre channel/module is unavailable, configuration evaluation fails; it does
not silently fall back to Xorg. `/etc/securityops/desktop` records the selected
declarative value (`sway`, `xmonad-xlibre`, or `kde`).

Password entry remains fail-closed. The guided installer can prove and change
the live keyboard mapping only through the caller-owned Sway IPC socket or a
real VT. When using the live XMonad or KDE session, log out and select Sway (or
switch to a real VT) before starting `security-ops-install`. No password is
requested before this check succeeds.

## Security boundaries

Desktop choice is not a cell, container, or VM boundary. In particular, X11
permits same-display clients to observe or inject substantially more input and
window state than native Wayland clients; select XMonad + XLibre only when that
compatibility tradeoff is acceptable. KDE's larger service and plugin closure
also has more attack surface than the default Sway session. XWayland retains
X11 semantics among XWayland clients even under Sway or KDE.

The XLibre server now ships inside the securityops channel, which is pinned to
commit `34a0099058eada895d92069f36feb2267ebfa203` with its published channel
introduction; the separate guix-xlibre channel is retired. The earlier
deterministic-integrity-only pin (Phase 29) no longer applies.
