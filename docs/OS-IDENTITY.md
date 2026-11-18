# Security Ops OS identity

Security Ops OS is a complete GNU/Linux distribution assembled and managed
declaratively with GNU Guix.  Guix is an important construction, package, and
upgrade foundation; it is not the product name.  Linux remains the kernel.

The live and installed systems expose one consistent distribution identity:

```text
$ uname
Linux
$ uname -s
Linux
$ uname -o
Security Ops OS
$ uname -a
Linux <hostname> <release>-SecurityOps <kernel-build> x86_64 Security Ops OS
```

Plain `uname` and `uname -s` intentionally retain the standard kernel-name
answer. Changing them to a distribution name would lie about the kernel API and
break software that detects Linux. `uname -r`, `uname -v`, and `uname -m` also
remain real kernel or hardware values. Only Coreutils' GNU-specific
`-o`/`--operating-system` field is distribution-branded, so `uname -a` includes
Security Ops OS without corrupting the other fields. GNU/Linux and Guix
provenance remains in `/etc/os-release`, `/etc/issue`, and this documentation,
rather than being appended to the requested product name.

This behavior comes from the source-built `securityops-coreutils` package
definition in `securityops/branding.scm`. It is not a shell alias, function,
environment-variable override, or mutable wrapper. The build fails if the
upstream source anchor changes, runs the upstream Coreutils test suite, and runs
additional checks for the default, `-s`, `-o`, and `-a` behavior.

`/etc/os-release` begins with:

```text
NAME="Security Ops OS"
ID=securityops
ID_LIKE=guix
PRETTY_NAME="Security Ops OS 1.14.0"
```

It also records `SECURITYOPS_SYSTEM_MANAGER="GNU Guix"` and
`SECURITYOPS_KERNEL="Linux"`. `/etc/issue` identifies Security Ops OS and its
GNU/Linux and Guix-managed foundation. The live hostname is
`securityops-live`; an installed system uses the hostname chosen during
installation.

## Licensing boundary

The original Security Ops OS configuration and other owner-authored first-party
components are offered under the project's AGPL-3.0-or-later/commercial
dual-license terms. Third-party components retain their own licenses. In
particular, GNU Coreutils and the patched `uname` binary remain
GPL-3.0-or-later; Security Ops OS does not and cannot relicense them under its
commercial license.

The identity states product ownership without concealing provenance. It does
not imply that Security Ops OS wrote Linux, GNU Coreutils, or GNU Guix.
