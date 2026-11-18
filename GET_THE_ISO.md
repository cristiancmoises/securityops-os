# Download the Security Ops OS live ISO

> **Temporarily unavailable — v1.14.0 is being revalidated.**
>
> A boot regression was found during QEMU validation of the v1.14.0 image.
> The release assets have been withdrawn from every public mirror and no
> direct link, torrent, magnet link or checksum is published until a fixed
> image passes boot validation on both QEMU and physical hardware.

## Build it yourself

The source in this repository remains public and buildable. Clone the tagged
source and run the maintainer tool. It validates the canonical OS settings,
uses the pinned channel set and the ordered substitute servers (Security Ops
build farm first, GNU Guix CI second), builds the image and verifies its
checksum:

```sh
git clone --branch v1.14.0 --depth 1 \
  https://github.com/cristiancmoises/securityops-os.git
cd securityops-os
./securityopsctl doctor
./securityopsctl build
```

See the README and `./securityopsctl --help` for package, kernel, release and
resource-control commands.

© Cristian Cezar Moisés · sac@securityops.co · AGPL-3.0-or-later
