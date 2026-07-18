# Guest images and desktop design

## Image catalog

Official x86_64 images:

```text
workstation-basic
workstation-office
workstation-development
downloader
scanner
exporter
```

Optional later:

```text
workstation-media
workstation-research
workstation-plasma
aarch64 variants
```

## Common NixOS baseline

- NixOS 26.05 pinned by `flake.lock`
- QEMU guest profile and virtio kernel modules
- systemd-networkd or NetworkManager according to role
- no SSH server
- no reusable password
- no sudo for desktop user
- volatile journald
- volatile `/tmp`
- automatic guestd startup
- guestd listens only on VSOCK
- no cloud-init
- no host keys baked in
- role and build metadata in `/etc/private-vm/image.json`
- automatic poweroff on guestd completion when role requires it

## XFCE workstation

Desktop user:

```text
name: private
autologin: local display only
sudo: none
password: locked
home: session overlay
```

Base applications:

- Firefox
- VSCodium
- LibreOffice for office/development bundles
- XFCE terminal
- Thunar
- Mousepad
- Evince
- Ristretto
- File Roller
- Git
- OpenSSH client
- curl/jq
- KeePassXC
- Zenity for guestd status/warnings

No guest should contain user credentials at image-build time.

## Browser defaults

- private browsing default
- telemetry/crash upload disabled
- password/form history disabled
- HTTPS-only
- downloads not auto-opened
- downloads to `~/Downloads`
- no extensions in official image
- no host integration
- profile destroyed with overlay

## Development bundle

Include:

- Go 1.26 toolchain
- JDK
- Kotlin compiler/Gradle tooling as selected by locked Nixpkgs
- Rust stable
- Python
- Node.js
- common compilers and build tools
- VSCodium

Do not bake GitHub tokens, SSH keys, package registry credentials, or mutable
language caches.

## Scanner desktop

Applications are intentionally limited:

- terminal
- Thunar configured not to thumbnail or preview
- text/hex inspection tools
- scan report viewer
- reconstruction tools
- no browser in offline scan boot if it can be omitted
- no file auto-open

## Downloader desktop

- qBittorrent graphical interface
- no general browser by default
- no media/file preview handlers
- no office suite
- no development credentials
- no host import path

## Exporter image

- no desktop
- no login
- no network manager
- guestd
- cryptsetup
- ext4 tools
- USB storage/filesystem drivers
- checksum tools

## Image manifest

Every image includes and publishes:

```text
schema version
role
bundle
architecture
NixOS release
flake lock SHA-256
source repository
source commit
build workflow
guest protocol
guestd version
virtual disk format
virtual size
compressed/uncompressed digest
minimum QEMU
required devices
forbidden devices
package/SBOM references
```

The manifest capability set must exactly equal the compiled role map in
`docs/09-rpc-protocol.md`. Extra, missing, or duplicate capabilities are a fatal
handshake mismatch; capabilities do not silently negotiate across roles.

## Update model

Images are replaced, never in-place upgraded during a user session. The CLI may
pull a newer verified image before the next session.

Scanner signatures are updated ephemerally at runtime, separate from image
updates.
