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
- no inherited NixOS curl/OpenSSH core clients; roles add network tools explicitly
- no reusable password
- no sudo for desktop user
- volatile journald
- tmpfs-backed `/tmp`, `/var/tmp`, and `/var/log`
- no swap or resume device and no sleep, suspend, or hibernation targets
- no coredumps or unattended Nix garbage collection
- automatic guestd startup
- guestd listens only on VSOCK
- guestd has a strict systemd sandbox and device allowlist
- no cloud-init
- no host keys baked in
- role and build metadata in `/etc/private-vm/image.json`
- automatic poweroff on guestd completion when role requires it

The common image replaces NixOS's normal interactive core package set with a
small audited shell/diagnostic set. This prevents `curl`, the stock OpenSSH
output and unrelated administration tools from appearing in every role by
default. Workstation bundles add curl and a server-pruned OpenSSH client
explicitly; the scanner contract rejects both in its update and offline boots.

## XFCE workstation

Desktop user:

```text
name: private
autologin: local display only
sudo: none
password: locked
home: session overlay
```

The role-neutral XFCE module contains the display manager, shell components,
locked local user, NetworkManager service, and SPICE agent only. It explicitly
excludes the upstream module's optional media player, image/text viewers,
terminal, screenshot/task-manager tools, audio controls, thumbnailer, GVFS,
UDisks integration, and NetworkManager applet. Its screen saver and
ModemManager are disabled because the locked disposable account has no unlock
credential and the typed QEMU models expose no modem hardware. Workstation
applications are selected from the versioned catalog in
`project/workstation-bundles.json`; downloader and scanner images do not inherit
Firefox or workstation document viewers.

The catalog's `openssh-client` identifier maps to a client-only pinned OpenSSH
derivation. The SSH daemon, daemon helpers, SFTP server, server configuration,
and moduli file are removed from that output; the image also disables the sshd
unit and SSH-agent startup.

The `basic` bundle contains:

- Firefox
- Git and OpenSSH client
- curl and jq
- KeePassXC
- XFCE Terminal and Thunar
- Mousepad
- Evince
- Ristretto
- File Roller
- Zenity for guestd status/warnings

The `office` bundle adds LibreOffice, Hunspell, and the US English dictionary.
The `development` bundle includes the office bundle plus VSCodium, Go, JDK,
Kotlin, Gradle, Rust/Cargo, Python, Node.js, GCC, GDB, CMake, GNU Make, and
pkg-config.

Each image embeds the selected, sorted logical package list at
`/etc/private-vm/workstation-bundle.json`. Nix maps every catalog identifier to
one pinned package and fails evaluation on an unknown, duplicate, unsorted, or
wrong-bundle declaration. The catalog is exact for user-facing workstation
applications; the fixed XFCE shell and support components described above are
shared infrastructure rather than bundle entries.

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

NixOS installs these controls through `programs.firefox`, not as an unused
policy declaration. Managed preferences also disable form/password history,
telemetry, account sync, profile import, crash-session resume and submission,
prefetch and network prediction, WebRTC, and post-update/first-run pages. The
graphical session also sets Mozilla's crash-reporter disable environment flag.
The policy file and effective session environment are verified during the
desktop boot test.

Do not bake GitHub tokens, SSH keys, package registry credentials, or mutable
language caches into any development image.

## Scanner desktop

Applications are intentionally limited:

- terminal
- Thunar configured not to thumbnail or preview
- text/hex inspection tools
- scan report viewer
- reconstruction tools
- no browser in offline scan boot if it can be omitted
- no file auto-open

The scanner is one immutable image with two boot configurations over the same
per-session root overlay. The default `definitions-update` configuration enables
NetworkManager and `freshclam` but declares quarantine attachment forbidden. The
`scan-offline` specialization disables NetworkManager, DHCP, resolved and the
FreshClam service/timer. The daemon must also render the scan launch with no NIC;
disabling guest services is not accepted as evidence that a network device is
absent.

`/etc/private-vm/scanner-toolchain.json` records the exact Nix package name and
version for ClamAV, file identification, bounded archive primitives, parser
containment, PDF/Office/image/media reconstruction and metadata inspection.
Those same direct tool identities appear in the embedded SPDX 2.3 document at
`/etc/private-vm/scanner-sbom.spdx.json` and the separate `sbom-scanner` flake
output. This toolchain SBOM is immutable image identity evidence; release
publication later augments it with the complete image-closure SBOM and artifact
digest.

The image contains no browser, password manager, source-control/SSH client,
development toolchain or downloader client. LibreOffice is present only as the
required headless Office-to-PDF reconstruction backend. Thunar and the terminal
remain for the explicitly graphical inspection role, with thumbnailing, GVFS
and UDisks disabled.

## Downloader desktop

- qBittorrent graphical interface
- no general browser by default
- no media/file preview handlers
- no office suite
- no development credentials
- no host import path

## Exporter image

- no desktop
- no unlocked login or normal user
- no network manager
- guestd
- cryptsetup
- ext4 tools
- USB storage/filesystem drivers
- udev and USB identity inspection tools
- checksum tools

The exporter defaults to `multi-user.target`, overrides NixOS's normally
inherited `system.fsPackages` to omit FAT/compatibility filesystem formatters,
omits UDisks, and is boot-tested with no emulated NIC. Its role-specific
guestd advertises the common service plus only the exact exporter capability
set; workstation, downloader and scanner services are not registered. USB
attachment and the narrowly scoped device access needed for a confirmed export
are runtime responsibilities and are not exercised by the image test.

`/etc/private-vm/exporter-tools.json`, validated by
`schemas/exporter-tool-inventory.schema.json`, records the exact Nix package
names, versions and store paths for the exporter formatting, filesystem,
USB/udev and checksum tool closure. The boot test verifies those paths and
commands. This inventory is image-local evidence for the later closure-based
SPDX generation; it is not itself an SBOM and does not replace the published
release SBOM.

## Image identity and published manifest

Every guest embeds `/etc/private-vm/image.json`, validated by
`schemas/guest-image-identity.schema.json`. The embedded identity contains only
facts available inside the immutable image:

```text
schema version
role and optional bundle
architecture
NixOS release
flake lock SHA-256
source repository and commit
guest protocol version
guestd version
exact sorted capability set
```

The role-specific `private-vm-guestd --version` record repeats its compiled
role, exact capabilities, protocol version, source commit, and binary version.
A generic packaging build reports `uncompiled` and refuses to serve.

The separately published artifact manifest, validated by
`schemas/image-manifest.schema.json`, adds release facts that cannot be embedded
before the image exists:

```text
build workflow
virtual disk format
virtual size
compressed/uncompressed digest
minimum QEMU
required devices
forbidden devices
package/SBOM references
```

Both identity records' capability sets must exactly equal the compiled role map
in `docs/09-rpc-protocol.md`. Extra, missing, or duplicate capabilities are a
fatal handshake mismatch; capabilities do not silently negotiate across roles.

## Update model

Images are replaced, never in-place upgraded during a user session. The CLI may
pull a newer verified image before the next session.

Scanner signatures are updated ephemerally at runtime, separate from image
updates.
