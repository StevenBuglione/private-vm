# NixOS image build

## Canonical source

NixOS 26.05 configuration under `nix/guests/` is the source of truth. The project
uses the image-building facilities exposed by NixOS and pins Nixpkgs in
`flake.lock`.

Do not provision an OS interactively with Packer.

## Build outputs

The flake must expose:

```text
packages.x86_64-linux.private-vm
packages.x86_64-linux.private-vmd
packages.x86_64-linux.private-vm-guestd
packages.x86_64-linux.guestd-workstation
packages.x86_64-linux.guestd-downloader
packages.x86_64-linux.guestd-scanner
packages.x86_64-linux.guestd-exporter
packages.x86_64-linux.image-workstation-basic
packages.x86_64-linux.image-workstation-office
packages.x86_64-linux.image-workstation-development
packages.x86_64-linux.image-downloader
packages.x86_64-linux.image-scanner
packages.x86_64-linux.image-exporter
packages.x86_64-linux.sbom-scanner
nixosModules.default
checks.x86_64-linux.default
checks.x86_64-linux.desktop-role-isolation
checks.x86_64-linux.downloader-desktop
checks.x86_64-linux.guest-common
checks.x86_64-linux.scanner-image-contract
checks.x86_64-linux.scanner-update
checks.x86_64-linux.scanner-offline
checks.x86_64-linux.workstation-bundles
checks.x86_64-linux.workstation-desktop
devShells.x86_64-linux.default
```

The generic `private-vm-guestd` output is included for packaging but has no
compiled role and refuses to serve. Each image consumes only its matching
role-specific guestd output, which prevents a boot-time argument from changing
the API surface.

Images use the NixOS 26.05 `image.modules.qemu-efi` configuration and
`system.build.images.qemu-efi` output. This produces the canonical GPT/UEFI
QCOW2 derivations without an external image generator. Do not use the archived
`nixos-generators` project as a long-term dependency.

## Image properties

- GPT/UEFI boot
- QCOW2
- fixed virtual sizes by role
- sparse/compressed
- no build secrets
- no mutable machine ID
- no SSH host keys
- no package manager credentials
- versioned role identity embedded at `/etc/private-vm/image.json`
- guestd enabled
- base disk expected read-only at runtime

The embedded identity follows `schemas/guest-image-identity.schema.json`. It is
distinct from the post-build release artifact manifest in
`schemas/image-manifest.schema.json`, which adds output digests, sizes, SBOM,
workflow identity, and build timestamp.

## Reproducibility

A build manifest records:

- Nixpkgs locked revision
- flake lock digest
- source commit
- guestd binary digest
- Nix derivation path
- output digest
- build architecture
- CI runner image
- image role/bundle
- build timestamp as metadata, not input where avoidable

Bit-for-bit reproducibility may be affected by filesystem/image metadata. The
project must distinguish:

- reproducible source/closure
- reproducible normalized content
- byte-identical QCOW2

The reproducibility workflow should normalize or compare extracted image
contents when byte identity is not yet achieved.

## Packer

`packer/acceptance.pkr.hcl` may:

- accept an existing QCOW2 path
- boot it
- wait for guestd readiness
- run an acceptance client
- shut it down

It must not contain installation/provisioning scripts.

## Local build

```bash
nix build .#image-workstation-basic
nix build .#image-downloader
nix build .#checks.x86_64-linux.guest-common
nix build .#checks.x86_64-linux.workstation-desktop
nix build .#checks.x86_64-linux.scanner-image-contract
nix build .#checks.x86_64-linux.scanner-update
nix build .#checks.x86_64-linux.scanner-offline
```

## Image tests

Each image must prove:

- correct role
- correct capability set
- no SSH listener
- no persistent journal
- guestd VSOCK readiness
- expected desktop target for graphical images
- no desktop/network in exporter
- scanner scan specialization has no NIC
- QEMU device allowlist compatibility

The `guest-common` NixOS VM test is the first executable boot gate. It boots a
minimal common guest and verifies locked accounts, disabled SSH and sudo,
tmpfs-backed writable logs/temporary paths, volatile journald, an exact embedded
role identity, a matching compiled guestd identity, no TCP/UDP listeners, and a
VSOCK listener on port 4050. The role-specific image tests extend this baseline.

The `workstation-desktop` test forces TCG, supplies a SPICE vdagent channel with
clipboard and agent file transfer disabled, and proves LightDM autologin reaches
an XFCE session for the locked `private` user. It also verifies both agent
processes and the channel, workspace directory permissions, exact basic-bundle
manifest, exact locked Firefox enterprise policy values and crash-reporter
environment, client-only OpenSSH output, absence of implicit XFCE applications,
SSH/sudo services, and TCP/UDP listeners. The separate
`workstation-bundles` check evaluates and compares the embedded manifests for
all three official workstation variants.

The `desktop-role-isolation` check builds the downloader and scanner system
paths, proves their role-required tools are installed, and rejects workstation
viewers, preview helpers, NetworkManager applet, and other implicit XFCE
applications from those roles.

The `downloader-desktop` test boots the downloader under TCG and proves its
exact compiled role/capability set, XFCE and WireGuard tools, absence of
personal-work applications and embedded VPN/torrent credentials, and an
initial default-drop nftables policy. It mounts a disposable test quarantine,
creates a dummy `proton0`, and verifies that qBittorrent cannot start before a
root-owned volatile VPN-ready marker exists. After readiness it verifies the
service and loopback-only listeners, the immutable `proton0` binding, volatile
logging/profile paths, bounded stop, fail-closed restart, and syntax of both
typed endpoint firewall templates. NET-003 remains responsible for rendering
those templates and continuously withdrawing readiness on tunnel failure.

The scanner has three focused gates. `scanner-image-contract` checks both boot
configurations, every required executable, fail-closed ClamAV limits, absence of
workstation/downloader tools, and one-to-one package/version coverage between
the embedded tool inventory and SPDX document. `scanner-update` boots the online
phase without quarantine and performs a deterministic FreshClam database update
from a non-secret local test database, rather than treating `--version` as an
update proof. `scanner-offline` passes explicit `-nic none`, attaches a generated
quarantine filesystem through a read-only QEMU block backend, verifies that only
loopback exists, mounts it `ro,nodev,nosuid,noexec`, and proves a write fails.
Both boot tests compare the scanner role and exact sorted RPC capability list.

Run the two scanner VM gates serially. Each is configured for 2 GiB of guest RAM;
do not run them together on a 16 GiB development host.
