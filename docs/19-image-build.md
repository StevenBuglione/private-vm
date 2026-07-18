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
nixosModules.default
checks.x86_64-linux.default
devShells.x86_64-linux.default
```

The generic `private-vm-guestd` output is included for packaging but has no
compiled role and refuses to serve. Each image consumes only its matching
role-specific guestd output, which prevents a boot-time argument from changing
the API surface.

The initial Nix task must choose and lock one of the supported NixOS 26.05 image
interfaces:

- `system.build.images` / `nixos-rebuild build-image`
- or a project wrapper around the official `image/repart.nix` plus deterministic
  `qemu-img` conversion

Do not use the archived `nixos-generators` project as a long-term dependency.

## Image properties

- GPT/UEFI boot
- QCOW2
- fixed virtual sizes by role
- sparse/compressed
- no build secrets
- no mutable machine ID
- no SSH host keys
- no package manager credentials
- role manifest embedded
- guestd enabled
- base disk expected read-only at runtime

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
