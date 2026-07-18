# Reproducible build contract

## Goal

A release should be independently attributable to exact public source and
dependencies. Byte-for-byte QCOW reproducibility is desirable but not assumed
until demonstrated because filesystem timestamps, disk UUIDs and image builders
may introduce nondeterminism.

## Required reproducibility

- Go module and toolchain versions are pinned.
- `flake.lock` is committed.
- GitHub Actions use full commit SHAs or no external actions.
- image manifests include source commit, workflow, NixOS version and lock digest.
- OCI artifacts are addressed by digest.
- SBOMs enumerate included packages.
- provenance attestations bind artifacts to the release workflow.
- release commands include `-trimpath` and deterministic version metadata.
- build inputs never use mutable `latest` references.

## Independent rebuild modes

```bash
nix build .#workstation-basic-image
nix build .#downloader-image
nix build .#scanner-image
nix build .#exporter-image
go build -trimpath ./cmd/private-vm
```

A `private-vm images compare-builds` command should later compare:

- package closure identities;
- image manifest;
- partition layout;
- file inventory and hashes after a controlled guest-side inventory;
- permitted nondeterministic fields.

## CI design

A periodic clean job rebuilds locked inputs and compares semantic image identity.
It does not update dependencies. Dependency updates arrive through reviewed pull
requests.

## Release trust statement

The project must distinguish:

1. **source reproducibility** — exact inputs and process are public;
2. **semantic reproducibility** — installed files/packages/config match;
3. **byte reproducibility** — artifact bytes match.

Do not claim level 3 before the comparison job proves it.
