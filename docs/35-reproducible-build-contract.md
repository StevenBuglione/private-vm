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
- embedded image identities include source commit, NixOS version, lock digest,
  protocol version, role, and exact capabilities.
- published image manifests add workflow identity, output digests, sizes, SBOM,
  and provenance-related metadata.
- OCI artifacts are addressed by digest.
- SBOMs enumerate included packages.
- provenance attestations bind the compressed artifact digest to the exact
  release workflow, protected immutable Git SemVer/RC tag, source commit, GitHub
  repository/owner numeric IDs, and run invocation. The client verifies the
  saved Sigstore bundle offline against its reviewed embedded trust snapshot.
- a bounded Go producer validates the single regular QCOW2, records its virtual
  size, hashes the complete source, uses a fixed single-worker zstd profile, and
  derives the manifest and SPDX document from the same bytes and exact sorted
  `system.build.toplevel` closure.
- the exact empty OCI config and ordered four-layer manifest are canonical JSON;
  each release receipt is a closed version-1 public-digest record with no local
  staging path or credential.
- the producer refuses an existing package SemVer/RC tag, rechecks absence,
  creates it conditionally and confirms the resolved digest. GHCR tag
  immutability is not assumed; the post-publication execution identity is the
  resolved manifest digest.
- release commands include `-trimpath` and deterministic version metadata.
- build inputs never use mutable `latest` references.

## Independent rebuild modes

```bash
nix build .#image-workstation-basic
nix build .#image-downloader
nix build .#image-scanner
nix build .#image-exporter
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

The REL-003 verification job does not reuse the publisher workspace or
credential. It starts on a fresh standard runner, resolves the just-published
tag anonymously, pulls by the resolved digest and runs the official offline
provenance/SBOM verifier. Local deterministic and policy tests may complete
without waiting for that remote job, but remote publication and visibility are
not reproducibility evidence until the job succeeds.

## Release trust statement

The project must distinguish:

1. **source reproducibility** — exact inputs and process are public;
2. **semantic reproducibility** — installed files/packages/config match;
3. **byte reproducibility** — artifact bytes match.

Do not claim level 3 before the comparison job proves it.
