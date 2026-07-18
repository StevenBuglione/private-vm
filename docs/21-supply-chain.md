# Supply-chain security

## Artifact model

Each released binary/package/image has:

- SHA-256 digest
- SPDX JSON SBOM
- build manifest
- GitHub artifact attestation
- source repository and commit
- workflow identity
- semantic version
- architecture
- role/bundle where applicable

## OCI layout

Repository examples:

```text
ghcr.io/stevenbuglione/private-vm/workstation-basic
ghcr.io/stevenbuglione/private-vm/workstation-development
ghcr.io/stevenbuglione/private-vm/downloader
ghcr.io/stevenbuglione/private-vm/scanner
ghcr.io/stevenbuglione/private-vm/exporter
```

OCI media types:

```text
application/vnd.private-vm.qcow2+zstd
application/vnd.private-vm.manifest.v1+json
application/spdx+json
application/vnd.dev.sigstore.bundle+json
```

The CLI uses `oras-go` rather than Docker.

## Verification order

1. parse reference without executing content
2. resolve tag to immutable digest
3. pull manifest with byte limits
4. verify OCI content digests
5. verify provenance bundle
6. require official repository identity
7. require approved workflow identity
8. require expected tag/ref constraints
9. verify image manifest schema
10. verify role, bundle, arch, protocol, and minimum host requirements
11. verify decompressed QCOW2 digest
12. atomically install read-only cache entry

Any failure deletes partial data.

## Trust policy

Official default:

```text
repository: StevenBuglione/private-vm
workflow: .github/workflows/release.yml
issuer: GitHub Actions OIDC
visibility: public
```

Custom registries require a separate explicit trust configuration and warnings.
The official client does not accept unsigned custom artifacts merely because the
registry is user-configured.

## Image cache

```text
/var/lib/private-vm/images/sha256/<digest>/
├── image.qcow2
├── manifest.json
├── sbom.spdx.json
└── provenance.json
```

- root-owned
- base image mode `0444`
- directory not writable by normal users
- atomic temp-to-final rename
- periodic integrity verification
- active session holds digest reference so prune cannot remove it

## Dependency policy

- Go modules pinned in `go.mod` and vendored for release
- Nix dependencies pinned in `flake.lock`
- GitHub actions pinned by full SHA
- Renovate/Dependabot opens reviewed PRs
- no auto-merge of security-critical dependencies
- QEMU, cryptsetup, kernel, nftables, protobuf, gRPC, OCI, and Sigstore changes
  require focused review

## SBOM

Generate SBOMs for:

- each Go binary
- each DEB/RPM/tar release
- each NixOS image closure

The image SBOM should include Nix store package identities and versions, not just
the compressed QCOW2 file.

## Reproducibility workflow

A second clean job:

- checks out tag
- uses locked toolchains
- rebuilds selected artifacts
- compares normalized result/closure manifests
- reports byte-level differences
- never overwrites published artifact

## Revocation

Maintain a signed revocation feed or repository file containing:

- compromised version/digest
- reason
- date
- fixed version
- severity

`images sync` refuses known-revoked digests even if their historical provenance
is valid.
