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

IMG-001 implements a read-only anonymous HTTPS ORAS client. It opens no Docker
daemon or credential store, resolves every tag to a canonical SHA-256 manifest
descriptor before fetching any layer, and fetches only descriptors from that
immutable manifest. Digest references are resolved as well and must return the
exact requested digest.

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

The pull boundary applies one overall deadline and a bounded HTTP-request
deadline, independently hashes every fetched descriptor, and accepts exactly
one layer for each documented v1 media type. The manifest is a closed frozen-v1
document: it has no subject, artifact type or annotations; its config descriptor
has exactly the OCI empty-config media type, two-byte `{}` size and SHA-256, and
the fetched config bytes must be exactly `{}`. Config and layer descriptors have
no URL, embedded data, platform or artifact-type channels. Config annotations
are forbidden. Every layer has exactly one annotation: the OCI title with the
documented fixed source filename. Missing titles, extra annotations, absolute
paths, traversal names, aliases, duplicate or unknown media types and
non-SHA-256 descriptors are rejected. The resolved manifest descriptor likewise
cannot carry URLs, embedded data, annotations, a platform or an artifact type.
The compressed QCOW2 is first written to one hidden bounded file,
fully counted, hashed, matched to its OCI descriptor, cleanly closed and rewound;
only then is the zstd decoder constructed over that same private file
description. Decoding uses one worker and bounded decoder memory, while
installed bytes are independently counted and hashed. The compressed file is
removed before publication. Manifest/config metadata, component count,
compressed image and installed image each have finite hard ceilings.
Cancellation, timeout, read, close, digest, decode, verification and
staged-synchronization failures remove the hidden staging directory.

IMG-001 intentionally does not make its structural checks a provenance
decision. `internal/image.Verifier` is mandatory and runs over the complete
read-only staging entry before publication. IMG-002 and IMG-003 provide the
manifest/SBOM and repository/workflow provenance implementations. With no
verifier, pulling fails closed with `IMAGE_VERIFICATION_UNAVAILABLE`.

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
├── provenance.json
└── cache-entry.json
```

- root-owned
- base image mode `0444`
- directory not writable by normal users
- atomic temp-to-final rename
- periodic integrity verification
- active session holds digest reference so prune cannot remove it

`cache-entry.json`, validated by
`schemas/image-cache-entry.schema.json`, records schema version 1, the resolved
OCI manifest digest, and fixed component media types, compressed/source digests,
installed digests and byte counts. It does not retain a mutable tag or original
source reference. Cache hits resolve the requested tag again, re-hash all
installed regular files, validate exact owner/mode/type/count, and invoke the
trust verifier again. Entries contain only the five fixed read-only files;
there are no extracted artifact-controlled paths, links or special files.

## Dependency policy

- Go uses the `go 1.26.0` language baseline and exact `toolchain go1.26.5`;
  CI sets `GOTOOLCHAIN=local` and rejects any other resolved release
- Go modules are pinned in `go.mod` and `go.sum`; the complete `vendor/` tree is
  committed and is the only dependency source used by Nix/release builds
- CI runs `go mod verify`, requires `go mod tidy -diff` to be empty,
  regenerates `vendor/`, and rejects modified, deleted, or untracked output
- `govulncheck ./...` blocks unresolved applicable findings; any temporary
  exception requires a documented owner, justification, remediation and expiry
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
