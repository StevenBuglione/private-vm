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

The six official repositories are fixed:

```text
ghcr.io/stevenbuglione/private-vm/workstation-basic
ghcr.io/stevenbuglione/private-vm/workstation-office
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

The frozen image artifact is an OCI image manifest with the exact two-byte
empty config `{}` and exactly four ordered layers:

| Order | Title | Media type | Bound content |
| --- | --- | --- | --- |
| 1 | `image.qcow2.zst` | `application/vnd.private-vm.qcow2+zstd` | deterministic compressed canonical QCOW2 |
| 2 | `manifest.json` | `application/vnd.private-vm.manifest.v1+json` | frozen-v1 image/build manifest |
| 3 | `sbom.spdx.json` | `application/spdx+json` | complete canonical runtime Nix closure |
| 4 | `provenance.json` | `application/vnd.dev.sigstore.bundle+json` | saved GitHub Sigstore bundle |

Each layer descriptor has only its exact OCI title annotation. The manifest has
no subject, artifact type, manifest annotations, URLs, embedded data or
platform; adding, omitting, duplicating or reordering a layer is invalid. The
generic outer provenance media type is intentionally distinct from the inner
bundle's required `application/vnd.dev.sigstore.bundle.v0.3+json` declaration.

The tag is a discovery alias created only after every blob and the manifest are
available by digest and the official verifier accepts the staged artifact. The
publisher checks that the canonical SemVer/RC tag does not resolve before any
blob push and applies a conditional non-overwrite tag write after a second
absence check. Duplicate tags fail closed. A partial push does not create a tag.

IMG-001 implements a read-only anonymous HTTPS ORAS client. It opens no Docker
daemon or credential store, resolves every tag to a canonical SHA-256 manifest
descriptor before fetching any layer, and fetches only descriptors from that
immutable manifest. Digest references are resolved as well and must return the
exact requested digest.

## Verification order

1. parse reference without executing content
2. resolve tag to immutable digest
3. pull manifest with byte limits
4. verify every OCI component digest
5. verify the complete compressed QCOW2 digest before constructing its decoder
6. decompress within bounds and verify the installed QCOW2 digest
7. verify the image manifest schema, cache bindings and host compatibility
8. verify the complete SPDX closure and its image binding
9. verify the offline Sigstore provenance bundle and signed digest
10. require the exact official repository, numeric IDs and release workflow
11. require the immutable canonical SemVer/RC ref and source commit
12. atomically install the read-only cache entry

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

IMG-002 defines the complete frozen-v1 release-manifest contract in
`schemas/image-manifest.schema.json`. The Go `Manifest` has exactly the same
required field set; a contract test rejects schema/struct drift. Decoding is
byte-bounded, depth-bounded and presence-aware. Unknown fields, duplicate keys
at any object depth, missing fields, trailing documents and invalid `null`
values fail closed. The verifier requires:

- `schema_version = 1`, project `private-vm`, NixOS `26.05`, canonical build
  time, flake-lock SHA-256, source commit, source ref, repository and workflow
  shapes;
- the requested role and exact bundle (`basic`, `office` or `development` only
  for workstation; explicit JSON `null` for the other roles);
- Go `amd64` → manifest `x86_64` or Go `arm64` → manifest `aarch64`;
- compatible guest API major/minor under the copied immutable host policy;
- the exact frozen `9.2` image minimum and a host QEMU version at least that
  new;
- the exact sorted common-plus-role capability list;
- compressed QCOW2 digest/size and installed QCOW2 digest/size equal to the
  immutable cache record;
- the SBOM digest equal to the installed `application/spdx+json` layer; and
- virtual size, manifest size, SBOM size and collection counts within hard
  ceilings.

The exported official verifier constructor always composes those checks with
the embedded-root IMG-003 verifier. Its provenance interface and accepting test
function are package-private, so a product caller cannot replace the official
identity policy or select a non-provenance mode.

The OCI provenance layer keeps the frozen generic media type above; its JSON
document must declare the distinct
`application/vnd.dev.sigstore.bundle.v0.3+json` bundle media type. IMG-003
accepts exactly one bounded Sigstore bundle v0.3 containing one DSSE
`application/vnd.in-toto+json` envelope, one Fulcio certificate, one Rekor
`dsse/0.0.1` entry and inclusion proof, and at least one authenticated observer
timestamp. Verification is offline against the reviewed embedded Sigstore
public-good trust snapshot. No TUF, Rekor, Fulcio, GitHub or registry request is
made while verifying a staged or cached entry.

The signed payload is the closed SLSA provenance v1 profile in
`schemas/image-provenance-payload.schema.json`. It binds the compressed-image
SHA-256 to `image.qcow2.zst`, the source commit, the exact release workflow and
a protected, immutable Git `refs/tags/v<SemVer>` tag (only canonical `-rc.N`
prereleases are accepted). The repository name is additionally pinned by GitHub
repository ID `1305109560` and owner ID `34593055`. The Fulcio SAN, OIDC issuer, source
repository/ref/commit, both numeric IDs, hosted-runner identity, and release
workflow are exact. Its `RunInvocationURI` must equal the signed SLSA
`invocationId`; repository-name reuse therefore cannot satisfy policy.

`actions/attest` receives the producer's closed `predicate.json`, predicate type
`https://slsa.dev/provenance/v1`, exactly the subject name `image.qcow2.zst` and
the producer-computed `sha256:<digest>`. Its saved `bundle-path`, rather than a
network-fetched attestation, becomes `provenance.json`. The bounded Go publisher
rehashes every staged component, validates the release receipt, and runs
`NewOfficialVerifier` locally before it can publish or tag the graph. A fresh
runner then pulls anonymously with no Docker configuration or registry
credential and repeats the complete official client verification. This final
remote check proves public readability; source tests alone cannot prove GHCR
visibility.

`schemas/image-release-receipt.schema.json` defines the closed version-1
pre-attestation handoff. It records the fixed source, tag, role/bundle and GHCR
repository identity plus immutable component digests and byte counts. Its
fourth prepared file is `predicate.json`; after `actions/attest` succeeds, the
saved bundle replaces that producer input in the published graph under the
fixed title `provenance.json`. Credentials, absolute staging paths, raw command
output, final OCI digest and mutable source references are forbidden in the
receipt.

## Published image SPDX 2.3 profile

`schemas/image-sbom.schema.json` is the exact REL-003 producer contract. It is a
deliberately narrow SPDX 2.3 JSON profile generated from the full runtime Nix
closure; it is not a Syft-field compatibility profile and is not the scanner's
embedded direct-tool evidence.

The document requires `SPDX-2.3`, `CC0-1.0`, `SPDXRef-DOCUMENT`, one unique
HTTPS namespace derived from the compressed image digest, one canonical
creation record and `documentDescribes = ["SPDXRef-IMAGE"]`. The described root
image package and the single `./image.qcow2` file both carry exactly one SHA-256
checksum equal to the installed/uncompressed QCOW2 digest from the manifest.

The image package is first. Every remaining package represents one runtime Nix
store closure path, uses `filesAnalyzed = false` and an explicitly present empty
`checksums` array, and has:

```text
downloadLocation = file:///nix/store/<32-character-store-hash>-<store-name>
SPDXID            = SPDXRef-Package-<same-store-hash>
name              = <same-store-name>
versionInfo       = a value contained in the store name, or NOASSERTION
```

Closure paths are unique and strictly sorted. Relationships are ordered as
document `DESCRIBES` image, image `CONTAINS` QCOW2, then one image `DEPENDS_ON`
closure-package edge in the same store-path order. Unknown elements, duplicate
IDs or paths, ambiguous aliases, reordered entries, missing/null nested fields,
unreferenced packages and extra relationships are blocking failures. This
profile makes generation deterministic and self-consistent; provenance and
independent rebuild evidence remain responsible for proving that the published
list came from the official full Nix closure.

## Trust policy

Official default:

```text
repository: StevenBuglione/private-vm
workflow: .github/workflows/release.yml
issuer: GitHub Actions OIDC
visibility: public
repository-id: 1305109560
owner-id: 34593055
ref: refs/tags/v<canonical-semver-or-rc.N>
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
