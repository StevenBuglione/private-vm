# GitHub Actions and public CI

## Runner strategy

Use public standard GitHub-hosted runners to maximize free CI:

- 4 vCPU
- 16 GB RAM
- 14 GB SSD
- free and unlimited for public repositories at the time this plan was written

Every image builds in a separate job. Never build all desktop images in one
workspace.

## Workflow permissions

Default:

```yaml
permissions:
  contents: read
```

Add only per job:

- `packages: write` for publishing
- `id-token: write` and `attestations: write` for provenance
- `contents: write` only for the protected release job
- no write permission on pull-request builds

Never use `pull_request_target` to execute untrusted code.

## Active workflow: `ci.yml`

For pull requests and pushes:

- formatting
- Go unit tests
- race tests
- vet
- staticcheck
- govulncheck
- protobuf lint/breaking checks
- clean protobuf regeneration with committed-output drift rejection
- schema tests
- Nix flake check/evaluation
- package builds
- workflow policy validation with locked actionlint and zizmor
- no publishing

Fuzz targets and their bounded smoke runs are planned but are not an active gate
until task-specific fuzz harnesses are committed. `image-build.yml.template` and
`release.yml.template` are policy-checked dormant templates; renaming either
file is a separate reviewed activation change. There is no active nightly
workflow yet.

Before template activation, create and protect the exact `image-publish` and
`release` GitHub environments, configure their deployment rules, finish the
backlog dependencies named in each template, and re-run the repository settings
audit. Merely naming an environment in YAML does not create server-side
protection.

Reproduce the workflow-security gate with the locked flake tools:

```bash
nix build .#checks.x86_64-linux.workflow-policy --print-build-logs
```

The gate validates active and dormant workflow sources, exercises negative
fixtures, runs actionlint, and runs offline zizmor at low severity or higher.

The protobuf generator plugins are pinned by version and registry revision in
`buf.gen.yaml`. CI checks out full history, compares pull requests with their
exact base SHA and main pushes with the exact pre-push SHA, then runs `buf
generate` and rejects modified, deleted, or untracked output under `gen/`.

## Planned workflow: `image-build.yml`

Matrix, one role/bundle per job:

```text
workstation-basic
workstation-office
workstation-development
downloader
scanner
exporter
```

Steps:

1. checkout pinned action SHA
2. install pinned Nix
3. report disk/RAM
4. build one image
5. static inspect manifest
6. boot TCG smoke test
7. compress zstd
8. generate SBOM
9. on protected main/tag, publish OCI
10. generate attestation
11. delete workspace outputs

Pull requests build only changed images where safe, with a periodic full matrix.

## Disk-budget strategy

Before build:

- estimate closure size
- require configured maximum
- use no large retained result symlinks
- garbage collect between phases
- compress immediately
- avoid duplicate base/toolchain images in one job

If an image does not fit 14 GB:

1. reduce image closure and temporary disk first
2. split closure build and image assembly into separate jobs
3. publish a temporary digest-pinned OCI build stage
4. pull/import it in a fresh runner
5. never silently move required CI to a private paid runner

A self-hosted KVM job may supplement but must not be required for ordinary public
contribution.

## Planned workflow: `nightly.yml`

- rebuild locked images
- full TCG boot matrix
- vulnerability scans
- dependency freshness report
- test mock WireGuard endpoint
- cleanup/recovery fault injection
- do not automatically update lockfiles

## Planned workflow: `release.yml`

Triggered by protected semantic tag.

1. verify clean source/tag
2. build/test binaries
3. build packages
4. build images
5. run acceptance tests
6. generate SPDX SBOMs
7. publish OCI by digest
8. attest artifacts
9. publish GitHub release
10. fresh runner pulls anonymously
11. verify digest/provenance/SBOM
12. mark release complete

## Action pinning

All active actions and dormant template references are pinned by full commit
SHA. A comment may show the human-readable version. CI validates action pins,
checkout credential handling, triggers, permissions and protected publishing
job isolation. GitHub server-side SHA pin enforcement is also required.

## Caching

Caches must not contain secrets. The active Go cache is managed by `setup-go`,
is dependency-keyed only by `go.sum`, and is additionally scoped by runner OS,
architecture and resolved Go toolchain by the action. Nix inputs are pinned by
`flake.lock`; the active Determinate installer does not configure an untrusted
binary cache. Explicit cache actions are currently rejected; enabling one
requires a separately reviewed policy defining exact keys and safe paths.
Release jobs must not trust writable caches as release artifacts; they rebuild
or verify outputs and attest final digests.

## CI secrets

No Proton config, account credential, real magnet link, private signing key, or
USB identifier exists in GitHub Actions.

Tests use:

- local mock WireGuard peer
- generated test keys
- synthetic torrent fixture
- EICAR test file where appropriate
- malicious archive corpus generated in tests
