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

The release producer must save the actions/attest v4 `bundle-path` output next
to each image as the bounded Sigstore bundle v0.3 layer. Its signed payload must
match `schemas/image-provenance-payload.schema.json`; release publication is not
compatible with branch refs, arbitrary tags, repository-name-only identity, or
an invocation URL that differs between the Fulcio certificate and payload.

## Active source workflow: `ci.yml`

For pull requests and pushes:

- formatting
- Go unit tests
- race tests
- bounded daemon RPC fuzz smoke
- vet
- staticcheck
- govulncheck
- protobuf lint/breaking checks
- clean protobuf regeneration with committed-output drift rejection
- schema tests
- complete Nix flake evaluation without building role-image checks
- enabled host-module contract with custom group/package override, pinned daemon
  PATH, directory modes, and independent Polkit policy identity
- static package builds and the bounded runtime fuzz gate
- workflow policy validation with locked actionlint and zizmor
- no publishing

The source Nix job serializes derivations at two cores. It builds only the
focused non-image gates after `nix flake check --no-build`; canonical images and
all TCG role boots belong exclusively to the isolated image workflow below.
This avoids rebuilding the entire role matrix in one 16 GB workspace.

The daemon request-protobuf, context-validation, and process-evidence parser
fuzz target runs for two seconds with one worker in both `ci.yml` and the Nix
flake checks. It rejects individual corpus inputs above 64 KiB and includes
deterministic seeds for each context-bearing daemon request shape, resource
validation, and the `/proc` stat, status, and pidfd-info parsers. Additional
task-specific fuzz harnesses and a longer nightly fuzz workflow remain planned.
`image-build.yml` is active as the build-only REL-002 workflow.
`release.yml.template` remains a policy-checked dormant template. Activating
the release template or adding image publication is a separate reviewed change.
There is no active nightly workflow yet.

Before REL-003 adds image publication or REL-004 activates the release
template, create and protect the exact `image-publish` and `release` GitHub
environments, configure their deployment rules, finish the named backlog
dependencies, and re-run the repository settings audit. Merely naming an
environment in YAML does not create server-side protection.

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

## Active build-only workflow: `image-build.yml`

The matrix runs one role/bundle per fresh `ubuntu-24.04` public-runner job:

```text
workstation-basic
workstation-office
workstation-development
downloader
scanner
exporter
```

Each job:

1. checkout pinned action SHA
2. install pinned Nix
3. reclaim only documented disposable runner tool directories and the unused
   Nix store
4. require at least 10 GiB available RAM and disk before building
5. build exactly one canonical image without a result symlink
6. report its closure size
7. run the role's static contract check where applicable
8. boot its role-specific smoke test under explicit TCG
9. run scanner update and offline boots serially
10. print bounded disk/RAM and target names on failure
11. garbage-collect Nix outputs on every outcome and prove the checkout is clean

The workflow uses `contents: read` at workflow and job scope. It has no package,
OIDC, attestation, release, cache, or artifact-upload path, so neither pull
requests nor main pushes publish anything in REL-002. Full-SHA action pins,
exactly six reviewed matrix entries, the standard-runner label, serialized Nix
limits, `--no-link`, cleanup, TCG targets, and the absence of publication are
enforced by `tools/check_workflow_policy.py` and negative tests.

Path filters run the matrix when canonical image inputs, role guestd code,
generated APIs, dependency closure, bundle catalogs, relevant schemas, or the
workflow itself change. A periodic full matrix remains planned for the nightly
workflow.

## Disk-budget strategy

Before each build:

- estimate closure size
- require configured maximum
- use no retained result symlinks
- garbage collect before the build and after every outcome
- avoid duplicate base/toolchain images in one job

If an image does not fit 14 GB:

1. reduce image closure and temporary disk first
2. split closure build and image assembly into separate jobs
3. after REL-003 exists, split a temporary stage only through the protected,
   digest-pinned OCI publication boundary
4. anonymously pull/import that exact digest in a fresh runner
5. never silently move required CI to a private paid runner

A self-hosted KVM job may supplement but must not be required for ordinary public
contribution.

The standard workflow never selects a self-hosted or larger paid runner and
never depends on nested KVM. NixOS tests set `requiredFeatures.kvm = false` and
pass `accel=tcg`; a future KVM acceptance job is supplemental and separately
gated.

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
