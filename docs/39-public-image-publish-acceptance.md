# Public image publication acceptance evidence

This is the version-1 REL-003 evidence contract for publishing the six official
guest images. It describes the reviewable source boundary and the remote results
that still must be recorded. It contains no credential, VPN material, torrent
identifier, endpoint, user filename, runner path or raw command output.

## Fixed publication matrix

| Row | Canonical image | Exact runtime closure | GHCR repository |
| --- | --- | --- | --- |
| `workstation-basic` | `image-workstation-basic` | `closure-workstation-basic` | `ghcr.io/stevenbuglione/private-vm/workstation-basic` |
| `workstation-office` | `image-workstation-office` | `closure-workstation-office` | `ghcr.io/stevenbuglione/private-vm/workstation-office` |
| `workstation-development` | `image-workstation-development` | `closure-workstation-development` | `ghcr.io/stevenbuglione/private-vm/workstation-development` |
| `downloader` | `image-downloader` | `closure-downloader` | `ghcr.io/stevenbuglione/private-vm/downloader` |
| `scanner` | `image-scanner` | `closure-scanner` | `ghcr.io/stevenbuglione/private-vm/scanner` |
| `exporter` | `image-exporter` | `closure-exporter` | `ghcr.io/stevenbuglione/private-vm/exporter` |

Each matrix row is an independent standard `ubuntu-24.04` runner, builds one
image, and limits Nix to one job and two cores. Only tag pushes match the
workflow; bounded Go validation rejects a noncanonical `v*` ref before any Nix
build or publication. A permitted tag is a canonical stable SemVer or `-rc.N`
tag from `StevenBuglione/private-vm`, and its commit must be an ancestor of the
full-history checkout's official `origin/main`. The publication job uses the protected
`image-publish` environment and exactly `contents: read`, `packages: write`,
`id-token: write`, and `attestations: write`.

## Artifact and producer contract

Bounded Go code performs file selection, QCOW2 validation, deterministic
single-worker zstd compression, hashing, complete sorted-closure SPDX 2.3
generation, frozen-v1 manifest generation, receipt generation, OCI descriptor
construction, credential consumption, duplicate-tag rejection, publication and
verification. Shell does not implement a security or lifecycle decision. There
is no Docker daemon/store, mutable action tag, upload-artifact handoff or
credential in argv, environment or logs.

The manifest has the exact `{}` config and the following ordered graph:

1. `image.qcow2.zst` — `application/vnd.private-vm.qcow2+zstd`
2. `manifest.json` — `application/vnd.private-vm.manifest.v1+json`
3. `sbom.spdx.json` — `application/spdx+json`
4. `provenance.json` — `application/vnd.dev.sigstore.bundle+json`

The pinned
`actions/attest@f7c74d28b9d84cb8768d0b8ca14a4bac6ef463e6` action signs the
closed `predicate.json` as
`https://slsa.dev/provenance/v1` for the exact subject name
`image.qcow2.zst` and its producer-computed SHA-256. The saved `bundle-path` is
the provenance layer and must pass `NewOfficialVerifier` before any tag write.
A pre-existing tag is a hard failure. Failure or cancellation after a blob push
may leave only unreachable content because the producer has not reached its tag
write. GHCR package tags are not claimed to have a server-side immutability
ruleset. The independent controls are the protected immutable Git release tag,
tag-only workflow identity, per-tag workflow concurrency, sole protected
`packages: write` authority, conditional creation and post-write digest check.

The pre-attestation `release-receipt.json` is validated by
`schemas/image-release-receipt.schema.json`. It lists the three publishable
content layers plus `predicate.json`; it deliberately has no provenance bundle
or final OCI-manifest digest. The publisher rehashes the receipt inputs and
replaces the predicate input with the saved attestation bundle when constructing
the final four-layer graph.

## Local source evidence

Run the following bounded gates serially on a 16 GiB maintainer host:

```text
CGO_ENABLED=0 GOMAXPROCS=2 GOMEMLIMIT=3GiB \
  go test -p=1 ./internal/image ./cmd/private-vm-image-release
python3 tools/validate_schemas.py
python3 tools/validate_examples.py
python3 tools/test_workflow_policy.py
python3 tools/check_workflow_policy.py
```

Focused tests must cover success, failure, cancellation, timeout, cleanup,
duplicate tag, failure after each partial push, and anonymous official
verification. The schema/example gate covers the closed version-1 release
receipt and negative mutations. Workflow-policy tests pin the exact tag
trigger, six rows, permissions, protected environment, action SHAs, resource
limits, credential channel and fresh anonymous job.

This checked-in template does not by itself claim that the complete local gate
passed. Record the commit and bounded command results in the implementing change
or release record; never paste raw build logs or secret-bearing process state.

After these local gates pass, implementation may continue without waiting for
the remote image build. This reduces idle time only; it does not convert an
unexecuted remote condition into evidence.

## Remote-only acceptance record

For the candidate tag, record the immutable workflow run URL, source commit,
resolved digest for each matrix row and these conclusions:

- [ ] the GitHub `image-publish` environment existed before the run and its
      reviewed protection rules applied to all six publication jobs;
- [ ] all six publication jobs completed successfully;
- [ ] the generated Sigstore bundles carry the exact official repository,
      workflow, tag, commit, numeric IDs, hosted-runner and invocation identity;
- [ ] all six GHCR package versions are public without a workflow/API visibility
      mutation or broad credential;
- [ ] all six fresh-runner jobs started without registry credentials, resolved
      their tag to the recorded digest, pulled anonymously and completed the
      full official manifest/SBOM/provenance verification; and
- [ ] no tag existed before publication and each tag still resolves to the
      recorded immutable digest after verification.

Current source-review status: **remote evidence not yet recorded**. A private
package, missing environment protection, pending/skipped/cancelled/failed job,
different digest, or credentialed verification is a blocking result. Report a
visibility failure for maintainer remediation; do not add an API mutation or a
broader token to make the check pass. GitHub documents that a newly published
container package defaults private; the first release candidate may therefore
need a one-time owner visibility change followed by an unauthenticated rerun.
