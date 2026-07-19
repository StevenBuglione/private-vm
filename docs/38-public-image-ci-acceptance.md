# Public image CI acceptance evidence

This record defines the redacted REL-002 evidence boundary for the active public
image workflow. It contains no VPN credential, torrent identifier, user file,
endpoint, USB identity, or unpublished artifact.

## Source contract

`.github/workflows/image-build.yml` contains exactly six matrix entries. Every
entry receives a fresh standard `ubuntu-24.04` public runner and builds exactly
one canonical QCOW2 output. Nix work inside a runner is serialized at one job
and two cores. The job requires 10 GiB available memory and disk after bounded
runner cleanup, uses `--no-link`, reports the canonical closure, emits only
bounded target and capacity diagnostics on failure, and garbage-collects Nix
outputs on every outcome.

The general `ci.yml` workflow evaluates the complete flake with `--no-build`
and then builds only the focused non-image Nix gates. It cannot accidentally
duplicate all role TCG boots in one workspace; those heavy gates live only in
the isolated matrix below.

The workflow and every job have only `contents: read`. There is no package,
OIDC, attestation, release, cache, or upload action. Pull-request code therefore
has no publication path. REL-003 must add publication later in a distinct
protected-environment job and update the workflow-policy contract in the same
review.

## Exact matrix

| Job | Canonical output | Contract gate | TCG gate(s) |
| --- | --- | --- | --- |
| `workstation-basic` | `image-workstation-basic` | `workstation-bundles` | `workstation-desktop` |
| `workstation-office` | `image-workstation-office` | — | `workstation-office-desktop` |
| `workstation-development` | `image-workstation-development` | — | `workstation-development-desktop` |
| `downloader` | `image-downloader` | — | `downloader-desktop` |
| `scanner` | `image-scanner` | `scanner-image-contract` | `scanner-update`, then `scanner-offline` |
| `exporter` | `image-exporter` | — | `exporter` |

Every listed NixOS VM test sets `requiredFeatures.kvm = false`; its QEMU options
select TCG. The ordinary public contribution path has no self-hosted runner,
larger paid runner, or nested-KVM dependency.

## Static evidence

Run from a Nix development environment:

```text
python3 tools/test_workflow_policy.py
python3 tools/check_workflow_policy.py
```

The first command covers success plus negative cases for a duplicate or changed
matrix, mutable action pins, checkout credentials, nonstandard runners, missing
`--no-link`, write permissions, publication commands, unsafe triggers, and
unbounded tool execution. The second validates active and dormant workflows
with the repository policy, actionlint, and offline zizmor. It fails if the
active image workflow drifts from the table above.

The REL-002 source change passed both commands locally on 2026-07-19. It did not
run a Nix build, QEMU, KVM, race test, credential test, or physical-device test
in the source-review worktree.

## Public-runner closure gate

REL-002 runtime acceptance requires one green `image / <role>` result for every
row above on the pull request that introduces this workflow. A successful row
proves that its canonical output and assigned checks fit a fresh standard
runner's 16 GB RAM and 14 GB SSD budget. A failed or cancelled row is not
evidence. Record the immutable workflow-run URL and commit in the pull request;
do not copy raw Nix logs into persistent project reports.

This document does not pre-claim a remote result. The task remains fail closed
until the protected branch records all six required job conclusions as success.
