# Packaging release runbook

This is the packaging section of the versioned acceptance runbook. Run it only
after runtime, image, workstation, network, scanner and USB source gates pass.
Stop on the first failure. A pending, skipped, cancelled or unavailable result
is not success.

## Resource policy

On the 16 GiB maintainer host, run one Nix build or VM at a time with Nix
`max-jobs = 1`, `cores = 2`, `GOMAXPROCS=2`, Go `-p=1` and no concurrent race or
QEMU job. GitHub checks may continue in the background; local implementation
does not idle for them, but no release gate may be marked passed until its
corresponding immutable remote result succeeds.

## 1. Packaging source gate

```bash
nix develop --offline --command python3 tools/check_packaging_assets.py
GOMAXPROCS=2 nix develop --offline --command go test -p=1 ./internal/systeminstall ./internal/cli ./cmd/private-vm ./cmd/private-vm-bundle-manifest
GOMAXPROCS=2 nix develop --offline --command go vet ./internal/systeminstall ./internal/cli ./cmd/private-vm ./cmd/private-vm-bundle-manifest
nix develop --offline --command python3 tools/validate_schemas.py
nix develop --offline --command python3 tools/validate_examples.py
nix eval --raw .#checks.x86_64-linux.host-module-contract.drvPath
nix eval --raw .#checks.x86_64-linux.package-contract.drvPath
nix eval --raw .#deb.drvPath
nix eval --raw .#rpm.drvPath
nix eval --raw .#generic-archive.drvPath
```

Record one redacted JSON/JUnit case per command with source commit, start/end
time, exit status and derivation path where applicable. Do not include the
process environment, home-directory paths, daemon configuration contents,
session IDs or external-command output.

## 2. Artifact build gate

Build serially and without result symlinks:

```bash
nix build .#deb --no-link
nix build .#rpm --no-link
nix build .#generic-archive --no-link
```

Record the exact output path through `nix path-info`, artifact filename, byte
count and SHA-256. This gate proves only the three raw package bytes. The
protected `private-vm-release prepare` invocation in gate 5 generates and binds
the SPDX 2.3 document and build manifest for each exact artifact before the
workflow attests those digests; do not claim that evidence at this earlier
gate.

## 3. Clean distribution gate

Use fresh, snapshot-reset VMs—not containers sharing the maintainer kernel—for
Ubuntu supported LTS, current Debian stable and current Fedora. Give each VM KVM,
cgroups v2 and systemd. Copy in only one previously hashed artifact plus its
public manifest/SBOM/provenance.

For every native-package row:

1. verify digest, SPDX and provenance before package-manager invocation;
2. install with `apt` or `dnf` and record resolved dependency versions;
3. preserve/review the USBGuard rule file, apply the documented safe
   first-activation policy, apply the static sysctl fragment, explicitly
   enable/start USBGuard and `private-vmd.service`, then re-login the test user;
4. verify exact installed paths, owners/modes, sysusers/tmpfiles, the one-setting
   sysctl fragment and active value, candidate-only udev rule, one Polkit
   action, completions and man pages;
5. verify `/run/private-vm/control.sock` is `root:private-vm` mode `0660` and no
   product TCP listener exists;
6. run `private-vm doctor --strict --json` and require no unresolved blocking
   package/integration diagnostic;
7. create non-secret sentinel configuration and image-cache files, clean every
   session, stop the daemon and upgrade from the prior supported RC;
8. prove the two sentinel hashes are unchanged, then restart and rerun Doctor;
9. clean sessions, explicitly stop/disable the service, remove the package and
   prove no `private-vmd` process or active unit remains; and
10. prove configuration, image cache and test export sentinel remain.

## 4. Generic archive gate

In a fresh supported VM, extract the archive as an unprivileged user. Run
`sudo ./private-vm system install --dry-run --json`, archive that fixed plan,
then run the identical command with `--accept`. Verify the manifest record,
files, service/socket and strict Doctor. Separately prove:

- a modified byte, symlinked bundle entry, missing KVM/systemd/cgroup evidence,
  non-root accept, active daemon, cancellation and timeout cause no mutation;
- injected failure after each file publication and activation step restores the
  prior fixed files and leaves no transaction staging entry; and
- uninstall dry-run/accept removes only manifest-managed non-configuration
  paths, stops/disables the daemon and preserves configuration/cache/exports.

Any `SYSTEM_ROLLBACK_INCOMPLETE` result blocks the release and requires the
recovery procedure in `docs/28-operations-runbook.md`.

## 5. Protected publication gate

Only a canonical protected `vMAJOR.MINOR.PATCH-rc.N` tag on protected `main` may
publish. The package job must use the protected `release` environment, minimal
permissions, full-SHA actions, fresh builds, exact artifact subjects, SPDX and
GitHub attestations. A second fresh read-only runner downloads anonymously and
verifies every package and the six already-published image digests against the
official repository/workflow/tag identity before repeating the clean-system
install matrix.

Archive the immutable workflow URL, run attempt, tag, commit, artifact digests,
attestation verification result and redacted clean-system JUnit/JSON summary.
Do not create `v1.0.0` until the independent security review is recorded; use an
RC tag while that external gate remains outstanding.

The protected job invokes only:

```text
private-vm-release prepare
actions/attest for DEB, RPM and generic archive
private-vm-release publish --token-stdin
```

`prepare` refuses a dirty checkout, non-official origin, non-main ancestor,
noncanonical SemVer/RC tag, mismatched commit, or missing anonymously verified
image. `publish` verifies all package bytes, manifests, SPDX files and offline
Sigstore bundles before creating a draft. A failed upload deletes that draft
with an independent 30-second cleanup context and reports
`RELEASE_CLEANUP_INCOMPLETE` if absence cannot be proved. Never delete or move
the Git tag as rollback; inspect/delete only the unpublished draft, then rerun
the same tag as a new workflow attempt after absence is recorded.

The fresh `verify-release` job has only `contents: read`. It downloads exactly
13 public assets without a credential, verifies three packages and all six OCI
digests against `release-index.json`, and fails on missing, extra, changed,
private or ambiguously addressed content.
