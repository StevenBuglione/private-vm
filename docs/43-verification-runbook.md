# Verification runbook

This is the operator-facing proof index for the integrated v1 development
tree. It is deliberately stricter than a build log: a gate is passed only by a
successful command or an immutable external result for the exact commit. A
pending, skipped, blocked, cancelled or unavailable case is not success.

## Safety and resource limits

On a 16 GiB host, run one build or VM gate at a time. Do not run a race test at
the same time as Nix or QEMU. The source commands below use two Go scheduler
threads, one Go package worker, no swap allowance and a hard cgroup memory cap.
Run destructive USB and reboot tests only in a scheduled maintenance window.
Never place the Proton profile, magnet, filenames, hashes, endpoints or device
serials in evidence.

Record the exact commit before each gate:

```bash
git status --short
git rev-parse HEAD
```

The status output must be empty. Do not treat evidence from another commit as
proof for the current tree.

## Gate 1: executable redacted source evidence

The repository includes a fixed Go evidence producer. It runs the packaging,
release, schema, example and workflow-policy source sequence, stops on the first
failure, suppresses subprocess output, and writes new mode-`0600` JSON and
JUnit files. Run it from the pinned development shell:

```bash
evidence_dir=$(mktemp -d /tmp/private-vm-evidence.XXXXXX)
chmod 700 "$evidence_dir"

systemd-run --user --scope --quiet \
  -p MemoryHigh=1536M -p MemoryMax=2G -p MemorySwapMax=0 \
  nix develop --offline --command \
    go run -p=1 ./cmd/private-vm-release-acceptance \
      --workdir "$PWD" \
      --json "$evidence_dir/source.json" \
      --junit "$evidence_dir/source.junit.xml"
```

The expected terminal result after all local cases pass is
`RELEASE_GATES_INCOMPLETE`, so the process exits nonzero. That is intentional:
the producer records protected publication, anonymous verification and clean
distribution testing as blocked rather than calling a source-only result a
complete release. Inspect only the redacted evidence:

```bash
jq -e '
  .schema_version == 1 and
  .project == "private-vm" and
  .profile == "source-only" and
  .complete == false and
  ([.cases[] | select(.status == "failed")] | length) == 0 and
  ([.cases[] | select(.status == "passed")] | length) == 9 and
  ([.cases[] | select(.status == "blocked")] | length) == 4
' "$evidence_dir/source.json"

stat -c '%a %n' "$evidence_dir/source.json" "$evidence_dir/source.junit.xml"
```

Both modes must be `600`. The JSON must validate against
`schemas/release-acceptance-evidence.schema.json`. The JUnit suite must report
zero failures and four skipped live gates. Existing destinations are rejected,
so every rerun starts with a new evidence directory.

## Gate 2: complete local source gate

Run this gate separately because it exercises the whole Go tree, race detector,
static analyzers, protobufs and secret scanner. It is broader than Gate 1 and
does not write an acceptance completion record:

```bash
systemd-run --user --scope --quiet \
  -p MemoryHigh=1G -p MemoryMax=1536M -p MemorySwapMax=0 \
  nix develop --offline --command go mod verify

test -z "$(nix develop --offline --command gofmt -l cmd internal)"

systemd-run --user --scope --quiet \
  -p MemoryHigh=1536M -p MemoryMax=2G -p MemorySwapMax=0 \
  nix develop --offline --command env \
    GOMAXPROCS=2 GOMEMLIMIT=1536MiB \
    go test -p=1 ./...

systemd-run --user --scope --quiet \
  -p MemoryHigh=2G -p MemoryMax=3G -p MemorySwapMax=0 \
  nix develop --offline --command env \
    GOMAXPROCS=2 GOMEMLIMIT=2GiB \
    go test -race -p=1 ./...

systemd-run --user --scope --quiet \
  -p MemoryHigh=1536M -p MemoryMax=2G -p MemorySwapMax=0 \
  nix develop --offline --command env GOMAXPROCS=2 go vet -p=1 ./...

systemd-run --user --scope --quiet \
  -p MemoryHigh=1G -p MemoryMax=1536M -p MemorySwapMax=0 \
  nix develop --offline --command env GOOS=darwin GOARCH=amd64 \
    go test -exec=true -p=1 ./internal/secret

systemd-run --user --scope --quiet \
  -p MemoryHigh=1536M -p MemoryMax=2G -p MemorySwapMax=0 \
  nix develop --offline --command staticcheck ./...

systemd-run --user --scope --quiet \
  -p MemoryHigh=1536M -p MemoryMax=2G -p MemorySwapMax=0 \
  nix develop --offline --command govulncheck ./...

nix develop --offline --command buf lint
nix develop --offline --command buf generate
git diff --exit-code -- gen
test -z "$(git ls-files --others --exclude-standard -- gen)"
nix develop --offline --command python3 tools/validate_schemas.py
nix develop --offline --command python3 tools/validate_examples.py
nix develop --offline --command python3 tools/check_packaging_assets.py
nix develop --offline --command python3 tools/test_workflow_policy.py
nix develop --offline --command python3 tools/check_workflow_policy.py
nix develop --offline --command gitleaks dir . --redact --no-banner --exit-code 1
nix flake check --offline --no-build
```

Stop at the first nonzero result. `nix flake check --no-build` proves evaluation,
not VM boot. Generated protobuf changes and formatting changes must be absent
from `git status --short` at the end.

## Gate 3: serial image and VM proof

Evaluate all six canonical image outputs, then build the VM checks one at a
time with `--max-jobs 1 --cores 2`. The current flake exposes workstation
basic/office/development, downloader, scanner and exporter images. The minimum
role proof is:

```bash
nix build --offline --no-link --max-jobs 1 --cores 2 \
  .#checks.x86_64-linux.guest-common
nix build --offline --no-link --max-jobs 1 --cores 2 \
  .#checks.x86_64-linux.workstation-desktop
nix build --offline --no-link --max-jobs 1 --cores 2 \
  .#checks.x86_64-linux.downloader-desktop
nix build --offline --no-link --max-jobs 1 --cores 2 \
  .#checks.x86_64-linux.scanner-update
nix build --offline --no-link --max-jobs 1 --cores 2 \
  .#checks.x86_64-linux.scanner-offline
nix build --offline --no-link --max-jobs 1 --cores 2 \
  .#checks.x86_64-linux.exporter
```

Run only one command at a time. These TCG checks prove the declared role image
boots and the test assertions pass; they do not prove KVM performance, a live
Proton handshake or physical USB export.

## Gate 4: installed-host proof

After installing the NixOS module or a distribution package, require:

```bash
private-vm version --json
systemctl is-active private-vmd.service
stat -c '%U %G %a %F' /run/private-vm/control.sock
private-vm doctor --strict --json
ss -lnt
private-vm session list --json
```

Doctor must exit 0 and report `runnable: true`; the control endpoint must be a
mode-`660` Unix socket owned by root and the configured group. Review `ss`
manually and reject any private-vm SPICE, QMP, gRPC or guest-service TCP
listener. A successful source gate cannot substitute for this installed-host
gate.

## Gate 5: live network proof

Run the credential-free isolated Linux backend test first:

```bash
systemd-run --user --scope --quiet \
  -p MemoryHigh=1G -p MemoryMax=1536M -p MemorySwapMax=0 \
  nix develop --offline --command make verify-network-live
```

Require the exact redacted `NETWORK_NAMESPACE_INTEGRATION_VERIFIED` record and
a zero exit. This disposable user namespace does not prove Proton. The separate
live Proton test must import the owner-only profile through `--from-file`, prove
the WireGuard handshake plus IPv4/IPv6/DNS/LAN leak blocks and tunnel-loss
fail-closed behavior, and then inspect argv, environment and journald for
absence of profile material. Store only redacted pass/fail evidence.

## Gate 6: synthetic workflow proof

Use only the local synthetic torrent and the corpus defined in
`docs/24-testing.md`. Prove metadata-before-payload, explicit selection,
capacity admission, VPN-loss pause, sealing, downloader destruction, scanner
update boot, offline no-NIC boot, read-only quarantine, fail-closed corpus
handling, reconstructed-only promotion and authenticated report completion.

This gate remains incomplete until the KVM workflow is run on the target host.
Unit tests alone do not prove ClamAV definition freshness, QEMU device topology
or external PDF/Office/media tool behavior.

## Gate 7: destructive USB proof

Do not automate this gate. Re-resolve the disposable device by full identity,
prove it is unmounted and mass-storage-only, then use the two exact interactive
confirmations described in `docs/06-user-workflows.md`. Accept the receipt only
when scanner/relay/exporter/reread hashes agree and every sync, rename, unmount,
detach, stop and cleanup field is true. Independently prove that the host never
mounted the device.

No source test, fake backend or device listing is physical USB evidence.

## Gate 8: reboot recovery proof

In a maintenance window, leave one controlled encrypted session orphan, reboot,
prove its volatile key is unavailable, and require startup recovery to remove
every owned QEMU, cgroup, socket, CID, namespace, interface, nftables object,
loop, mapper, mount, USB claim and ciphertext object.

The current advanced recovery backend intentionally returns a blocking identity
failure because exact QEMU/cgroup/network/VSOCK/USB orphan ownership evidence is
not yet integrated. This gate is therefore not passed and must not be waived.

## Gate 9: clean release proof

Follow `docs/42-packaging-release-runbook.md`: install DEB, RPM and the generic
archive in fresh supported distribution VMs, test upgrade/uninstall, publish an
RC from protected `main`, and anonymously verify exact digests, SPDX documents
and provenance from a fresh read-only runner. GitHub CI may run in the
background while local work continues, but a pending remote result is never a
passed release gate.

Do not tag `v1.0.0` until all gates above and the independent security review
are recorded for the same commit.

## Current integrated evidence

The consolidated `main` history contains the reviewed batch evidence under
`docs/37-runtime-foundation-acceptance.md` through the packaging, scanner and
startup-recovery acceptance documents. The integrated local gates have covered
Go unit/race/vet/static/vulnerability checks, schemas/examples, protobuf and
workflow policy, secret scanning, isolated networking, host-module evaluation,
and representative workstation/exporter TCG boots.

That history does not convert the still-unrun live Proton, physical USB,
advanced reboot recovery, clean-distribution and protected publication rows
into passes. This runbook is the authoritative path for closing those rows.
