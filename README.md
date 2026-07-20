# private-vm

`private-vm` is an open-source Linux project for running disposable
graphical workstations and a compartmentalized torrent-download, malware-scan,
sanitization and USB-export workflow.

The six implementation batches are consolidated on `main`. The codebase is
still pre-release: completed boundaries are tested, while unimplemented adapters
and unrun live/hardware gates continue to fail closed.

Start with the [user guide](docs/06-user-workflows.md), then use the
[verification runbook](docs/43-verification-runbook.md) to prove the exact
checkout and target host. The [CLI reference](docs/07-cli-reference.md) is the
canonical command, exit-code and machine-output contract.

## Read in this order

1. [`HANDOFF_PROMPT.md`](HANDOFF_PROMPT.md)
2. [`START_HERE.md`](START_HERE.md)
3. [`AGENTS.md`](AGENTS.md)
4. [`DESIGN_FREEZE.md`](DESIGN_FREEZE.md)
5. [`docs/00-master-plan.md`](docs/00-master-plan.md)
6. [`docs/01-requirements.md`](docs/01-requirements.md)
7. [`docs/02-threat-model.md`](docs/02-threat-model.md)
8. [`project/backlog.yaml`](project/backlog.yaml)
9. [`project/FIRST_10_COMMITS.md`](project/FIRST_10_COMMITS.md)

## Settled architecture

- Public repository target: `StevenBuglione/private-vm`
- User command: `private-vm`
- Privileged daemon: `private-vmd`
- Guest agent: `private-vm-guestd`
- Guest OS baseline: NixOS 26.05
- Desktop: XFCE
- Hypervisor: direct QEMU/KVM
- Display: SPICE over a per-session Unix socket
- Host RPC: authenticated gRPC over a Unix socket
- Guest RPC: capability-authenticated gRPC over AF_VSOCK
- VPN: a user-supplied Proton WireGuard profile
- Guest roles:
  - disposable graphical workstation
  - disposable graphical downloader
  - disposable graphical scanner
  - disposable headless USB exporter
- Image distribution: public GHCR OCI artifacts
- Provenance: GitHub artifact attestations plus SPDX SBOMs
- Persistence: no intentional persistent plaintext session state
- Output: explicit approved transfer to an enrolled USB or later encrypted bundle

## What is included

- numbered design, operations, implementation and acceptance-evidence documents
- architecture decision records for every approved design change
- complete v1 CLI and error catalog
- host and guest protobuf contracts
- versioned JSON schemas and example configurations
- Go package boundaries, interfaces and tested starter implementations
- NixOS host module and six image-output scaffolds
- NixOS module plus hook-free DEB/RPM and manifest-bound generic-archive sources
- systemd, Polkit, tmpfiles, sysusers, udev, completions and manual-page assets
- public source/image-build CI plus a tag-only protected image-publication workflow
- machine-readable implementation backlog, milestones and acceptance suites
- source drafts preserved under `references/`
- validation report and archive manifest

## Local validation

```bash
systemd-run --user --scope --quiet \
  -p MemoryHigh=1536M -p MemoryMax=2G -p MemorySwapMax=0 \
  nix develop --offline --command env GOMAXPROCS=2 GOMEMLIMIT=1536MiB \
  go test -p=1 ./...

nix develop --offline --command go run -p=1 ./cmd/private-vm version --json
```

See the [verification runbook](docs/43-verification-runbook.md) for the complete
memory-bounded gates. [`VALIDATION.md`](VALIDATION.md) is retained only as the
historical handoff validation record.

## Important status

This is not yet a released security product. Configuration, diagnostics,
the authenticated host daemon, volatile session records, typed QEMU/QMP
lifecycle, ephemeral storage primitives, authenticated role-restricted guest
channels, role orchestration, VPN/torrent/scanner workflows, and exact-identity
USB claim/prepare/export are implemented and covered by source, unit, and
integration tests. Representative image TCG boots and isolated Linux networking
have also passed locally. Real-Proton, physical-USB, advanced reboot recovery,
protected publication, clean-distribution package and complete target-host
acceptance remain open. The visible but unimplemented command adapters are
listed explicitly in the user guide. Intentional gaps, including
encrypted-bundle workspace export and automatic Doctor repair, report failure
instead of simulating success.

## License

Apache License 2.0 for project-authored code. Every distributed guest image also
needs an automatically generated third-party license report and SBOM.
