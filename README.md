# private-vm

`private-vm` is a proposed open-source Linux tool for running disposable
graphical workstations and a compartmentalized torrent-download, malware-scan,
sanitization and USB-export workflow.

This directory is both a **complete implementation blueprint** and a
**compilable starter repository**. It is designed to be handed directly to a
coding agent.

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

- 37 numbered design and operations documents
- 10 architecture decision records
- complete v1 CLI and error catalog
- host and guest protobuf contracts
- versioned JSON schemas and example configurations
- Go package boundaries, interfaces and tested starter implementations
- NixOS host module and six image-output scaffolds
- systemd, Polkit, tmpfiles and udev packaging assets
- public GitHub CI plus secured image/release workflow templates
- machine-readable implementation backlog, milestones and acceptance suites
- source drafts preserved under `references/`
- validation report and archive manifest

## Local validation

```bash
go test ./...
go vet ./...
python3 tools/validate_schemas.py
go run ./cmd/private-vm version
```

See [`VALIDATION.md`](VALIDATION.md) for what was and was not verified while
creating this package.

## Important status

This is not an operational security product. Only `version` and the starter
`doctor` command are implemented. Every security-sensitive command intentionally
fails as not implemented until its backlog tasks and acceptance tests pass.

## License

Apache License 2.0 for project-authored code. Every distributed guest image also
needs an automatically generated third-party license report and SBOM.
