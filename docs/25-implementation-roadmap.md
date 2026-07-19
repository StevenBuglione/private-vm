# Implementation roadmap

## Phase 0 — contracts and repository

Deliver:

- Go 1.26 module
- command binaries
- protobuf contracts
- schemas
- config and policy model
- CI
- Nix dev shell
- ADR set
- structured errors
- documentation lint

Exit:

```text
go test ./...
go test -race ./...
go vet ./...
nix flake check
buf lint
```

## Phase 1 — doctor, config, and planning

Implement:

- host feature probes
- immutable config
- capacity model
- image requirement model
- JSON output
- stable remediation codes
- safe repair operations

Exit:

- runs on NixOS/Fedora/Ubuntu/Debian fixtures
- detects KVM, QEMU features, disk swap, `/run`, USBGuard, dependencies
- makes no privileged mutation without explicit repair

## Phase 2 — daemon and session ownership

Implement:

- Unix gRPC
- peer credentials/group auth
- root service
- session registry under `/run`
- encrypted session store abstraction
- resource journal
- idempotent cleanup
- startup recovery
- fake-QEMU harness

Exit:

- crash after every allocation converges to cleanup
- no generic root command API
- concurrent sessions governed by policy

## Phase 3 — images and guest control

Implement:

- NixOS 26.05 common image
- guestd
- image manifest
- VSOCK gRPC
- fw_cfg token
- OCI pull/cache
- provenance verification
- TCG tests

Exit:

- verified role image boots and handshakes
- wrong role/digest/protocol fails
- no SSH or persistent logs

## Phase 4 — graphical workstation

Implement:

- XFCE image bundles
- SPICE Unix socket
- vdagent with clipboard/file transfer disabled
- remote-viewer launcher
- workspace import/export
- dirty stop protection
- explicit audio opt-in

Exit:

- user can work graphically
- host cannot share clipboard/files
- output survives only explicit export
- all session state disappears after stop

## Phase 5 — network and Proton

Implement:

- WireGuard parser
- netns/TAP/veth
- host nftables endpoint allowlist
- guest nftables
- Proton config streaming
- leak tests
- VPN-loss UI/state

Exit:

- no direct egress before/after tunnel
- VPN loss fails closed
- workstation remains usable offline for save/export

## Phase 6 — downloader

Implement:

- downloader image
- qBittorrent local API
- secure magnet/torrent input
- metadata-only stage
- selection/capacity plan
- quarantine disk
- download state
- VPN pause
- sealing

Exit:

- no payload before plan approval
- no preview/open
- disk moves only downloader→scanner
- downloader destroyed before scanner

## Phase 7 — scanner

Implement:

- signature update boot
- offline scan boot
- read-only quarantine
- inventory
- ClamAV
- archive safety
- PDF/Office/image/media reconstruction
- policy/report
- output stream

Exit:

- every uncertainty rejects
- malicious fixtures contained
- report schema complete
- original hostile input cannot enter safe promotion

## Phase 8 — USB exporter and release

Implement:

- USB enrollment
- USBGuard integration
- exporter image
- exact passthrough
- LUKS2/ext4 prep
- streaming and triple hash
- packages
- public release
- attestations/SBOM
- reproducibility workflow
- security review

Exit:

- complete torrent→scan→USB demo
- no host mount
- no active resource after teardown
- independent artifact verification succeeds

## Suggested first ten commits

1. `chore: establish Go module, docs, schemas, and CI`
2. `feat(cli): add command tree, version, errors, and JSON renderer`
3. `feat(config): add typed config and policy validation`
4. `feat(doctor): add pure host probes and remediation output`
5. `feat(daemon): add Unix gRPC server and peer authentication`
6. `feat(session): add volatile registry and idempotent cleanup`
7. `feat(qemu): add typed launch spec and fake QMP harness`
8. `feat(images): add manifest, OCI interfaces, and verified cache`
9. `feat(guest): add VSOCK handshake and role capabilities`
10. `feat(nix): boot minimal NixOS guest in TCG acceptance test`

## Project management

Use `project/backlog.yaml` as the seed for GitHub issues. Each issue includes:

- component
- priority
- dependencies
- deliverables
- tests
- acceptance criteria
- security notes

Do not start later phases by bypassing an exit gate.

## Approved six-batch delivery plan

The phase ordering above remains the security dependency order. For delivery,
the remaining backlog is grouped into six reviewable batches so independent
source work can continue while a previous batch's remote CI is running:

1. Runtime foundation: `D-002`, `D-003`, `STOR-001`, `STOR-002`, and
   `STOR-003` (issues 16, 17, and 21-23).
2. Images and trust: `NIX-002` through `NIX-006`, `IMG-001` through
   `IMG-003`, `REL-002`, and `REL-003` (issues 12-14, 28-30, and 50-51).
3. Workstation networking: `VPN-001`, `NET-001` through `NET-003`,
   `WS-001`, and `WS-003` (issues 24-27, 40, and 42).
4. Torrent and scanning: `TOR-001` through `TOR-003`, `SCAN-001` through
   `SCAN-006`, and `WS-002` (issues 31-39 and 41).
5. Recovery and export: `D-005` and `USB-001` through `USB-003` (issues 19
   and 43-45).
6. Packaging and release: `PKG-001` through `PKG-003` and `REL-004`
   (issues 46-48 and 52).

Each original backlog task retains its own acceptance evidence and focused
commit even when several tasks share a pull request. A batch may begin local,
dependency-safe source work while the prior pull request runs remotely, but it
must not consume an unmerged contract or bypass a required exit gate. Required
GitHub checks still have to pass before merge; the project does not idle solely
to watch them.
