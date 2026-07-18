# Coding-agent handoff

You are implementing `private-vm`. Treat this document and
`docs/00-master-plan.md` as the controlling specification.

## Mission

Build a reproducible, public, open-source Linux application that creates and
destroys disposable graphical NixOS virtual machines. It must support private
desktop work and a compartmentalized torrent-to-scan-to-export workflow without
intentionally retaining plaintext session state.

## Non-negotiable rules

1. Do not collapse the four guest roles into one VM.
2. Do not mount guest filesystems, torrent storage, or the export USB on the host.
3. Do not expose SPICE, QMP, gRPC, or guest services on TCP.
4. Do not place VPN keys, magnet links, filenames, or file contents in argv,
   environment variables, journald, persistent logs, crash reports, or telemetry.
5. Do not use shared folders, `virtiofs`, 9p, clipboard sharing, drag-and-drop,
   SPICE file transfer, agent forwarding, or arbitrary USB passthrough.
6. Do not make Packer the image source of truth. NixOS image definitions are
   canonical; Packer is optional acceptance tooling only.
7. Do not implement security decisions or lifecycle orchestration in shell.
   CI may run simple commands. Product logic belongs in Go or declarative Nix.
8. Every privileged action must be represented in the daemon API, authorized,
   validated, bounded, and covered by tests.
9. Every session must have one state machine and one cleanup owner.
10. Fail closed. A missing verification, stale scan database, scan error, skipped
    file, VPN leak, unexpected device, dirty workspace, or incomplete report is a
    blocking failure.
11. Never claim anonymity, perfect erasure, perfect malware detection, or that a
    clean scan proves a file safe.
12. Architectural changes require a new ADR in `docs/adrs/`.

## Required reading order

1. `docs/00-master-plan.md`
2. `docs/01-requirements.md`
3. `docs/02-threat-model.md`
4. `docs/03-architecture.md`
5. `docs/05-state-machines.md`
6. `docs/07-cli-reference.md`
7. `docs/09-rpc-protocol.md`
8. `docs/10-go-architecture.md`
9. `docs/11-qemu-runtime.md`
10. `docs/12-networking-vpn.md`
11. `docs/13-storage-ephemerality.md`
12. `docs/16-scanning-sanitization.md`
13. `docs/20-ci-cd.md`
14. `docs/24-testing.md`
15. `project/backlog.yaml`

## Initial implementation sequence

1. Make the existing Go scaffold compile under Go 1.26.
2. Add Cobra and structured exit codes.
3. Implement immutable configuration parsing and validation.
4. Implement `private-vm doctor --json` with no privileged mutations.
5. Implement daemon Unix-socket startup and peer-credential authentication.
6. Implement session records under `/run/private-vm` only.
7. Add QMP process lifecycle with a fake-QEMU test harness.
8. Add NixOS image evaluation and the workstation boot smoke test.
9. Add AF_VSOCK guest handshake with per-session authentication.
10. Add workstation display, stop protection, and explicit import/export.
11. Only then add downloader, scanner, and exporter workflows.

## Definition of done for every change

- Tests prove success, failure, cancellation, timeout, and cleanup.
- No new persistent session data appears.
- No secrets appear in logs or process arguments.
- Error messages include a stable error code and a concrete remediation.
- Documentation and JSON schemas are updated.
- `go test ./...`, `go test -race ./...`, `go vet ./...`, and `nix flake check`
  pass where supported.
- The change does not weaken an ADR without replacing it.

## Do not guess

When code and documentation disagree, the documentation controls until an ADR
changes it. When an external API differs from the plan, update the implementation
and documentation in the same commit; do not silently invent behavior.
