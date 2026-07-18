# Start here

This bundle contains the consolidated specification and starter repository for
`private-vm`.

## Coding agent bootstrap

Run:

```bash
go test ./...
go vet ./...
python3 tools/validate_schemas.py
go run ./cmd/private-vm version
go run ./cmd/private-vm doctor --json
```

Then follow `project/FIRST_10_COMMITS.md` and implement
`project/backlog.yaml` in dependency order.

The first release target is **x86_64 Linux**. Compile-only ARM64 support may be
maintained, but ARM guest images and runtime support are not v1 blockers.

## First engineering tasks

```text
GO-001    pin Go 1.26.5 and dependency policy
NIX-001   validate NixOS 26.05 image outputs and commit flake.lock
PROTO-001 generate and pin the v1 protobuf API
CLI-001   implement the complete command surface
CFG-001   implement strict configuration and policy loading
```

## First usable milestone

```bash
private-vm doctor --strict
private-vm images sync --role workstation --bundle basic
private-vm desktop start --bundle basic
private-vm desktop stop --discard
```

That milestone must already provide:

- a verified immutable NixOS image;
- an ephemeral root overlay;
- XFCE through SPICE on a Unix socket;
- disabled clipboard and file transfer;
- authenticated guest control over VSOCK;
- Proton-only egress with host and guest enforcement;
- teardown after normal stop, CLI interruption, QEMU death, daemon restart and
  host reboot recovery.

Do not begin torrent, scanner or USB integration until the basic workstation
lifecycle passes repeatedly.
