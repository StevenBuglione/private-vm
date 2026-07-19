# ADR 0020: Scanner offline boot selection

- Status: Accepted
- Date: 2026-07-19

## Context

The scanner image already contains separate definitions-update and
`scan-offline` NixOS configurations, and the host already reuses one root
overlay while changing from a networked/no-quarantine QEMU device graph to a
no-NIC/read-only-quarantine graph. A specialisation existing in the store does
not by itself make the second boot enter it. Selecting the wrong configuration
would either leave update networking available during parsing or make the guest
phase document disagree with the host's intended device graph.

The selection must survive the update VM shutdown in the same encrypted or
tmpfs-backed overlay, but callers must not receive a generic boot-entry,
command, path or QEMU-argument surface.

## Decision

After the official definition receipt has been atomically committed, the
scanner guest starts exactly one root-owned systemd oneshot:
`private-vm-scanner-stage-offline.service`. Its immutable `ExecStart` invokes
the current configuration's `scan-offline` `switch-to-configuration` with the
single `boot` action. This records that Nix specialisation as the next boot
default in the same root overlay. The unprivileged guestd process can only
start or stop that fixed unit through an exact Polkit allowlist.

The typed QEMU renderer also supplies a non-secret `fw_cfg` expectation:
`definitions-update` for the first boot and `scan-offline` for the second.
Scanner guestd reads that fixed kernel-exposed item and requires it to equal the
immutable `/etc/private-vm/scanner-phase.json` phase before collecting any
scanner evidence. Missing, unknown or mismatched values fail closed. Other
guest roles and caller-selected scanner modes are rejected by the QEMU spec.

The host stops and audits the update VM before relaunching that exact overlay.
The second launch still independently requires no NIC and one read-only
quarantine disk. Failure, cancellation or timeout while staging invokes a
bounded stop of the fixed unit; incomplete cleanup blocks reuse and the VM
cleanup owner destroys the overlay.

## Consequences

- A definition receipt is not reported successful until the next boot target
  has been staged.
- Boot selection persists only as part of the already-owned scanner overlay;
  no new host-persistent session record is created.
- QEMU intent, booted Nix phase, same-overlay identity, NIC absence and
  quarantine read-only evidence are separate fail-closed checks.
- Returning to the online scanner configuration requires a fresh scanner
  session and overlay; the offline specialisation disables its staging and
  update units.
