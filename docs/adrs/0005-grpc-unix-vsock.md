# ADR 0005: gRPC over Unix sockets and AF_VSOCK

- Status: Accepted
- Date: 2026-07-18

## Decision

The unprivileged CLI talks to `private-vmd` over a mode-0660 Unix socket.
The daemon talks to `private-vm-guestd` over AF_VSOCK using a unique CID and a
single-use session capability delivered through QEMU `fw_cfg`.

Protocol definitions live under `api/privatevm/v1`.

## Security rules

- Unix peer credentials and Polkit authorize host requests.
- Every guest request includes session ID, role and capability.
- The daemon rejects method/role combinations not listed in the capability map.
- Protocol version mismatch is fatal.
