# ADR 0026: Trust only systemd-created workspace endpoint mounts

- Status: Accepted
- Date: 2026-07-20

## Context

ADR 0021 requires workstation guestd to pin `Inbox` and `Export` and refuse
filesystem crossings beneath them. The hardened unit grants write access only
to those two paths with systemd `ReadWritePaths`. systemd implements each grant
as a bind mount in the service namespace, so treating the initial endpoint
mount itself as an unexpected crossing prevents guestd from starting.

## Decision

Guestd may cross exactly the initial, fixed-name `Inbox` and `Export` endpoint
bind mounts while resolving them beneath the already opened `/home/private`
directory. The open still requires `RESOLVE_BENEATH`, `RESOLVE_NO_SYMLINKS` and
`RESOLVE_NO_MAGICLINKS`, and the resulting device and inode are pinned.

Every create, open, list, rename, unlink and synchronization operation below an
endpoint continues to use its pinned dirfd with `RESOLVE_NO_XDEV`. Pathname
device/inode verification before publication and completion remains mandatory.
No RPC can select an endpoint or mount, and the unit retains only the two
explicit `ReadWritePaths` entries.

## Consequences

- systemd's least-privilege writable-path sandbox and the pinned workspace
  protocol can coexist.
- A nested or substituted mount below either endpoint still fails closed.
- A change to the two fixed endpoint names or unit grants requires a new ADR.
