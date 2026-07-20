# ADR 0016: User-owned Unix SPICE display proxy

## Status

Accepted

## Context

QEMU and its private SPICE Unix socket are owned by the root daemon. Changing
the QEMU socket or its `0700` parent to the session user would invalidate the
QEMU process owner's identity-pinned cleanup contract, and an unexpected QEMU
exit could then leave a socket that cleanup must refuse to remove. Running
`remote-viewer` as root is prohibited.

## Decision

After QEMU has created and the launcher has validated the root-owned mode-`0600`
SPICE Unix socket, the workstation runtime creates a second Unix socket at the
fixed path `/run/private-vm/display/<session-id>.sock`.

- The `display` directory is root-owned mode `0711` beneath the existing
  `root:private-vm` mode-`0750` runtime root.
- The proxy socket is identity-pinned, mode `0600`, and owned only by the
  session owner UID. The directory is not caller-writable.
- Every accepted connection is checked again with `SO_PEERCRED` and relayed
  only to the fixed private SPICE socket for that same session.
- The proxy has one owned accept/relay loop, bounded buffers, and a bounded
  cancellation/cleanup owner. It permits one active viewer connection and
  immediately closes a concurrent connection rather than queueing it. Viewer
  death closes one connection without affecting the VM; session cleanup closes
  all proxy connections and removes only the pinned socket identity.
- The CLI derives the proxy path only from a validated opaque session ID and
  launches a root-owned `remote-viewer` executable as the invoking user. It has
  no arbitrary viewer command or socket-path option.
- `desktop start` does not launch a viewer. `desktop connect` and
  `desktop restart-viewer` own a foreground viewer until it exits or the
  bounded CLI context cancels it; either outcome leaves the VM lifecycle
  unchanged.

QEMU still disables clipboard and agent file transfer, and no TCP listener,
USB redirection, shared folder, or alternate SPICE destination is introduced.

## Consequences

The QEMU socket remains entirely under the existing root cleanup contract, and
the graphical process is user-owned. The daemon relays display bytes but does
not interpret or persist them. The host remains trusted and can observe the
display, as already stated by the threat model.

The proxy adds a small daemon attack surface. It is limited to local Unix
sockets, exact peer UID, one fixed source, bounded memory and session-owned
cleanup. A changed proxy pathname or inode is not removed and becomes a typed
cleanup failure.
