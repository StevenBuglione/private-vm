# ADR 0028: Confine workstation guestd DAC override to exact endpoints

- Status: Accepted
- Date: 2026-07-20

## Context

The private desktop user's home is correctly mode `0700`. Workstation guestd
runs as root with a narrow capability bounding set, so without
`CAP_DAC_OVERRIDE` it cannot pin or transfer through that user's `Inbox` and
`Export` directories. Relaxing the home mode would expose it to unrelated guest
users and running guestd as the desktop user would prevent reliable access to
the root-only fw_cfg boot capability.

## Decision

Only workstation guestd receives `CAP_DAC_OVERRIDE`, in addition to its existing
`CAP_IPC_LOCK` and `CAP_NET_ADMIN`. Its unit retains `ProtectSystem=strict` and
exact writable exceptions for `/home/private/Inbox` and
`/home/private/Export`; the capability does not make any other system path
writable. The semantic RPC and pinned-dirfd implementation still expose only
those two endpoints.

Downloader, scanner and exporter capability sets are unchanged.

## Consequences

- Workstation guestd can traverse the `0700` home and read/write the two typed
  transfer endpoints.
- A compromised workstation guestd could read other plaintext in the same
  disposable workstation guest. It gains no host, cross-role or persistent
  storage access, and cannot write outside the two unit exceptions.
- Any additional writable path or role using `CAP_DAC_OVERRIDE` requires a new
  ADR.
