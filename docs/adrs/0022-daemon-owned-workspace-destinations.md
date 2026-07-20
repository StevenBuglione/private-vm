# ADR 0022: Daemon-owned workspace destination transactions

## Status

Accepted for frozen v1.

## Context

The workstation relay can prove a guest-to-daemon export, but a production
`workspace export` must also prove persistence and an independent re-read at a
declared destination. Letting the unprivileged CLI receive plaintext, choose a
host path, or retain the final digest would move lifecycle and storage security
decisions outside the daemon. Treating USB as a host filesystem would violate
the host-mount prohibition. The encrypted-bundle destination has no approved
container, key-delivery, or ciphertext-storage contract.

## Decision

The CLI sends `ExportWorkspaceToDestination` with one owned workstation
session, one opaque output ID, and a closed destination enum. It sends no host
path, device selector, mount point, hash, or transfer bytes. The daemon verifies
that the current output needs export and prepares a semantic destination
transaction before opening the workstation source.

The provider receives an authorized plan containing only owner UID, source
session ID, output ID, and destination. Its transaction may consume exactly one
bounded source callback. A successful transaction reports an independently
calculated receiver digest plus explicit persistence, re-read, and cleanup
evidence. The daemon requires this digest to equal the authenticated workstation
relay receipt and then asks workstation guestd to re-hash the current output.
Only that final verification records an exported receipt and allows `READY`.

The transaction owns an idempotent `Abort` operation. The daemon invokes it
under an independent bounded context after transfer, destination, receipt,
cancellation, timeout, or final-verification failure. Incomplete abort is a
separate blocking recovery error. Ordinary dirty-stop protection and explicit
discard remain unchanged.

USB is the only accepted v1 enum. Its provider composes the networkless exporter
workflow and never mounts the export filesystem on the host. It selects exactly
one owner-matching active exporter in `DESTINATION_PREPARED`, reloads the exact
enrollment, and revalidates the sole owned claim both before constructing the
source and immediately before consuming it. The direct synchronous adapter
hands each bounded frame to the exporter without a pathname, registry entry, or
second plaintext byte buffer. Success, failure, cancellation, and timeout all
destroy that exporter session and release its serialized operation lock. The
`encrypted-bundle` enum is reserved but rejected before provider preparation or
source consumption until a separate ADR defines its storage and key contract.

## Consequences

- Production CLI export no longer has a memory-writer or host-path boundary.
- The final receiver, not the CLI or source guest, supplies the persistence
  re-read digest.
- Destination unavailability fails before workstation bytes are requested.
- The production daemon binds the semantic transaction to the same confirmed
  claim and exporter workflow used by explicit USB preparation.
- A successful destination write whose guest output changes before final
  verification remains dirty and must be exported again or explicitly
  discarded.
