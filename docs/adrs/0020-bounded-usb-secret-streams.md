# ADR 0020: Bounded USB secret streams and semantic export RPCs

Status: accepted

## Context

The frozen exporter service listed `PrepareUSB` as a unary request containing
only a confirmation boolean. That shape could not deliver a LUKS2 passphrase
without adding it to a reusable protobuf request, and the daemon API exposed no
semantic way to obtain a one-use preparation plan or relay one approved scanner
output. Passing a passphrase by process argument, environment variable, file,
configuration value, generic command RPC, or log is forbidden.

The exporter must also prove file and filesystem flush, atomic rename, reread,
unmount and LUKS close. A generic `TransferReceipt` cannot represent that
role-specific evidence.

## Decision

- CLI-to-daemon and daemon-to-exporter passphrases use authenticated bounded
  client streams. The first frame carries the request context and every later
  frame carries only a bounded secret chunk.
- Each receiver copies the complete value directly into `secret.Bytes`, clears
  protobuf and staging buffers on every path, and destroys the protected value
  when the synchronous operation returns.
- The daemon exposes only `PlanUSBPreparation`, streamed `PrepareUSB`, and
  `ExportApprovedToUSB`. Requests contain opaque session, claim, enrollment and
  approved-output identifiers, never block paths, mount targets, commands or
  QEMU arguments.
- The two exact confirmations are checked against a daemon-owned, one-use,
  five-minute plan after final claim revalidation and before Polkit and the
  exporter commit boundary.
- Exporter guest RPCs accept an identity expectation rather than a device path.
  `USBTransferReceipt` carries the typed flush/rename/reread evidence required
  for three-hash verification. These are additive `PrepareExactUSB`,
  `WriteVerifiedFile`, and `VerifyWrittenFile` methods; the earlier unary and
  generic-receipt method signatures remain registered and fail closed.
- The generic host daemon and generic guestd build remain unavailable for these
  methods. Composition succeeds only when fixed-policy typed adapters for the
  networkless exporter, exact QEMU USB attachment, guest-local LUKS2/ext4
  operations and scanner source are supplied.

## Consequences

gRPC and Go necessarily create short-lived plaintext copies while decoding a
secret chunk. The implementation bounds and clears owned copies but does not
claim that every runtime or transport copy can be proven overwritten. No
secret or digest is included in JSON output, events or error details.

The role implementation does not serve the earlier unsafe unary preparation
stub, but its descriptor remains wire-compatible. Host and guest images still
must be upgraded together before using the additive exact-device workflow.
