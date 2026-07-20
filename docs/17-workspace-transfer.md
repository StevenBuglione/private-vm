# Workspace import and output transfer

## Host-to-workstation import

Only explicitly selected regular files.

Checks:

- caller owns or can read the file
- no device, FIFO, socket, or directory
- no symlink by default
- maximum size
- stable size/inode during read
- SHA-256 before/while transfer
- no path sent to guest beyond sanitized display name

The host opens the file with safe flags and streams from the open descriptor.
The guest chooses a collision-free path under `~/Inbox`.

## Scanner-to-workstation promotion

Only output with:

- completed scan report
- approved policy verdict
- output ID and hash
- session state allowing promotion
- scanner guest still authenticated or approved bytes already in bounded relay

The scanner is stopped and destroyed before a workstation that will receive the
content is exposed to the Internet.

## Workstation output model

Guestd watches only `~/Export`.

For each file:

- relative path
- size
- SHA-256
- modification generation
- last exported hash/destination
- state

States:

- `CLEAN`: no export files
- `READY`: current hashes exported and verified
- `UNEXPORTED`: never exported
- `CHANGED`: changed after export
- `UNREACHABLE`: agent unavailable

## Streaming relay

The daemon relays chunks between VSOCK streams without writing plaintext to disk.

Requirements:

- 1 MiB default chunks
- max total from plan
- read/write deadlines
- backpressure
- independent host hash
- partial receiver cleanup
- final three-way hash comparison:
  - sender
  - host relay
  - receiver

## Declared destination transaction

The production CLI never acts as the persistent receiver. It selects one exact
opaque output and the closed `usb` destination. The daemon prepares the typed
destination before it opens the workstation source, then supplies a one-shot
bounded stream callback to that transaction. The transaction must report that
the output was persisted, independently re-read, and that its runtime resources
were cleaned. The daemon compares the workstation sender, daemon relay, and
destination re-read SHA-256 values before asking the workstation guest to
re-hash the current output and record the export receipt.

Every pre-verification failure, cancellation, or timeout invokes idempotent
abort with an independent deadline. An abort failure returns
`WORKSPACE_DESTINATION_CLEANUP_INCOMPLETE` and requires recovery. Destination
plans contain no pathname, device node, mount point, or arbitrary command.

## Encrypted bundle destination

A later v1.x feature may export an encrypted bundle to a host-selected file.
Requirements:

- recipient/passphrase selected explicitly
- encryption performed in exporter-like guest or audited library
- host receives ciphertext only
- manifest inside authenticated encryption
- no plaintext staging

USB remains the required v1 destination for persistent physical output unless
the implementation team completes and reviews the encrypted-bundle ADR.
