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
