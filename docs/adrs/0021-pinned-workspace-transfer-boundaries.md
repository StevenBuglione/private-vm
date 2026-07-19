# ADR 0021: Pinned workspace transfer boundaries

- Status: Accepted
- Date: 2026-07-19

## Context

Workstation imports previously validated pathnames before opening a source or
publishing a guest file. A pathname can be replaced after that validation, and
a stream that accepts frames after `TransferEnd` has no unambiguous commit
boundary. Those races are unacceptable for the sole trusted-file ingress and
workspace egress paths.

## Decision

The Linux host opens the trusted source parent and selected regular file with
`openat2`, `O_NOFOLLOW`, and no-symlink/no-magic-link resolution. It retains
both descriptors for the transfer lifetime; hashing and streaming consume the
same selected file descriptor even if a pathname is later replaced.

Workstation guestd pins `Inbox` and `Export` directory descriptors during role
composition. It creates, opens, lists, renames, unlinks, and synchronizes files
relative to independently leased pinned descriptors. It also compares the
configured directory pathname's device and inode with the pinned identity
before publication and after bounded operations. A missing, replaced, linked,
cross-mount, or non-directory workspace component fails closed.

An import consists of one begin frame, no more than 8,192 non-empty chunks of
at most 1 MiB, and one end frame. The read immediately after the end frame must
return EOF. The daemon relay applies the same rule in both directions and does
not forward or record the end frame until EOF is proven. Cancellation,
deadline, invalid bounds, trailing input, synchronization failure, directory
replacement, and receipt failure remove the staged or newly published import.

## Consequences

- The supported production boundary requires Linux `openat2`; unsupported
  kernels fail closed rather than falling back to pathname validation.
- Renaming the source parent does not redirect an open transfer. Replacing a
  guest workspace directory blocks publication or completion.
- Guestd owns and closes the pinned descriptors when its role server stops.
- No host mount, guest pathname, generic filesystem API, or arbitrary guest RPC
  is added.

