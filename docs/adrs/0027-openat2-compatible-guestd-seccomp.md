# ADR 0027: Keep guestd seccomp compatible with mandatory openat2

- Status: Accepted
- Date: 2026-07-20

## Context

Guestd's workspace and hostile-file boundaries require Linux `openat2`.
systemd's `RestrictSUIDSGID` implementation cannot inspect `openat2`'s pointed
to `open_how` flags, so enabling it makes the syscall return `ENOSYS`. This was
reproduced in the complete production service sandbox and prevented the
workstation role from composing.

Falling back to pathname checks or `openat` would weaken ADR 0021. Removing all
mode protection would be unnecessary.

## Decision

Guest images disable the coarse `RestrictSUIDSGID` switch and install an
explicit systemd syscall deny-list for the path-based `chmod`, `fchmodat` and
`fchmodat2` calls. Guestd's sole fd-only `fchmod` call applies fixed mode `0600`
to a newly created anonymous secret memfd before it is sealed; the secret tests
verify that exact mode and sealing. Its fixed filesystem creation paths use
non-executable `0600` files and `0700` directories.

`NoNewPrivileges`, the role-specific capability bounding set, locked accounts,
the strict device policy, immutable system paths and all other service sandbox
controls remain enabled. Linux `openat2` remains mandatory and there is no
fallback.

## Consequences

- Race-safe dirfd traversal works inside the production service namespace.
- Guestd cannot change pathname mode bits; the fixed anonymous memfd mode
  transition remains available.
- Any future need for a chmod-family syscall requires a new ADR and an explicit
  security review.
