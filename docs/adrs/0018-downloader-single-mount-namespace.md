# ADR 0018: Downloader single mount namespace

## Status

Accepted for frozen v1.

## Context

Downloader guestd validates, formats and mounts the quarantine device only
after systemd has started guestd inside its hardened filesystem namespace.
`ProtectSystem=` and `ReadWritePaths=` create a private mount namespace for
each system service. A separate qBittorrent system unit therefore cannot see a
quarantine mount created by guestd. Adding the mount path to both units creates
an unrelated bind mount before device validation and does not propagate a later
guestd mount into the qBittorrent unit.

Moving the mount to the guest's initial namespace would split the typed
quarantine lifecycle across guestd and systemd. Weakening guestd's filesystem
sandbox would also expose more of the image than the application needs.

## Decision

Guestd starts exactly one package-pinned qBittorrent child after the quarantine
is mounted and the authenticated VPN controller has installed and verified the
kill switch and `proton0`. The child inherits guestd's systemd-created mount,
filesystem, syscall, no-new-privileges and capability restrictions. Before
exec, the Go process owner drops to the fixed `private:users` identity, creates
a distinct process group, sets a parent-death signal, fixes the working
directory and supplies an allowlisted, secret-free environment and argument
list. Standard output and error are discarded.

The executable is an immutable Nix-store-backed link outside the global command
path. The manager opens a pidfd before accepting ownership. Stop uses bounded
TERM/KILL escalation and reaps the child; partial starts and canceled operations
retain ownership until cleanup succeeds. qBittorrent is not represented as a
second systemd service.

The quarantine mount path is not a guestd `ReadWritePaths=` entry, because that
entry would install the conflicting bind mount. The newly mounted filesystem is
the only writable payload tree. Downloader guestd uses read-only home
protection; the child can read LightDM's Xauthority file but its XDG writable
paths remain limited to volatile `/run` and quarantine.

## Consequences

- qBittorrent and its sole cleanup owner observe the same verified quarantine
  mount without moving filesystem lifecycle control outside Go.
- The application has no independently startable unit, generic executable or
  caller-controlled command surface.
- Process supervision is part of guestd's typed downloader cleanup path and is
  covered for start failure, cancellation, TERM/KILL and idempotent stop.
- Live image acceptance must prove the quarantine is the expected virtio
  device, qBittorrent starts only after VPN verification and no process remains
  after downloader cleanup.
