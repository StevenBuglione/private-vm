# Storage and ephemerality

## Persistent objects

Only these are persistent by design:

- verified immutable base images
- image manifests, SBOMs, and provenance bundles
- application binaries/configuration
- explicitly enrolled USB identity
- explicitly exported user files
- optional user-exported reports

## Session directory

```text
/run/private-vm/<session-id>/
├── metadata.json          # redacted, volatile
├── qmp/
├── spice/
├── events/
├── secrets/               # memfd preferred; no ordinary files when avoidable
├── mount/                 # outer encrypted session filesystem
└── locks/
```

Mode `0700`, owned by daemon, with per-user access mediated through RPC.

## Large-session encrypted container

Path:

```text
/var/lib/private-vm/scratch/<session-id>.luks
```

Properties:

- sparse regular file
- LUKS2
- random 256-bit or stronger passphrase/key material
- key only in daemon memory/memfd
- no recovery key
- no user password
- no key backup
- excluded from backup and indexing
- startup deletion when orphaned

Inside the opened mapping is an ext4 filesystem containing opaque files:

```text
root-workstation.qcow2
root-downloader.qcow2
root-scanner.qcow2
root-exporter.qcow2
quarantine.raw
uefi-vars.fd
transfer-state/
```

The host mounting this **outer** filesystem does not mount or parse guest content.

The storage implementation passes the random LUKS key through inherited file
descriptor 3 to `cryptsetup`; argv and environment contain no key bytes. Loop
selection is validated before attachment. The outer ext4 mount is
`nodev,nosuid,noexec`, contains only allowlisted opaque filenames, and is torn
down in the order mount → mapper → loop → key → ciphertext. A failed cleanup
step retains the key and ciphertext so the same cleanup owner can retry safely.

## Small-session tmpfs mode

Allowed only when planner proves:

```text
guest RAM
+ expected root writes
+ download bytes
+ scan temporary bytes
+ host reserve
<= safe memory budget
```

Do not rely on sparse virtual size; use conservative expected allocated bytes.

Small mode uses a per-session tmpfs submount with an explicit byte limit and
`nodev,nosuid,noexec`; it does not rely on the capacity of the shared `/run`
mount alone. Planning includes guest RAM, expected allocated writes, and the
larger of 4 GiB or 20% total RAM as host reserve before selecting this mode.

## Key handling

- generated from kernel CSPRNG
- held in a core-dump-excluded, sealed memfd mapping on supported Linux hosts
- memory locked on a best-effort basis; lock failure does not imply protection
- passed to each `cryptsetup` invocation through a fresh read-only inherited FD
  with an independent offset at zero
- not stored in environment or argv
- destroyed after device close
- current owned mapping overwritten before unmap and close
- JSON, text, binary, gob and XML serialization rejected
- Go, library, kernel and hardware copies outside the owned mapping cannot be
  proven erased; the project makes no perfect-erasure claim

On Linux, memfd setup, mapping, dump exclusion and sealing fail closed when the
kernel implements memfd. An `ENOSYS` compatibility fallback cannot provide an
inherited descriptor, so workflows that require FD delivery remain blocked.
Non-Linux heap storage exists only so the package can compile and be tested; it
is not an accepted production storage path.

## Root overlays

Create a fresh QCOW2 overlay with a verified read-only base. Validate backing
format and path. Never chain session overlays across runs.

## Quarantine disk

Use a raw sparse disk or QCOW2 without a backing image. The guest creates a
simple filesystem. The host treats it as opaque.

Attachment matrix:

| Role | Access |
|---|---|
| downloader | writable |
| scanner update | absent |
| scanner scan | read-only |
| workstation | absent |
| exporter | absent |

## Workspace data

Workstation home lives in its root overlay. It is not separately persistent.
`~/Export` is only a convention watched by guestd.

## Swap and hibernation

Strict mode blocks:

- active unencrypted disk swap
- host hibernation enabled for the session
- VM save-state
- QEMU memory dump configuration
- core dumps

zram is acceptable because it remains in volatile memory.

## Cleanup audit

After teardown, verify no:

- running QEMU/cgroup
- open pidfd
- QMP/SPICE socket
- VSOCK CID reservation
- TAP/veth
- network namespace
- nftables table
- loop device
- device-mapper mapping
- mount
- USB claim
- session directory
- secret FD
- active ciphertext session in registry

If any remains, return exit code 24 and keep a redacted recovery record under
`/run` or the daemon's minimal lifecycle journal.

## Reboot recovery

At daemon startup:

1. enumerate only objects matching private-vm naming and ownership
2. verify no current registry owner
3. stop stale transient scopes
4. remove stale netns/nftables/TAP
5. close stale mappings when possible
6. delete orphan ciphertext
7. remove volatile paths
8. emit a coarse recovery summary

Never delete a path based only on a filename supplied by a user.
