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

## Key handling

- generated from kernel CSPRNG
- held in mutable byte slice and memfd
- memory locked where permitted
- passed to `cryptsetup` by inherited FD
- not stored in environment or argv
- destroyed after device close
- current buffer overwritten
- Go zeroing limitations documented

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
