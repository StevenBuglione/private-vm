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

Startup also requires the root-owned mode-`0600`
`.private-vm-no-backup` marker with the frozen v1 content
`private-vm-ephemeral-scratch-v1`. A missing, replaced, linked, writable or
malformed marker blocks encrypted scratch creation. The marker is explicit
operator evidence, not a claim that every third-party backup tool honors it.

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

The storage implementation attaches the ciphertext with atomic
`losetup --find --show`, then proves through sysfs that the returned trusted
`/dev/loopN` block device backs the exact owned ciphertext before formatting it.
After `cryptsetup open`, it verifies the `/dev/mapper` link, DM name and sole
loop slave before allowing `mkfs.ext4`. It
passes the random LUKS key through inherited file
descriptor 3 to `cryptsetup`; argv and environment contain no key bytes. Loop
selection is validated after attachment and before any destructive operation.
The outer ext4 mount is
`nodev,nosuid,noexec`, contains only allowlisted opaque filenames, and is torn
down in the order mount → mapper → loop → key → ciphertext. A failed cleanup
step retains its typed handle, key and ciphertext so the same cleanup owner can
retry safely. Mountpoints, ciphertext and loop/mapper identities are rechecked
before cleanup; substituted paths or devices are never removed or formatted.

The NixOS module writes the marker only when the operator explicitly sets
`services.private-vm.scratchBackupExcluded = true` after configuring the host's
actual backup, indexer and snapshot tools. The default is false.

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
The planner reads bounded `MemTotal`/`MemAvailable`, `statfs` evidence for both
roots and `/proc/swaps`; only zram swap is accepted. Arithmetic overflow,
missing evidence, a non-tmpfs runtime root, disk-backed swap or insufficient
RAM/disk capacity blocks allocation before mounting or sparse-file creation.
One immutable capacity pool serializes all session reservations against the
same host snapshot. A reservation accounts for guest RAM plus tmpfs writes or
guest RAM plus encrypted-disk writes and is an idempotent session cleanup
resource; concurrent plans cannot spend the same capacity twice.

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

The base is opened without symlink or magic-link traversal, must be a trusted
non-writable standalone QCOW2 image, and may not itself have a backing file.
The newly created overlay must report the exact full backing path and virtual
size. Base and overlay device/inode, owner, group, link count, size and mode are
pinned across each `qemu-img` operation. An image-use registry prevents
`qemu-img` from touching a base or overlay while QEMU holds an active lease,
and cleanup uses a pinned parent directory plus `unlinkat` after exact identity
revalidation. Overlay, tmpfs and LUKS handles expose idempotent cleanup plus explicit
absence audits and are registered through the session actor's atomic allocation
boundary.

The production storage stack first reserves the plan's guest RAM and bounded
root/scratch write budget from one daemon-owned capacity pool. It selects tmpfs
only when the immutable host evidence preserves the required host reserve;
otherwise it creates the random-key LUKS2 outer filesystem. The fresh root
overlay and, for downloader only, an opaque raw quarantine file live inside
that outer filesystem. Failure at any later step returns the one partially
constructed owner or proves reverse cleanup before returning; no guest or
quarantine filesystem is interpreted by the host.

## Quarantine disk

Use a raw sparse disk or QCOW2 without a backing image. The guest creates a
simple filesystem. The host treats it as opaque.

The downloader guest resolves only `/dev/disk/by-id/virtio-quarantine`, opens
the final block node without following another link and verifies the sysfs
serial, writable bit and capacity. It accepts only an all-zero initial header
or an ext4 superblock from an interrupted/restarted preparation; every other
signature fails closed. Formatting uses the pinned `mkfs.ext4` with the device
on inherited fd 3, then guestd mounts it at `/mnt/quarantine` with
`nodev,nosuid,noexec`. The payload, incomplete and qBittorrent state
directories have fixed identities and permissions. Seal/cleanup calls
`syncfs`, unmounts, audits exact mount absence and only then closes the device.
No one of these operations mounts the disk on the host.

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

1. capture an aggregate identity seal for every immutable base image
2. enumerate only bounded objects found by trusted volatile-record, kernel, and
   scratch inventories
3. validate the closed resource kind, internal session ID, daemon ownership and
   exact identity fingerprint for every candidate
4. atomically claim each orphan against the live registry; a current owner
   blocks recovery of that session
5. prove that no recoverable private-vm key source survived before touching a
   session with storage artifacts
6. pin the complete candidate set before the first mutation, then revalidate the
   exact identity again immediately before every typed cleanup operation
7. stop QEMU and its cgroup, remove private sockets/VSOCK/network/USB claims,
   then tear down outer mount, mapper, loop, ciphertext and runtime path in the
   fixed dependency order
8. audit every individual object and the complete QEMU, cgroup, socket, CID,
   namespace, interface, nftables, loop, mapper, mount, USB, ciphertext and
   runtime-path set for the session
9. verify the immutable base-image aggregate is unchanged
10. emit only the closed, coarse `schemas/recovery-report.schema.json` report

The recovery owner stops at the first dependent failure for a session. A later
attempt repeats inventory and exact identity validation and resumes safely;
another independently claimed session may still converge. Cancellation and
timeouts leave the report incomplete and never turn an unaudited absence into
success. Ordinary session admission stays closed until startup recovery returns
complete.

The production startup composition writes the closed report atomically to
`/run/private-vm-recovery-private-vm.json` for the default runtime root before
opening the control socket. The report is mode `0600`, remains volatile, and is
replaced on each startup. Failure to publish it is itself a startup failure.

The current concrete Linux adapter can independently recover exactly pinned
runtime records, QMP/SPICE sockets, outer ext4 mounts, device-mapper mappings,
loop devices and scratch ciphertext. Runtime records in `CREATED`,
`PREFLIGHTED`, `IMAGES_VERIFIED`, or already audited `DESTROYED` may be removed
after revalidation. A ciphertext whose volatile record disappeared at reboot
may be removed only after the outer mount, mapper and backing loop are proven
absent or have been closed in dependency order, and the fresh daemon proves no
ordinary key file survived.

An advanced volatile record (`STORAGE_READY` through `DESTROYING`) currently
blocks startup before any mutation. Those records do not yet contain the exact
pidfd/start-time/cgroup, network, VSOCK and USB ownership identities needed for
safe daemon-restart cleanup. The adapter does not infer ownership from a name,
PID or pathname and does not downgrade this gap to an empty inventory. The
remaining D-005 work is to retain those redacted exact identities under
`/run`, add the corresponding typed Linux adapters, and pass the daemon
`SIGKILL` and maintenance-window reboot acceptance gates.

Never delete a path based only on a filename supplied by a user.
