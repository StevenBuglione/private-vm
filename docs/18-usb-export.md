# USB enrollment and export

## Enrollment

`private-vm usb enroll` shows:

- kernel device path
- vendor/product ID
- serial
- USBGuard hash
- physical port
- interface classes
- capacity
- current mount state
- model string

It refuses:

- system/root/boot device
- mounted device
- multiple matching devices
- no stable identity unless port binding is accepted
- composite interfaces other than exactly mass storage
- read-only device
- insufficient capacity

Enrollment stores identity only, never filesystem content.

The persistent record is the closed `schemas/usb-enrollment.schema.json`
document. It uses `schema_version = 1`, stores no kernel block path or transient
bus/address, and is written as a mode-`0600` regular file in a private
user-owned directory. The `enrollment_id` is derived from the complete
normalized identity, so editing any identity field invalidates the record.

A serial-bearing device is still pinned to its observed physical port so a move
is visible. A device without a serial can be enrolled only after the user
separately accepts physical-port binding; moving it invalidates the enrollment.
Every later claim enumerates a fresh snapshot and requires exactly one complete
match. `/dev/sdX` names, bus numbers and addresses are observations only and
never authorize a claim.

## USBGuard

NixOS integration enables USBGuard with implicit block. The enrolled transfer
device rule should require its exact identity and:

```text
with-interface equals { 08:*:* }
```

Existing keyboard/mouse policies must be preserved. Installation must not
blindly replace USBGuard rules.

The source core emits an exact suggested rule containing VID/PID, optional
serial, USBGuard hash, physical port and
`with-interface equals { 08:*:* }`. Applying or merging that suggestion remains
an explicit privileged installation operation.

## Host automount

The module/package disables or documents disabling desktop automount for the
transfer device. `doctor` fails if the enrolled device is mounted.

## Passthrough

The daemon claims the physical device and passes exact bus/address or
vendor/product/serial association to QEMU exporter. It re-verifies identity
immediately before launch.

No generic `--usb` raw argument exists.

The daemon's host claim is a registered exporter-session resource. Exact
enrollment resolution and the USBGuard-backed acquisition run inside the one
session actor; successful, failed and canceled allocations all retain one
idempotent cleanup and absence-audit owner. Explicit release may run before
session destruction, but the actor repeats the idempotent release/audit during
final cleanup. Claim and release accept only opaque IDs—not paths, bus/address,
mount flags or arbitrary USBGuard policy text.

## Export formats

### Default: `luks2-ext4`

- entire device or one GPT data partition
- LUKS2
- ext4
- user enters passphrase directly through secure CLI/guest path
- no passphrase in daemon persistent config
- exporter mounts, writes, syncs, rereads, hashes, unmounts, closes

## Destructive preparation

Preparation first emits a closed `usb-prepare-plan` containing the enrolled
identity fingerprint, exact capacity, `luks2-ext4` policy, a 128-bit random
challenge and two separate confirmation phrases. Both phrases must match
exactly and the plan expires after five minutes. The second phrase binds the
enrollment ID, identity fingerprint and one-use challenge, so a confirmation
from an earlier inspection cannot authorize a changed device.

After both phrases are accepted, the daemon re-enumerates the claim and rejects
identity, kernel-path, bus/address, capacity, interface, USBGuard, mount or
read-only drift. It then requests only `org.private-vm.usb.prepare` immediately
before entering the destructive exporter operation. The LUKS2 passphrase stays
in the volatile secret type. CLI-to-daemon and daemon-to-exporter delivery uses
authenticated client streams with at most four 256-byte chunks and 1024 bytes
total. Each receiver clears its protobuf and staging buffers and destroys its
protected value when the synchronous operation returns. It is never part of
argv, the environment, disk, enrollment JSON or progress events. This bounds
owned plaintext copies without claiming that Go or gRPC can prove every
transient runtime copy was overwritten.

Progress has explicit `CONFIRMED`, `COMMIT_STARTED`,
`DESTINATION_PREPARED`, `CANCELED_PRECOMMIT` and `INCOMPLETE` states. A
cancellation observed before `COMMIT_STARTED` guarantees the destructive
backend was not invoked. Once commit starts, any error remains `INCOMPLETE`
until exporter-side inspection and cleanup succeed.

### Future compatibility format

exFAT may be added only under a separate weaker policy with a warning that it
provides no block encryption and expands host/destination parser exposure.

## Write procedure

1. verify enrolled identity
2. verify destination capacity
3. start exporter with no NIC
4. authenticate guest
5. attach USB
6. guest verifies identity/capacity
7. explicit destructive format confirmation if needed
8. mount destination
9. receive one approved stream
10. write temporary name
11. fsync file and filesystem
12. atomic rename
13. reread and hash
14. compare sender, relay, and USB hash
15. write manifest
16. unmount
17. close LUKS
18. detach USB
19. stop exporter
20. release host claim

The source implementation represents each of these boundaries with typed,
bounded interfaces. Before boot it revalidates the enrolled claim and requires
an independent boundary audit that the host has not mounted the device and the
scanner has not received it. The lifecycle adapter may then boot only the
networkless exporter, attach the revalidated device through the typed QEMU
hotplug boundary, and verify the same identity inside the guest.

The relay accepts one authenticated, complete, policy-approved reconstructed
output. Each chunk is at most 1 MiB, has a monotonic sequence, and is cleared
from the relay's owned buffer after the destination consumes it. Overall byte,
idle and operation deadlines are mandatory. Raw names and hashes never enter
events or the export receipt.

The scanner digest, relay digest, exporter receive digest and exporter reread
digest remain internal redacted values. A successful receipt exposes only the
three equality results and requires all of them to be true. It also requires
file and filesystem `fsync`, atomic rename, unmount, LUKS close, USB detach,
exporter stop, claim release and an absence audit. Any missing field or false
value makes the closed `usb-export-receipt` invalid.

The export operation is the single cleanup owner for its writer, exporter,
destination and claim. Failure cleanup runs in dependency order: remove a
partial writer, unmount/close, detach, stop, release and audit. It stops at the
first dependent failure and retains state so the same operation can retry the
incomplete step. Cancellation or caller loss cannot turn incomplete cleanup
into a success receipt.

The source host boundary exposes only preparation planning, streamed
preparation and approved-output export interfaces. The exporter guest boundary
implements the five role methods behind a fixed-policy adapter and verifies
identity, no-network evidence, LUKS2/ext4 preparation, monotonic stream bounds,
receive/reread hashes, both fsyncs, atomic rename, unmount and LUKS close. The
generic daemon/guestd composition returns `USB_WORKFLOW_UNAVAILABLE` or refuses
exporter startup until the image-specific QEMU, scanner and fixed-path
cryptsetup/mkfs/mount adapters are installed.

## Interrupted export

The report is `INCOMPLETE`. The USB must be reverified in exporter before use.
The host must not mount it to inspect partial output.
