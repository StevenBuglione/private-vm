# USB enrollment and export

## Enrollment

`private-vm usb enroll` internally verifies:

- vendor/product ID
- serial presence and the exact retained serial
- USBGuard hash
- physical port
- interface classes
- capacity
- current mount state
- model string

The CLI's bounded typed review shows the transient kernel path, VID/PID, model,
serial, USBGuard hash, physical port, interfaces, capacity, eligibility and the
complete enrollment fingerprint. Raw USBGuard command output and transient
bus/address remain inside the daemon. The kernel path is never persisted or
accepted as authorization; every later operation resolves the stored complete
identity again.

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

The installed root is `/var/lib/private-vm/enrollments`, mode `0700` and owned
by the daemon. It contains only numeric-UID directories, each mode `0700` and
owned by that authenticated user; `usb-enrollment.json` is a one-link mode
`0600` regular file owned by the same user. Request data cannot select this
path.
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

The production claim adapter re-lists USBGuard and compares the complete
VID/PID/serial/hash/port/interface identity immediately before authorizing the
record. Only USBGuard's numeric record ID enters the fixed `allow-device` and
`block-device` argv. Release blocks that exact unchanged record and then audits
it as blocked or absent; an ID reused for a different identity fails closed.

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

The relay accepts one authenticated approved source. Scanner sources must have
a complete authenticated report, policy approval and reconstructed output;
workstation sources must have authenticated Export state and be ready. The
daemon opens the source once from a volatile registry keyed by role, session and
opaque output ID. No source registration can carry a host/guest path. Each
chunk is at most 1 MiB, has a monotonic sequence, and is cleared from the
relay's owned buffer after the destination consumes it. Overall byte, idle and
operation deadlines are mandatory. Raw names and hashes never enter events or
the export receipt.

The production scanner registrar is reached only through `GuestScannerRelay`
after the per-boot token has MAC-verified the complete canonical report. USB
approval requires exactly one report-listed sanitized output and retains that
authenticated offline scanner until the one-use source is consumed or the
scanner actor is explicitly cleaned. Opening the source invokes only
`ExportApprovedFile(output_id)` on the role-restricted scanner service. The
begin descriptor, every sequence, total size, end digest and clean stream end
must match the report. Successful USB verification then stops and cleans the
scanner as well as the exporter.

The production workstation registrar runs only after
`VerifyWorkspaceExport` has compared daemon and receiver digests and the guest
has rehashed and marked one opaque output current. Opening it re-reads the
authenticated workspace inventory, requires the same exported/unchanged byte
identity, and re-streams only that output through the workstation relay. A
changed entry or changed begin/end digest fails before exporter commit. Both
registrars use a one-frame backpressure channel; neither buffers a file or
accepts a host path, guest path, mount, or shared folder.

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

The production host boundary exposes only preparation planning, streamed
preparation and approved-output export interfaces. It composes the verified
exporter image/storage selector, headless/no-NIC QEMU runtime, inherited
capability, authenticated VSOCK client, typed QMP hotplug and exact session
cleanup owner at daemon startup. It returns `USB_WORKFLOW_UNAVAILABLE` if any
required adapter is absent. The exporter guest boundary implements the five
role methods behind a fixed-policy adapter and verifies identity, no-network
evidence, LUKS2/ext4 preparation, monotonic stream bounds, receive/reread
hashes, both fsyncs, atomic rename, unmount and LUKS close. The exporter-compiled guestd
uses one image-owned Linux adapter: it discovers exactly one unmounted
mass-storage-only USB device, matches VID/PID/serial/capacity, proves that only
loopback networking exists, and owns fixed LUKS2/ext4, mapper, mount and output
paths. Its external tools and arguments are fixed; only the passphrase stream
is connected to command stdin.

QMP attach is treated as ambiguous ownership before the request is sent. A
timeout therefore enters cleanup rather than assuming the device was not
attached. Detach, VSOCK close, process stop, image destroy, CID release and
directory removal each retain their handle after failure and are retried by the
session owner. Process absence resolves an otherwise ambiguous attach/detach;
no successful receipt is possible while any ownership or audit remains.

## Interrupted export

The report is `INCOMPLETE`. The USB must be reverified in exporter before use.
The host must not mount it to inspect partial output.
