# QEMU runtime

## Minimum host contract

- QEMU 9.2 or newer
- KVM acceleration
- Q35 machine type
- OVMF/UEFI or a tested direct-kernel boot profile
- SPICE compiled in
- virtio-vsock
- virtio-net
- virtio-blk or virtio-scsi
- virtio-rng
- USB host passthrough
- QMP

The exact QEMU feature probe is performed by `doctor`; version alone is not
sufficient.

## Device allowlist by role

### Workstation

- virtio block root
- virtio net
- virtio GPU
- virtio input
- virtio RNG
- virtio VSOCK
- SPICE vdagent channel
- optional audio when explicitly requested

### Downloader

Same as workstation plus:

- quarantine block disk writable

### Scanner update boot

- root
- net
- GPU/input
- RNG
- VSOCK
- no quarantine

### Scanner scan boot

- root
- GPU/input
- RNG
- VSOCK
- quarantine block disk read-only
- **no network device**

### Exporter

- root
- RNG
- VSOCK
- one exact USB host device
- no GPU required
- no network
- no quarantine

Any device outside the role allowlist is a launch validation failure.

## QEMU argument construction

Use a typed `LaunchSpec` and render one argument per field. The renderer validates:

- canonical, directly referenced executable path with trusted owner and modes
- known machine and CPU mode
- bounded vCPU/RAM
- unique, daemon-owned socket paths
- read-only base image
- expected overlay format
- exact network and block device mode
- no `-daemonize`
- no TCP monitor/display
- no user-provided raw arguments
- no secret values

The runtime rejects a symlinked executable, a group/other-writable executable,
or an executable whose parent is not trusted. After `Start`, it compares the
child's `/proc/<pid>/exe` device/inode to that verified file before accepting
the process. Session IDs, VM names, disk serials, TAP names, socket paths,
memory alignment and VSOCK CIDs are bounded typed values rather than raw QEMU
arguments.

Scanner specs additionally render exactly one non-secret boot-mode `fw_cfg`
item. Update mode maps only to `definitions-update`; scan mode maps only to
`scan-offline`; unknown modes and any scanner mode on another role are launch
validation failures. The scanner guest compares this host intent with its
immutable Nix phase document, while same-overlay identity and device isolation
remain independent evidence.

Representative conceptual flags:

```text
-machine q35,accel=kvm
-cpu host
-nodefaults
-no-user-config
-no-reboot
-display none
-qmp unix:/run/private-vm/<id>/qmp.sock,server=on,wait=off
-spice unix=on,addr=/run/private-vm/<id>/spice.sock,...
-device vhost-vsock-pci,guest-cid=<cid>
-device virtio-rng-pci
```

The final exact flags must be covered by golden tests per role.

## SPICE

Required invariants:

- Unix socket only
- socket mode `0600`
- disable copy/paste
- disable agent file transfer
- no USB redirection
- no TCP fallback
- `remote-viewer` process runs as invoking user, never root

The root-owned QEMU socket is never chowned to the user. After launcher
validation, a daemon-owned bounded Unix relay creates the fixed UID-only
`/run/private-vm/display/<session-id>.sock` handoff. Runtime cleanup closes the
relay, audits its pinned inode and removes it before QEMU socket cleanup.

## QMP

The daemon:

1. starts QEMU
2. waits for QMP socket
3. negotiates `qmp_capabilities`
4. subscribes to lifecycle events
5. issues graceful powerdown
6. escalates to quit/TERM/KILL on bounded deadlines

All QMP JSON is size-bounded and decoded with strict expected shapes. Unknown
events may be logged safely but cannot drive state transitions.

QMP and SPICE destinations must be absent beneath an exact daemon-owned `0700`
session directory. The launcher waits for each Unix socket, pins its expected
owner/type and changes it to `0600` before use. QMP frames, queued events,
greeting fields and error descriptions are bounded; unknown JSON fields,
ambiguous envelopes, mismatched request IDs and trailing documents fail closed.
The accepted Unix connection's `SO_PEERCRED` PID must equal the verified QEMU
child PID and its UID/GID must equal the daemon. A separate non-consuming poll
watch detects QMP hangup/error even while no command is active; losing QMP
triggers bounded process termination and requests the same session cleanup
owner used for client-initiated stop. Canceled contexts interrupt blocked reads
and writes. Cleanup removes a socket
relative to an opened parent directory only after revalidating its type, owner,
mode and parent identity, so it never unlinks a caller-substituted path.

## PID ownership

Use pidfds where available. Store:

- QEMU pidfd
- process start time
- executable inode/device
- cgroup path

Never kill a PID solely by numeric value after a daemon restart without verifying
identity.

The supervisor requires pidfd support, records the kernel process start time and
the executable device/inode, and places QEMU in a delegated child of the
daemon's cgroups-v2 scope with memory, swap, CPU, and PID limits. Shutdown uses
QMP `system_powerdown`, bounded `quit`, and bounded TERM/KILL escalation. A
canceled stop caller does not abandon that escalation. One goroutine
owns `Wait`; cgroup and pidfd cleanup run from that owner after expected and
unexpected exits, and runtime socket cleanup is part of the same owner.
The session actor acquires the verified base/overlay image lease immediately
before launch and releases it only after process cleanup. If QMP disconnects or
QEMU exits unexpectedly, the supervisor submits daemon-owned cleanup; client
death cannot revoke it.

The argument renderer is role-aware. The capability is the first inherited
descriptor (guest fd 3); a networked spec must receive the TAP as the second
inherited descriptor (guest fd 4) and renders `-netdev tap,...,fd=4`. TAP and
namespace names never enter QEMU argv. Offline specs reject a TAP descriptor.
Exporter specs reject SPICE, GPU, network,
audio, and quarantine devices. They render `-nic none` and one fixed xHCI
controller but no `usb-host` argument; the exact device is added later by a
typed QMP `device_add` operation whose caller can supply only bus and address.
Scanner scan specs require `-nic none` and one
read-only quarantine disk. Workstation and downloader specs require a TAP and
cannot receive devices outside their role matrix.

For the composed workstation/downloader path, launch order is CID reservation,
capability creation, exact endpoint-scoped network allocation, private QMP and
SPICE directory creation, verified image-lease activation, typed argument
validation, QEMU start, authenticated guest handshake, guest kill-switch/VPN
configuration, guest proof, host policy proof and continuous loss monitoring.
The runtime cleanup owner reverses that ownership and audits the QEMU/network
owner, image lease, CID and private socket directories.

The exporter launch path independently owns its verified image lease, CID,
capability, private QMP directories, QEMU process, VSOCK connection and USB
attachment. Attachment ownership is recorded before `device_add`, because QMP
can apply the operation before a timeout or lost response. Cleanup clears an
ownership flag only after that step succeeds; failed steps retain their handles
for retry. Successful process termination is sufficient proof that an
ambiguous USB attachment no longer belongs to that guest. Host no-NIC arguments
alone are not accepted as guest evidence: export also requires the authenticated
exporter `InspectUSB` response to report no network.

## CPU and memory

Defaults:

| Role | vCPU | RAM |
|---|---:|---:|
| workstation (all bundles) | 2 | 4 GiB |
| downloader | 4 | 4 GiB |
| scanner | 4 | 4 GiB |
| exporter | 2 | 1 GiB |

The workstation value is configurable within the bounds in
`docs/08-config-policy.md`; the table records packaged defaults, not
recommended overrides. Downloader and scanner use closed daemon-selected
defaults. These defaults allow one role at a time to pass the non-overcommit
planner on the supported 16 GiB baseline while retaining the mandatory 4 GiB
host reserve. A larger request is never selected implicitly.

The planner leaves host reserve:

- max(4 GiB, 20% host RAM)
- no overcommit in strict mode
- no ballooning in v1
- no memory hotplug
- no swap-backed promise

## Firmware

UEFI is recommended. The daemon creates a per-session writable variable store
from a verified template if needed. It is stored in encrypted session storage
and destroyed.

## Image writes

Base images are opened read-only. Root writes go to a fresh overlay. QEMU cache
mode and discard behavior are chosen for correctness, not benchmark scores.
No internal snapshots or save-state are supported.

## Failure handling

- QMP unavailable: terminate QEMU and fail launch
- guest handshake timeout: terminate
- SPICE socket exposed incorrectly: terminate
- unexpected QEMU exit: transition to aborting
- stuck QEMU: TERM then KILL, then cleanup audit
- block device still busy: report cleanup incomplete and retry safely
