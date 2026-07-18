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

- absolute executable path
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
QMP `system_powerdown` followed by bounded TERM/KILL escalation. One goroutine
owns `Wait`; cgroup and pidfd cleanup run from that owner after expected and
unexpected exits.

The argument renderer is role-aware. Exporter specs reject SPICE, GPU, network,
audio, and quarantine devices. Scanner scan specs require `-nic none` and one
read-only quarantine disk. Workstation and downloader specs require a TAP and
cannot receive devices outside their role matrix.

## CPU and memory

Defaults:

| Role | vCPU | RAM |
|---|---:|---:|
| workstation-basic | 4 | 8 GiB |
| workstation-development | 8 | 16 GiB |
| downloader | 4 | 6 GiB |
| scanner | 6 | 12 GiB |
| exporter | 2 | 1 GiB |

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
