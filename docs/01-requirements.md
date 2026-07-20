# Product requirements

## Functional requirements

### FR-001: host diagnostics

`private-vm doctor` must evaluate host compatibility without mutating the host.
It must report machine-readable status for:

- Linux architecture and kernel
- systemd and cgroups v2
- KVM availability and permission
- QEMU, QMP, SPICE, virtio-vsock, virtio-net, virtio-blk, and USB-host support
- `/dev/net/tun`, `/dev/kvm`, `/dev/vhost-vsock`, and device-mapper support
- nftables and network-namespace support
- the host-global IPv6 forwarding prerequisite used by the owned dual-stack
  namespace path (global IPv4 forwarding remains disabled)
- cryptsetup, loop devices, ext4 tooling, and sparse-file support
- remote-viewer availability
- USBGuard status
- host root encryption evidence
- swap and hibernation risk
- `/run` being volatile
- available RAM and encrypted-session disk capacity
- orphaned private-vm resources
- installation/package consistency

### FR-002: immutable image management

The CLI must pull, verify, cache, inspect, and prune role-specific images. It
must refuse an image when any of the following fails:

- digest
- repository identity
- release workflow identity
- role
- architecture
- guest protocol version
- minimum host/QEMU requirements
- build manifest schema
- provenance
- strict-mode SBOM requirement

### FR-003: disposable desktop

The user can start, reconnect to, inspect, and stop an XFCE workstation. The
desktop must use a session Unix SPICE socket and an authenticated VSOCK agent.

### FR-004: Proton-only networking

The workstation and downloader must not reach the public network except through
the configured Proton WireGuard tunnel. VPN failure must fail closed.

### FR-005: explicit file import

The host can stream an explicitly named trusted file into `~/Inbox`. The guest
cannot enumerate host paths. Directories are not supported in v1.

### FR-006: protected work export

The workstation reports `CLEAN`, `READY`, `UNEXPORTED`, `CHANGED`, or
`UNREACHABLE`. Normal stop is blocked for unexported or changed output.

### FR-007: torrent metadata planning

The downloader receives a magnet or `.torrent` through a secure input path,
fetches metadata while paused, and returns file selection and capacity planning
before downloading payload bytes.

### FR-008: quarantine

Torrent payload is written to a session-owned encrypted block image. It is
writable only in downloader and read-only in scanner.

### FR-009: scanner update separation

The scanner can update signatures only when no quarantine disk is attached.
The actual scan runs with no network interface.

### FR-010: malware and policy report

Every requested input produces a report containing:

- source hash and byte count
- detected content type
- extension/type agreement
- ClamAV engine and database versions
- definitions timestamp
- scan duration
- all detection results
- skipped/limit/error results
- archive manifest
- reconstruction steps
- output hashes
- final policy verdict

### FR-011: sanitized promotion

Under `safe` policy, only reconstructed supported content may enter the
workstation or normal export path.

### FR-012: USB enrollment and export

The user can inspect and enroll a dedicated USB. The exporter must receive only
the exact enrolled device and no network interface.

### FR-013: crash-safe cleanup

Cleanup must occur after:

- user stop
- user abort
- CLI interruption
- daemon restart
- QEMU exit
- guest shutdown
- timeout
- failed preflight after partial allocation
- host reboot

### FR-014: installation

The project provides:

- NixOS module
- Nix flake package/app
- DEB
- RPM
- generic Linux tarball
- shell completions
- systemd service
- Polkit policy where needed
- tmpfiles and udev/USBGuard integration

## Security requirements

### SR-001: fail closed

Unknown or incomplete security state is a failure, not a warning, for:

- image identity
- role identity
- VPN enforcement
- scanner isolation
- read-only quarantine
- USB identity
- scan completion
- output integrity
- cleanup completion

### SR-002: least privilege

The CLI is unprivileged. The daemon exposes narrow RPCs. Guest services expose
only role-specific methods.

### SR-003: no host mounts of hostile media

The host must not mount:

- guest root filesystem
- quarantine filesystem
- scanner output filesystem
- transfer USB filesystem

The only host mount is the empty outer LUKS session container that stores opaque
QEMU disk files.

### SR-004: no network listeners

The system must not create externally reachable TCP/UDP listeners. SPICE, QMP,
and daemon RPC use Unix sockets; guest RPC uses VSOCK.

### SR-005: secret handling

Secrets must not be placed in:

- argv
- environment variables
- config files
- OCI artifacts
- Nix store
- generated cloud-init images
- journald
- crash dumps
- persistent reports

### SR-006: bounded parsing

All RPC frames, streams, manifests, archive operations, scan operations, and
external command output must have size and time bounds.

### SR-007: no shell interpolation

Go must execute binaries with argument arrays. Never invoke `/bin/sh -c` with
user-controlled values.

### SR-008: supply-chain identity

The official CLI accepts only artifacts built from the official repository and
approved workflow unless the user explicitly configures a custom trust root.

### SR-009: reproducibility evidence

A release includes enough metadata to rebuild and compare source, dependency,
flake, image, and packaging inputs.

### SR-010: user-visible truth

The UI must distinguish:

- VPN connected from VPN verified
- scan clean from file safe
- session deleted from physical media overwritten
- private session from anonymous activity

## Performance requirements

- Basic workstation boot-to-viewer target: under 30 seconds with KVM.
- Guest agent readiness target: under 20 seconds.
- CLI status update latency: under one second.
- VPN-loss block target: under one second at guest firewall; host policy is
  continuously enforced.
- Import/export streaming: bounded memory, default 1 MiB chunks.
- No whole-file buffering in CLI or daemon.
- Cleanup target: under 15 seconds after QEMU exit, excluding a stuck kernel
  device timeout.
- TCG CI smoke boot target: under five minutes per image.

## Compatibility requirements

v1 runtime:

- x86_64 Linux
- Linux kernel 6.6 or newer
- KVM
- systemd
- cgroups v2
- nftables
- QEMU 9.2 or newer with SPICE and VSOCK
- NixOS 26.05 primary host
- Fedora, Ubuntu, and Debian package targets

## Documentation requirements

Every public release must include:

- architecture
- threat model
- security boundary
- CLI reference
- configuration reference
- image manifest format
- scanner policy behavior
- installation
- upgrade
- incident response
- recovery/cleanup
- limitations
- reproducibility instructions
