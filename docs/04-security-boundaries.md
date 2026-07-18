# Security boundaries and invariants

## Boundary B1: host to guest display

Allowed:

- SPICE Unix socket
- display, keyboard, mouse
- automatic resolution through vdagent

Forbidden:

- TCP SPICE
- clipboard
- file transfer
- USB redirection
- audio unless explicitly enabled
- arbitrary SPICE channels

Invariant:

> A workstation can display pixels and receive input, but cannot transfer files
> or clipboard data through SPICE.

## Boundary B2: host control to guest

Allowed:

- authenticated gRPC over a unique VSOCK CID
- role-specific methods
- bounded streams

Forbidden:

- guest TCP services
- SSH
- generic command execution
- host path exposure

Invariant:

> The guest sees only values explicitly streamed through a typed, bounded API.

## Boundary B3: guest networking

Allowed:

- underlay UDP to one resolved Proton endpoint
- tunnel traffic through `proton0`

Forbidden:

- direct public IPv4/IPv6
- host LAN access
- multicast discovery
- inbound port forwarding by default
- UPnP/NAT-PMP by default

Invariant:

> Removing the WireGuard interface removes usable application egress.

## Boundary B4: downloader to scanner

Allowed:

- one quarantine block image
- downloader writable
- scanner read-only

Forbidden:

- simultaneous attachment
- host filesystem mount
- workstation attachment
- exporter attachment

Invariant:

> Hostile downloaded bytes cross roles only as an opaque block device.

## Boundary B5: scanner output

Allowed:

- report metadata
- approved bounded byte stream
- hash and reconstruction record

Forbidden:

- original safe-policy hostile content
- shared output filesystem
- direct USB
- network during scan

Invariant:

> Only a completed policy-approved output stream can leave scanner.

## Boundary B6: USB

Allowed:

- one enrolled mass-storage-only device
- exporter VM
- explicit format/mount/write/verify/unmount lifecycle

Forbidden:

- downloader/scanner/workstation passthrough
- host mount
- unexpected composite interfaces
- unidentified device

Invariant:

> The USB has one owner: the exporter guest.

## Boundary B7: persistent storage

Allowed:

- verified immutable base images
- public manifests/SBOMs
- explicit user exports
- coarse daemon lifecycle logs

Forbidden:

- plaintext session overlay
- VPN profile
- magnet link
- torrent metadata
- file names in persistent reports
- scanner output cache

Invariant:

> Writable session material is encrypted with a session-only key or stored in
> tmpfs.

## Hard invariants checked in code

1. `scanner.scan_mode == offline`
2. `scanner.quarantine_access == read_only`
3. `exporter.network_devices == 0`
4. `exporter.usb_devices == 1`
5. `workstation.shared_filesystems == 0`
6. `downloader.qbittorrent_interface == "proton0"`
7. `qemu.spice.transport == unix`
8. `qemu.qmp.transport == unix`
9. `guest.rpc.transport == vsock`
10. `session.key_persistent == false`
11. `base_image.read_only == true`
12. `host.mounts_guest_fs == false`
13. `scan.report.complete == true` before approval
14. `workspace.state in {CLEAN, READY}` before normal stop
15. `image.provenance.verified == true` before QEMU launch

These invariants should be represented as explicit validation functions and
negative tests, not assumptions embedded in command assembly.
