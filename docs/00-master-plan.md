# Complete implementation plan

## 1. Product definition

`private-vm` is a Linux-native security and privacy orchestration tool. It runs
disposable graphical virtual machines for private work and provides a strict
workflow for downloading content through a torrent, scanning and sanitizing it,
and exporting only approved output to an enrolled USB device or a new disposable
workstation.

The trusted host is Linux. NixOS 26.05 is the primary host integration, but
Fedora, Ubuntu, and Debian packages are part of the release plan. Guest images are
always NixOS so that the same declarative image is used on every supported host.

The product is not an anonymity system and is not a guarantee that no trace can
exist anywhere. Its concrete promise is narrower:

> `private-vm` creates no intentional persistent plaintext session state and
> destroys session keys, guest overlays, transient configuration, and runtime
> metadata at teardown. Persistent output exists only through an explicit export.

## 2. Goals

1. Provide a real XFCE graphical desktop suitable for browsing, office work, and
   development.
2. Route workstation and downloader network traffic only through a user-supplied
   Proton WireGuard profile.
3. Prevent direct network fallback with both host-side and guest-side policy.
4. Build every guest image reproducibly from public Nix definitions.
5. Publish images and binaries from a public GitHub repository using free
   standard public runners where resource limits permit.
6. Verify image digest, role, architecture, protocol, SBOM, and build provenance
   before launch.
7. Keep the downloader, scanner, workstation, and USB exporter in separate trust
   compartments.
8. Perform malware scanning and content-disarm/reconstruction inside a disposable
   offline scanner.
9. Never mount untrusted guest filesystems or the transfer USB on the host.
10. Automatically clean up after success, failure, cancellation, process death,
    daemon restart, and host reboot.
11. Provide a Go CLI that checks every prerequisite before mutating the system.
12. Provide NixOS, Debian/Ubuntu, Fedora/RHEL, and generic Linux installation
    formats.
13. Make the repository usable by another engineer without architectural research.

## 3. Non-goals

- Protecting a guest from a malicious or already compromised host.
- Defeating firmware, hypervisor, CPU, DMA, or physical attacks.
- Hiding activity from accounts the user signs into.
- Preventing remote services, peers, trackers, VPN providers, or ISPs from
  retaining their own records.
- Proving a file is safe because antivirus found no signature.
- Running unknown executables on the trusted host.
- Supporting Windows or macOS hosts in v1.
- Supporting arbitrary VPN providers in v1.
- Supporting arbitrary guest operating systems in v1.
- Live migration, save-state, snapshots, hibernation, or session recovery after
  host reboot.
- Raw export of hostile content in the default policy.

## 4. Final architectural decisions

| Area | Decision |
|---|---|
| Project | `StevenBuglione/private-vm` |
| License | Apache-2.0 recommendation |
| Language | Go 1.26 |
| Guest baseline | NixOS 26.05 |
| Desktop | XFCE + LightDM |
| Image build | NixOS image modules / `nixos-rebuild build-image` |
| Packer | Optional acceptance wrapper, not provisioning source |
| Hypervisor | Direct QEMU/KVM launched by `private-vmd` |
| Display | SPICE Unix socket + `remote-viewer` |
| Host RPC | gRPC over `/run/private-vm/control.sock` |
| Guest RPC | gRPC over AF_VSOCK |
| VM control | QMP Unix socket |
| Network | TAP in dedicated network namespace |
| VPN | Proton WireGuard config streamed at runtime |
| Egress control | Host nftables allowlist + guest nftables kill switch |
| Image registry | Public GHCR OCI artifacts |
| OCI client | `oras-go` embedded in CLI |
| Provenance | GitHub artifact attestations + Sigstore verification |
| Root/session storage | tmpfs for small sessions or per-session LUKS container |
| Torrent storage | encrypted per-session quarantine disk |
| Scanner | ClamAV plus type-specific reconstruction |
| USB | enrolled dedicated device, exporter VM only |
| Persistent logs | disabled by default |
| Telemetry | none |
| Shell logic | prohibited for product security/orchestration |

## 5. Four guest roles

### 5.1 Workstation

A disposable XFCE desktop used for normal work.

- Proton-only networking
- trusted explicit host imports
- sanitized scanner output imports
- no quarantine disk
- no direct USB
- no shared host directories
- output only through `~/Export`
- stop protection when output is unexported or changed

### 5.2 Downloader

A disposable XFCE desktop containing qBittorrent.

- Proton-only networking
- no personal accounts or credentials
- magnet input received from the host CLI over authenticated VSOCK
- metadata-only planning before payload download
- encrypted quarantine disk is the only data output
- cannot access the workstation or export USB

### 5.3 Scanner

A disposable XFCE inspection desktop.

- first boot may update ClamAV with no quarantine attached
- scan boot has no NIC at all
- quarantine attached read-only with `nodev,nosuid,noexec`
- scans, extracts, identifies, and reconstructs supported content
- rejects incomplete scans, skipped files, limit hits, encrypted archives, and
  policy violations
- streams approved output; never sees the USB

### 5.4 Exporter

A minimal headless guest.

- no network device
- no quarantine device
- receives one bounded approved stream
- receives exactly one enrolled USB device
- formats or mounts the USB according to explicit policy
- computes and returns post-write hashes
- powers off immediately

## 6. Primary user journeys

### 6.1 Private graphical work

```text
doctor → verify image → create encrypted session → create netns
→ boot workstation → establish Proton → leak tests → open SPICE viewer
→ work → explicit export → verify export → destroy VM and keys
```

### 6.2 Torrent to sanitized workstation file

```text
doctor → update scanner overlay without quarantine
→ boot downloader → Proton handshake and leak tests
→ add magnet metadata-only → show exact files and capacity plan
→ user selects files → download to encrypted quarantine
→ destroy downloader → boot scanner offline with quarantine read-only
→ scan and reconstruct → approve → destroy scanner
→ boot fresh workstation → stream sanitized output to ~/Inbox
→ user works → export → destroy everything
```

### 6.3 Torrent to USB

```text
download and scan as above
→ enroll/verify dedicated USB
→ boot exporter with no NIC and exact USB passthrough
→ stream approved output → flush → reread/hash → unmount
→ destroy exporter and session keys
```

## 7. Security boundary

The host operating system, kernel, QEMU binary, `private-vmd`, and CPU are trusted.
Guest applications, torrent peers, downloaded bytes, documents, archives, and
the USB contents are untrusted.

The user must understand that a compromised host can observe guest display,
memory, keyboard input, and secrets. This project protects the host and separate
guest roles from ordinary hostile guest content; it does not protect against a
host compromise.

## 8. Process model

### `private-vm`

Unprivileged user-facing CLI. It parses user intent, renders plans and reports,
streams explicitly selected input, and calls the daemon. It never manipulates
network namespaces, device mapper, USB, TAP, QEMU, or mounts.

### `private-vmd`

Root system service. It owns all privileged lifecycle operations and validates
every request against peer identity, configuration, session state, and policy.

### `private-vm-guestd`

Root service inside each guest. It advertises a compile-time role and capability
set, authenticates the session token, and exposes only role-appropriate RPCs.

## 9. Communication

- CLI ↔ daemon: gRPC on a Unix socket, mode `0660`, group `private-vm`.
- Daemon ↔ guest: gRPC over AF_VSOCK.
- QEMU control: QMP on a per-session Unix socket.
- Display: SPICE on a per-session Unix socket.
- File transfer: bounded gRPC client/server streams with independent SHA-256.
- Secrets: streamed after authenticated guest handshake; never command-line args.

Each guest receives a unique VSOCK CID. The daemon generates a 256-bit session
token and injects it through QEMU `fw_cfg` using an inherited file descriptor.
The guest reads it from sysfs. Every guest RPC requires that token in metadata.
The verified image role and the runtime-requested role must match.

## 10. Session storage

Persistent base images are read-only and verified. Everything writable is inside
one per-session storage domain:

- small mode: tmpfs-backed sparse files
- large mode: sparse LUKS2 container on disk with random key held only in volatile
  process memory / memfd

The opened LUKS mapping contains an ext4 filesystem mounted by the daemon only as
an outer container for opaque QEMU image files. The host never mounts a guest
filesystem. It stores root overlays, quarantine block images, and temporary
export relay metadata as opaque bytes.

At teardown the daemon:

1. stops all VMs
2. waits for QEMU exit
3. closes QMP/SPICE/VSOCK listeners
4. unmounts the outer encrypted session filesystem
5. closes the device-mapper mapping
6. destroys the only key material
7. deletes the ciphertext sparse file
8. removes `/run/private-vm/<session-id>`
9. verifies that no process, mapping, mount, TAP, namespace, or USB claim remains

Cryptographic erasure, not SSD overwriting, is the security mechanism.

## 11. Networking

The daemon resolves the Proton endpoint before launch and replaces a hostname
with a validated IP address in the ephemeral guest configuration.

For every networked guest it creates:

- a dedicated Linux network namespace
- a TAP interface used only by that QEMU process
- a veth uplink to the host
- static addressing; no general host DNS or DHCP service
- nftables policy that permits the guest underlay only to the Proton endpoint IP
  and UDP port
- no inbound host port forwards

Inside the guest:

- `eth0` may contact only the Proton endpoint
- `proton0` carries default IPv4 and IPv6 routes
- normal applications can egress only through `proton0`
- DNS is reachable only through the tunnel
- qBittorrent is bound specifically to `proton0`
- loss of WireGuard handshake blocks traffic rather than changing routes

The CLI runs active leak tests before marking the desktop online.

## 12. Desktop

Workstation, downloader, and scanner images use XFCE. The workstation image
provides:

- Firefox
- VSCodium
- LibreOffice
- terminal
- Thunar
- PDF/image viewers
- archive manager
- Git and OpenSSH client
- KeePassXC
- optional development toolchain bundle

No guest has SSH server, reusable password, sudo access, clipboard sharing,
SPICE file transfer, drag-and-drop, shared folders, agent forwarding, webcam,
microphone, arbitrary USB, or GPU passthrough in v1.

SPICE uses a `0600` Unix socket and QEMU flags that disable copy/paste and
agent file transfer. Audio is disabled by default and is an explicit option.

## 13. Torrent planning

A magnet link is accepted through a non-echoing prompt or stdin, not normal argv.

The downloader must:

1. establish and test Proton
2. add the torrent paused
3. fetch metadata only
4. report exact files, sizes, path hazards, file types inferred from names, and
   projected storage
5. wait for explicit file selection
6. recalculate quarantine, extraction, scan, reconstruction, and destination
   capacity
7. start payload download only after all hard checks pass

No automatic opening, preview, thumbnailing, media probing, or execution occurs
in the downloader.

## 14. Scanning and reconstruction

ClamAV is one layer, not a proof of safety. The scan phase also:

- identifies MIME/type from content, not extension
- hashes every file
- rejects FIFOs, device nodes, sockets, hard links, path traversal, and unsafe
  symbolic links
- extracts archives as an unprivileged user into a bounded tmpfs
- enforces depth, file-count, per-file, total-expanded-size, and timeout limits
- rejects password-protected or otherwise uninspectable content
- records every ClamAV limit and skipped file as a failure

Safe-policy reconstruction:

- PDF: rasterize every page and rebuild a new PDF
- Office: render to PDF inside the scanner, then rasterize/rebuild
- images: decode, strip metadata, and re-encode
- audio/video: fully decode and re-encode with metadata and chapters removed
- archives: export only individually approved reconstructed members
- executable/script/package/ISO/VM image: never promote to workstation or normal
  USB under safe policy

Dangerzone may be added as an optional backend, but the baseline implementation
must not depend on it.

## 15. Export

Scanner and workstation output reaches the exporter through a host memory relay.
The daemon does not interpret content. It enforces declared size, one stream at a
time, per-chunk limits, cumulative limits, timeout, and SHA-256.

The exporter accepts only a USB matching an enrolled identity record:

- vendor ID
- product ID
- serial when available
- USBGuard hash
- allowed physical port when serial is absent
- interface set exactly mass-storage only

Default USB format is LUKS2 + ext4. An optional compatibility format may be added
later but must be labeled as weaker and must not become the default.

## 16. Public build and release

The public repository uses standard GitHub-hosted Linux runners. Public standard
jobs are currently free and unlimited, but the standard Linux VM has four CPUs,
16 GB RAM, and 14 GB SSD. Each image is built in a separate job with a strict
disk budget.

The canonical image is produced by NixOS 26.05 image configuration. Packer can
boot an already-built image for optional acceptance testing; it does not install
or provision the OS.

Artifacts:

- Go binaries and packages in GitHub Releases
- NixOS QCOW2 images as zstd-compressed OCI artifacts in public GHCR
- SPDX SBOM for each binary and image
- image manifest with source commit and protocol metadata
- GitHub artifact attestation for every release artifact

Pulling a public GHCR image is anonymous. Publishing occurs only from protected
release workflows with minimal permissions.

## 17. Installation

### NixOS

A flake module installs binaries, host dependencies, group, systemd service,
socket permissions, tmpfiles rules, USBGuard integration, and configuration.

### Fedora / RHEL

An RPM declares QEMU, virt-viewer, cryptsetup, nftables, iproute, USBGuard,
Polkit, util-linux, and filesystem-tool dependencies.

### Ubuntu / Debian

A DEB declares equivalent dependencies.

### Generic Linux

A tarball contains binaries, unit files, policies, completions, and an install
manifest. `private-vm system install --dry-run` displays all mutations. Actual
installation requires root and explicit confirmation.

## 18. CLI principles

Every mutating workflow automatically performs preflight and planning. A user
cannot accidentally skip security checks by choosing a lower-level command.

Commands support:

- human output
- `--json`
- stable error codes
- noninteractive `--require-*` modes
- cancellation
- progress events
- dry-run plans
- explicit destructive confirmation

The complete command reference is in `docs/07-cli-reference.md`.

## 19. Logging

Default:

- no telemetry
- no persistent QEMU logs
- no persistent session report
- no magnet, torrent, file, or VPN secret in logs
- daemon records only coarse lifecycle events in journald
- session detail remains under `/run` unless explicitly exported
- core dumps disabled
- no VM save-state
- no hibernation support

## 20. Release gates

v1 is not complete until all of the following are demonstrated:

- verified image cannot be modified without launch failure
- direct egress fails while Proton is absent
- VPN loss stops torrent and workstation traffic
- scanner has no NIC when quarantine is attached
- quarantine is read-only in scanner
- USB is visible only to exporter
- host never mounts guest, quarantine, or USB filesystems
- dirty workstation cannot be normally destroyed
- CLI, daemon, QEMU, and host-reboot failures all leave no active session
- orphan ciphertext is unusable and removed on next boot
- malicious archive corpus cannot escape extraction root
- scan-limit and skipped-file conditions reject output
- SPICE clipboard and file transfer are demonstrably disabled
- all published artifacts verify against expected repository/workflow identity

## 21. Delivery plan

Implementation is divided into eight phases:

0. repository, contracts, and CI
1. host doctor/configuration
2. daemon and lifecycle
3. image factory and guest handshake
4. graphical workstation
5. VPN and network enforcement
6. downloader and quarantine
7. scanner and exporter
8. packaging, hardening, reproducibility, and v1 release

Detailed tasks and exit criteria are in `docs/25-implementation-roadmap.md` and
`project/backlog.yaml`.

## 22. Known limitations

- The trusted host can observe everything in a guest.
- Deleting encrypted ciphertext is not the same as proving physical flash cells
  were overwritten.
- Go cannot guarantee every historical copy of a secret was zeroed.
- Antivirus can miss malware and produce false positives.
- File reconstruction itself invokes complex parsers, which is why it runs in a
  disposable offline scanner.
- A USB controller or device firmware attack is not fully eliminated by VM
  passthrough or USBGuard.
- Torrent and VPN providers can maintain records outside this system.
- Signing in to an account identifies the user to that service.
- Free GitHub runner resource limits may require splitting the largest image
  build into multiple verified OCI stages.
