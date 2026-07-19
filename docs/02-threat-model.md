# Threat model

## Assets

1. Host files, credentials, browser state, keys, and development repositories.
2. Workstation session documents and credentials.
3. User identity and network address.
4. Proton WireGuard private key.
5. Torrent selection and downloaded content.
6. Scan verdict and reconstructed output.
7. Dedicated USB contents.
8. Official release signing/provenance identity.
9. Integrity of base images and daemon binaries.
10. Ephemeral session encryption keys.

## Trusted computing base

- physical CPU and memory
- host firmware and boot chain
- host Linux kernel
- host root filesystem and package manager
- `private-vmd`
- QEMU/KVM and required host utilities
- verified official base images
- official GitHub repository/workflow identity
- user operating the trusted host

The workstation guest is trusted for the user's own work but is still isolated
and disposable. The downloader and scanner are explicitly untrusted after they
process hostile input. The exporter is narrowly trusted to write bytes.

## Adversaries

### A1: malicious torrent peer or tracker

Capabilities:

- supplies malformed protocol data
- observes the torrent peer IP presented by Proton
- attempts denial of service
- influences metadata and filenames

Mitigations:

- qBittorrent is isolated in downloader
- no credentials or work data in downloader
- host and guest egress controls
- metadata-first planning
- bounded RPC and filename validation
- disposable teardown

### A2: malicious downloaded file

Capabilities:

- exploits previewers, parsers, archive tools, media decoders, office suites,
  antivirus engines, or user mistakes
- contains path traversal, symlinks, device nodes, decompression bombs, scripts,
  macros, active PDF content, misleading extensions, or polyglots

Mitigations:

- no opening in downloader
- scanner offline
- quarantine read-only
- unprivileged extraction
- resource and path limits
- noexec/nodev/nosuid
- reconstruction before promotion
- fresh workstation is unadvertised and not connected to a viewer until the
  authenticated one-way relay completes and the scanner is destroyed
- executable promotion blocked

### A3: malicious USB device

Capabilities:

- claims multiple USB interfaces
- emulates keyboard or network adapter
- changes identity after enumeration
- contains malformed filesystem metadata
- attempts controller or driver exploitation

Mitigations:

- dedicated device only
- USBGuard exact interface-set rule
- VID/PID/serial/hash/port enrollment
- host automount disabled
- exporter-only passthrough
- no network or hostile quarantine in exporter
- host does not mount filesystem

Residual risk: host USB stack and controller firmware still enumerate the device.

### A4: compromised guest application

Capabilities:

- obtains guest-user data
- attempts host escape
- attempts direct egress
- attacks guest agent or virtual devices
- tampers with scan output

Mitigations:

- role isolation
- minimal devices
- no shared folders/clipboard
- VSOCK authenticated session
- host firewall independent of guest
- read-only inputs
- independent host-relay hash
- short session life
- current QEMU/kernel updates

Residual risk: a hypervisor escape is in scope as a high-impact dependency risk,
not something the application can eliminate.

### A5: malicious or compromised release artifact

Capabilities:

- substitutes image
- changes role behavior
- includes backdoor
- exploits updater

Mitigations:

- digest pinning
- provenance verification
- official repository and workflow identity
- SBOM
- protected release environment
- immutable tags by policy
- transparent public build definitions
- optional local reproducible rebuild

### A6: local unprivileged host user

Capabilities:

- connects to daemon socket
- observes process list
- races session paths
- attempts to attach to SPICE/QMP sockets
- attempts to read runtime state

Mitigations:

- `private-vm` group
- peer-credential checks
- per-session ownership and `0700` directories
- `0600` QMP/SPICE sockets
- no secrets in argv/env
- unpredictable session IDs
- daemon-created runtime/session paths never follow symlinks; the sole
  daemon-side exception permits an ordinary NixOS `/etc` configuration link only after the
  opened target is proven root-owned, non-writable and on an allowlisted local
  filesystem (magic links remain forbidden)

### A7: compromised host

Capabilities:

- observes all guest memory, display, keyboard, VSOCK, and storage
- copies keys
- changes QEMU
- bypasses every cleanup promise

Status: out of scope. The documentation must state this prominently.

### A8: remote service identification

Capabilities:

- identifies account login
- retains server logs, cookies, fingerprints, document uploads, or messages

Mitigations:

- disposable browser state
- VPN transport
- private browsing defaults
- user education

Status: not anonymity. Remote service records remain outside project control.

### A9: power loss or host crash

Capabilities:

- interrupts cleanup
- leaves ciphertext container and QEMU metadata
- leaves USB write incomplete

Mitigations:

- session key only in volatile memory
- startup orphan cleanup
- exporter write journal and final verification
- no automatic resume
- explicit incomplete-export verdict

## Attack surfaces

- CLI argument and config parsing
- Unix socket RPC
- VSOCK RPC
- protobuf decoding
- QMP JSON
- QEMU command construction
- image manifest and OCI registry
- GitHub attestation verification
- network namespace/nftables setup
- WireGuard configuration parser
- qBittorrent Web API
- archive listing/extraction
- ClamAV output/protocol
- document/media reconstruction tools
- USB enumeration and passthrough
- system installation and upgrades

Every attack surface requires fuzzing or adversarial tests where practical.

## Privacy analysis

The system reduces local plaintext persistence. It does not guarantee:

- no filesystem metadata
- no SSD remanence
- no kernel trace
- no firmware trace
- no network-provider record
- no remote-service record
- no screen capture
- no host process accounting

The approved product wording is:

> No intentional persistent plaintext session state is retained by private-vm.
> Session ciphertext is cryptographically abandoned at teardown. Explicitly
> exported files, host-level system logs, remote-service records, and activity
> outside private-vm remain outside this guarantee.

## Abuse considerations

The project is a general-purpose privacy and malware-isolation tool. It must not
include features whose purpose is evading law enforcement, bypassing access
controls, concealing illegal activity, or distributing malicious content.
Documentation should remind users to download and share only content they are
authorized to access.
