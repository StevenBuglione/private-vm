# Testing strategy

## Test layers

### Unit

- config and schema
- session transition tables
- path validation
- QEMU argument rendering
- QMP JSON parsing
- WireGuard parser
- capacity planner
- USB identity matching
- scan report parser
- policy decisions
- stream framing/hash
- redaction
- cleanup idempotency
- volatile secret zero/nil/copy safety, serialization rejection and size bounds
- daemon request-context, role, selector, resource, and typed-error validation
- bounded `/proc` stat, status, and pidfd-info parsing
- Unix peer PID/start-time/UID/group revalidation and PID-reuse rejection
- control-socket path, ownership, mode, stale-socket, and replacement-race policy
- exact Polkit action, subject, timeout, empty environment, and output redaction

### Fuzz

Targets:

- active bounded `FuzzDaemonRPCInputs` coverage for daemon request protobufs,
  context/resource validation, and `/proc` identity parsers
- TOML/JSON/protobuf adapters
- QMP parser
- OCI/image manifest
- WireGuard config
- torrent metadata translation
- archive manifest parser
- ClamAV output parser
- USB descriptors
- path normalization
- stream sequence state

### Integration without KVM

- fake QEMU executable with QMP server
- Unix gRPC daemon
- VSOCK abstraction replaced with Unix socket
- capability-authenticated guest gRPC over an in-memory listener
- missing/wrong token rejection for unary and streaming RPCs
- exact role-only service registration and wrong-role `Unimplemented`
- protocol/image/capability handshake mismatch blocking
- concurrent CID allocation, reservation, exhaustion, release and collision
- `fw_cfg` exact-length and no-symlink token reads
- VSOCK transport credentials rejecting non-VSOCK connections
- fake cryptsetup/nft/ip/usb processes
- filesystem ownership/race tests
- crash injection at every resource creation step

### Daemon authorization and RPC boundary

The active D-001 integration evidence exercises a real Unix listener and gRPC
client, kernel-bound peer credentials, supplementary-group authorization,
PID/start-time/effective-UID revalidation, session ownership, protocol mismatch
details, active-socket refusal, and mode `0660`. Socket-hardening tests cover
parent identity and write policy, symlink and non-socket rejection, valid stale
socket removal, ambiguous dial failure, identity replacement during the stale
probe, safe shutdown after endpoint replacement, the setup timeout, oversized
headers, oversized messages, daemon-wide connection admission/recovery, and a
real unauthorized Unix-gRPC call. Parser tests reject empty, missing, duplicated,
malformed, NUL-containing, oversized, vanished, and identity-changing process
evidence.

Polkit adapter tests use only a fixture executable. They assert the exact
`org.private-vm.usb.prepare` action and `PID,starttime,UID` subject, an empty
environment, bounded cancellation, rejection of relative executables and other
actions, and complete stdout/stderr suppression. `ClaimUSB` remains a
`NOT_IMPLEMENTED` stub and is not treated as a destructive Polkit boundary.

Contract tests cover `GetVersion` as the sole context-free method, the complete
unary method/context map, request/session ID and protocol validation, image and
policy selectors, resource defaulting and bounds, `TransferBegin` as the first
import frame, stream correlation and first-frame deadline, cancellation/timeout
mapping (including gRPC terminal status), canceled-create cleanup, immutable
server configuration capture, RPC sentinel redaction, and the fail-closed USB
claim stub.
Completion evidence must continue to cover role rejection, every session-error
mapping, and safe remediation on every typed error. No test may accept a race by
unlinking an unverified path.

The bounded fuzz smoke is reproducible with:

```bash
nix develop --command go test ./internal/daemon -run='^$' \
  -fuzz='^FuzzDaemonRPCInputs$' -fuzztime=2s -parallel=1
```

Each input is limited to 64 KiB. The deterministic seed corpus covers all
context-bearing daemon request shapes, resource and role validation, a
contextual transfer begin, and the stat, status, and pidfd-info parsers. Stateful
handlers are deliberately excluded. CI and the Nix `daemon-rpc-fuzz` check run
the same two-second, single-worker gate.

### Volatile-secret evidence

Linux tests verify the memfd mode, required seals, `FD_CLOEXEC`, read-only
exports, independent offset-zero descriptors, `MADV_DONTDUMP`, best-effort
`mlock` failure, fail-closed memfd failure and byte-level zeroing through a
retained read-only descriptor. A bounded helper process receives a public test
fixture as runtime input on inherited fd 3 while its live
`/proc/<pid>/cmdline` and `/proc/<pid>/environ` are inspected for absence of
that fixture. The non-secret expected fixture is necessarily embedded in the
test executable. The LUKS fake fully consumes both consecutive key descriptors,
temporarily holds and then clears the first read, and proves that their complete
values match without printing or persisting the value. Race tests serialize an
active reader against destruction. CI and the Nix source check cross-compile
the package for Darwin so Linux syscalls cannot leak into common source files.

### NixOS VM tests

Use QEMU TCG in public CI for:

- image boot
- guest role/capabilities
- XFCE/lightdm target
- no SSH
- volatile journal
- VSOCK guestd
- scanner no-network specialization
- exporter headless behavior

The checked-in common-guest boot test is run with:

```bash
nix build .#checks.x86_64-linux.guest-common
```

It injects a non-secret 32-byte test capability through an `fw_cfg` file,
boots guestd, and verifies the common hardening and identity invariants. It does
not use a production capability or any VPN credential. NixOS test
instrumentation may add its own control channel; that channel is not present in
the canonical image derivations.

The workstation desktop gate is run with:

```bash
nix build .#checks.x86_64-linux.workstation-desktop
```

It boots with explicit TCG and no test VLAN, waits for LightDM autologin and the
XFCE session, verifies both SPICE agent processes and the virtio channel,
validates the exact versioned basic-bundle manifest, installed/forbidden desktop
applications, locked Firefox policy values, and crash-reporter environment, and
repeats the no-SSH-server/sudo and no-TCP/UDP checks. The pure
`workstation-bundles` check compares all three embedded bundle manifests to the
catalog. NixOS VM instrumentation uses its own test machine and devices, so this
is an image boot gate rather than a production launch-spec proof. Host QEMU
argument tests separately prove that the only SPICE transport is the session
Unix socket and that clipboard, agent file transfer, USB redirection, and TCP
fallback are absent.

`checks.x86_64-linux.desktop-role-isolation` separately evaluates the downloader
and scanner system paths so an implicit XFCE application cannot silently leak
across role boundaries.

Scanner acceptance is split so each TCG process stays within the public-runner
and 16 GiB maintainer-host budget:

- `scanner-image-contract` checks the online/offline module contract, ClamAV
  bounds, required tool commands, forbidden cross-role commands, and exact
  package/version coverage in the embedded and exported SPDX documents.
- `scanner-update` boots only the update role, proves quarantine is absent, and
  runs FreshClam against a deterministic local `.hdb` fixture. This exercises an
  actual database installation without relying on Internet availability or a
  real credential.
- `scanner-offline` uses explicit QEMU `-nic none`, verifies zero non-loopback
  interfaces, attaches one read-only ext4 fixture, verifies the block read-only
  bit and `ro,nodev,nosuid,noexec` mount flags, then proves writing fails.

Both scanner boots verify the compiled `scanner` role and the exact advertised
common-plus-scanner capability list. They also reject SSH/sudo, credential
directories and workstation/downloader commands. Run the VM checks one at a
time; they are deliberately not a multi-node test.

### KVM acceptance

Run locally and optionally on a public documented volunteer/self-hosted runner:

- performance targets
- SPICE interaction
- host namespace egress
- VPN mock handshake
- USB passthrough with test device
- real cleanup

KVM acceptance is required before release but should be reproducible by
maintainers; do not expose secrets to public PR jobs.

## Security fixtures

- EICAR detection file
- benign false-positive simulation
- ZIP slip
- TAR absolute path
- symlink escape
- hardlink escape
- nested archive depth
- decompression bomb with bounded fixture
- encrypted archive
- polyglot/mismatched extension
- PDF JavaScript fixture
- Office macro fixture
- media attachment/metadata fixture
- executable hidden as document
- malformed QMP
- oversized protobuf frame
- slowloris stream
- USB composite descriptor fixture

## Network tests

Mock Proton endpoint:

- underlay permitted only to mock endpoint
- tunnel established
- tunnel default routes
- direct IPv4 blocked
- direct IPv6 blocked
- DNS direct blocked
- tunnel removal causes immediate failure
- qBittorrent bound interface checked
- LAN access blocked

## Cleanup fault matrix

Inject failure after each:

1. session dir
2. ciphertext file
3. LUKS format
4. mapping open
5. outer mount
6. overlay create
7. netns create
8. veth create
9. nft apply
10. TAP create
11. QEMU start
12. QMP connect
13. guest handshake
14. USB claim

Then assert zero remaining resources or a specific recoverable cleanup record.

## Acceptance tests

A release must pass all entries in `project/acceptance-tests.yaml`.

## Test safety

Tests never:

- use real Proton credentials in CI
- download public torrents
- write an unapproved physical USB on contributor machines
- modify host firewall outside unique test namespaces/tables
- require root without explicit integration-test opt-in
- print or retain fixture `pkcheck` stdout/stderr or raw `/proc` identity data
