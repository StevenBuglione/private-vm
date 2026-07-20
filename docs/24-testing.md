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
- sysfs USB/block association, USBGuard record parsing, serial-or-explicit-port
  enrollment, duplicate-device ambiguity, host root/boot exclusion and
  mode-`0600` enrollment round trips
- claim collision, cancellation rollback, absence audit, release retry, stale
  preparation challenges, two exact confirmation steps, final identity
  revalidation, Polkit-before-commit ordering and incomplete prepare evidence
- exporter-only daemon claim admission, mismatched-enrollment rejection,
  serialized workflow ownership, partial-acquisition cleanup and idempotent
  explicit-release/session-cleanup absence audit
- one-way chunk sequencing and bounds, authenticated safe-policy eligibility,
  scanner/relay/exporter/reread hash equality, source-close failure, timeout,
  fsync/rename evidence, networkless role boundaries and retryable reverse-order
  export cleanup without serializing filenames or hashes
- authenticated exporter-only prepare/write/verify/finalize RPC composition,
  first-frame and passphrase bounds, fixed identity expectation, receive/reread
  equality, fsync/rename/unmount/LUKS-close evidence, timeout cleanup and generic
  exporter composition that fails closed without its fixed-path adapter
- daemon session/claim-bound USB plan, secret-stream preparation and approved
  scanner-to-exporter bridge, including complete workflow-state evidence
- production exporter no-NIC/xHCI argument shape, fixed typed QMP hotplug,
  guest `InspectUSB` no-network evidence, ambiguous attach ownership, per-step
  cleanup-handle retention, failed first cleanup and successful retry
- one-use role/session/output source selection for authenticated scanner
  reconstruction and workstation Export without a host path
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
- OCI tag-to-digest ordering, descriptor hashing, bounded zstd extraction and
  immutable cache records

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

### OCI pull and cache boundary

`internal/image` uses an in-memory read-only registry fake to prove that tag
resolution is the first remote operation, the final directory is the resolved
manifest digest, cache hits never fetch tag-selected layers, and all four
component descriptors are independently hashed. Adversarial cases cover
digest substitution before decoder construction; every forbidden manifest,
config and layer optional field; the exact `{}` config media type, size, digest
and fetched bytes; required fixed titles; extra annotations; unsafe or absolute
titles; duplicate and unknown media types; compressed and installed size limits;
stream-close failure; verifier
failure, cancellation, timeout, read-only modes, cache tampering and cleanup of
every hidden `.partial-*` directory.

The ORAS adapter test proves HTTPS-only, bounded and anonymous construction.
After an official public image exists, maintainers can run the opt-in anonymous
registry acceptance without embedding credentials:

```bash
PRIVATE_VM_TEST_PUBLIC_OCI_REFERENCE='ghcr.io/stevenbuglione/private-vm/workstation-basic:rc' \
  go test ./internal/image -run '^TestORASAnonymousResolve$'
```

The opt-in test resolves only. Complete installation remains blocked until the
IMG-002/IMG-003 verifier accepts the staged manifest, SBOM and provenance.

IMG-002 tests construct only local staged fixtures. They prove exact
role/bundle/architecture mapping, guest API minor policy, QEMU policy, sorted
capabilities, source/lock/NixOS fields, compressed and installed cache bindings,
SBOM layer binding, cancellation, timeout and hard byte/count limits. Manifest
and SPDX decoders reject unknown, duplicate, trailing, missing and null fields,
including nested package/file/checksum/relationship fields. The SPDX cases also
cover duplicate or unsorted store paths, store-hash-derived IDs, exact store
names, image/file checksum mismatch, incomplete closure packages and noncanonical
relationship graphs. The package-private IMG-003 seam is used only by focused
unit tests; the exported official constructor always installs the embedded-root
verifier.

IMG-003 tests use a local virtual Fulcio/Rekor/TSA deployment and no network.
They prove a valid cryptographic DSSE bundle; exact repository/workflow/tag,
numeric repository/owner IDs and invocation binding; wrong SAN/issuer/digest;
untrusted and expired certificate material; malformed, duplicate, unknown,
missing-proof and oversized inputs; cancellation, timeout and repeated offline
cache reverification. Schema tests also reject mutable refs and repository-name
reuse with a changed numeric ID.

### OCI release producer and publication boundary

REL-003 focused tests run serially and without Nix or a VM. They directly cover:

- bounded regular-file discovery, QCOW2 v3 header/virtual-size validation,
  deterministic single-worker zstd output and source/compressed hashes;
- symlink, duplicate-image, backing-file, encryption, malformed-header,
  incomplete-closure, cancellation and timeout rejection before publication;
- exact empty OCI config and ordered four-layer descriptor bytes;
- credential read only from bounded standard input with no cache, Docker store,
  argv, environment or diagnostic copy;
- duplicate-tag rejection before blob writes, a second pre-tag absence check,
  conditional non-overwrite tag creation and post-write digest resolution;
- injected failure after every blob/manifest operation, proving that a partial
  push cannot create the tag and that local staging is removed; and
- anonymous construction with no credential followed by digest-pinned pull;
  the IMG-002/IMG-003 tests in the same package independently exercise the
  complete `NewOfficialVerifier` manifest/SPDX/cryptographic policy.

The same production selector additionally rejects missing images, special
files, path/count/depth/size overflow and unsupported QCOW2 feature bits. Those
bounds are enforced in Go even where the focused REL-003 suite uses a
representative rejection rather than duplicating every selector mutation.

Schema tests validate the release receipt and reject unknown fields, branch or
arbitrary refs, non-official repositories/workflows, a mismatched role/bundle,
missing/fifth/reordered file names, invalid digests, and any secret/path-shaped
field. OCI graph tests independently reject a changed component media type.

The local source gate is:

```bash
CGO_ENABLED=0 GOMAXPROCS=2 GOMEMLIMIT=3GiB \
  go test -p=1 ./internal/image ./cmd/private-vm-image-release
python3 tools/validate_schemas.py
python3 tools/validate_examples.py
python3 tools/test_workflow_policy.py
python3 tools/check_workflow_policy.py
```

These checks are sufficient to continue local implementation without waiting
for GitHub's image build. They do not prove server-side environment protection,
an actual OIDC attestation, GHCR visibility or anonymous reachability. Those
remote-only conclusions require all six protected publication rows and all six
fresh anonymous-verification rows to succeed for the same protected Git tag and
commit. Pending, skipped, cancelled and failed rows are not acceptance evidence.

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

The scanner host integration uses the real Unix daemon transport with a typed
fake runtime. It proves a sealed downloader creates a distinct scanner session,
the update/no-quarantine and offline/no-NIC/read-only gates occur in order,
authenticated guest progress is projected to bounded aggregate events, report
data is redacted, promotion precedes approval, rejection never promotes, and
resources clean in offline-runtime → update-runtime → storage order. Injected
operation failure, cancellation, timeout and cleanup-audit failure prove either
`DESTROYED` convergence or an explicit retryable `DESTROYING` record.

The production scanner-runtime unit gate additionally proves the sealed
quarantine lease blocks downloader storage cleanup, the same scanner root
storage is reused across both boots, the update boot completes the full typed
VPN and host-egress sequence before its scanner client is available, and QEMU
renders update as NIC/no-quarantine with `definitions-update` boot intent, then
scan as no-NIC/read-only-quarantine with `scan-offline` boot intent. Failure,
cancellation and timeout return the same idempotent cleanup owner.

Focused production guest-adapter tests prove the fixed FreshClam/clamscan/clamd
unit order, complete official receipt evidence, per-overlay identity retention,
the scoped VPN context gate, receipt-before-offline-staging order, fixed-unit
staging failure/cancellation/timeout cleanup, QEMU-mode/Nix-phase agreement,
strict manifest identity/command parsing, exact conditional report-tool
composition, bounded one-output text reconstruction and idempotent volatile
cleanup. Missing required IDs, duplicate IDs or commands, malformed metadata,
operation aliases and version conflicts all fail closed. Archive fixtures prove a valid nested ZIP is
extracted, reinventoried, scanned, recursively reconstructed and promoted only
as its sanitized leaf. Traversal, encryption, expansion-ratio bombs, depth
exhaustion and member extension/type mismatch become blocking findings; member
scan cancellation and deadline leave no extraction tree or output.

The WS-002 production promotion gate proves that only the sole output in a
complete approved report is requested, scanner framing is bounded and rejects
trailing data, the relay assigns a destination transfer ID without exposing a
host path, and scanner sender, daemon relay and workstation receipt hashes are
equal. Daemon transport tests prove creation uses a separate active workstation
session and failure, cancellation or timeout converges that destination to
`DESTROYED`. CLI tests prove only successful workstation approval returns the
destination ID and invokes the user-owned viewer; USB approval omits both.

### Session, QEMU and ephemeral-storage evidence

Batch 1 runtime tests exhaust every allowed lifecycle transition and each
role-specific workflow transition, reject cross-role and cleanup-state bypasses,
and race concurrent requests against the fixed per-owner quota. Allocation tests
prove that cancellation rolls an unregistered resource back, duplicate and late
registrations fail, concurrent cleanup callers coalesce behind one owner, caller
cancellation does not abandon cleanup, a failed reverse-order cleanup resumes,
and daemon shutdown rejects new sessions while converging existing ones.

Event tests cover bounded replay plus follow, future cursors, contiguous sequence
validation, terminal closure, slow subscribers, and the 4,096-event fail-closed
limit. Volatile-record tests pin the `/run/private-vm` root identity and use
`openat2`/dirfd-relative operations to reject symlink, hardlink, magic-link and
root-replacement attacks. The journal decoder is bounded to 1 MiB and rejects
unknown fields, duplicates and trailing documents; its seed corpus is also a
short single-worker fuzz target.

Typed QEMU tests validate executable and image identity before launch, reject
TCP QMP/SPICE and shared-filesystem device shapes, bound QMP frames and command
deadlines, and inject process exit, QMP loss, cancellation, TERM timeout and
KILL escalation through the fake process harness. Storage tests cover trusted
read-only bases, fresh overlay teardown, tmpfs and LUKS resource audits,
overflow-safe host capacity probes, zram-only swap policy, exact loop-to-file
ownership, the private no-backup marker, rollback at each allocation boundary,
and repeated cleanup.

Focused production-composition tests additionally prove volatile plan/image/
storage/runtime ownership, reverse cleanup, partial-runtime timeout ownership,
scanner/exporter fail-closed behavior, downloader seal-before-absence audit,
idempotent private socket-directory cleanup, bounded 16-KiB guest torrent
framing, single first-frame context and oversize/send-failure rejection. Run
the affected source gate without starting a VM or mutating host networking:

```bash
GOMAXPROCS=2 go test -p=1 \
  ./cmd/private-vmd ./internal/orchestrator ./internal/guest ./internal/daemon
```

This focused gate does not prove live network namespace counters, mock-peer
packets, a real Proton handshake, cached official role images, KVM launch, or
the scanner/exporter host workflows. Workstation and downloader acceptance also
requires the role-specific guest VPN RPC implementation to consume the typed
underlay and fixed probe targets; a host build paired with an older guestd must
fail the authenticated readiness gate and is not release evidence.

The D-005 source recovery harness supplies all resource classes in reverse
order and proves the reconciler nevertheless executes the fixed dependency
order: QEMU/process, cgroup, private sockets, VSOCK CID, TAP/veth/netns/nftables,
USB claim, outer mount, mapper, loop, ciphertext and volatile runtime path. It
also injects identity replacement before the first mutation and immediately
before cleanup, a live-registry owner, available/unknown volatile-key evidence,
cleanup failure, per-object audit failure, whole-session audit failure,
cancellation, timeout and immutable-base-image drift. Reports are schema
validated and inspected for absence of session IDs, locators, fingerprints and
wrapped backend errors.

These source tests use typed fakes and make no host mutation. The release gate
still requires daemon-startup composition with the concrete QEMU, cgroup,
network, storage, VSOCK and USB inventories, a daemon `SIGKILL` acceptance, and
one controlled maintenance-window reboot.

The production startup path is now source-tested with the concrete Linux
filesystem/outer-storage adapter. Private temporary roots prove early-record
cleanup, exact ciphertext deletion after volatile-key-loss evidence, identity
replacement rejection, unknown-key retention, cancellation, immutable-base
drift, closed report publication and refusal to admit the daemon for incomplete,
timed-out or canceled recovery. These tests run no recovery command against the
real host. Process/cgroup, network, VSOCK and USB recovery remains fail-closed,
not simulated as successful production evidence.

Focused production-composition tests additionally prove volatile plan/image/
storage/runtime ownership, reverse cleanup, partial-runtime timeout ownership,
scanner/exporter fail-closed behavior, downloader seal-before-absence audit,
idempotent private socket-directory cleanup, bounded 16-KiB guest torrent
framing, single first-frame context and oversize/send-failure rejection.

The exporter/USB source gate runs without QEMU, USB mutation or a host mount:

```bash
GOMAXPROCS=2 go test -p=1 \
  ./internal/qemu ./internal/orchestrator ./internal/usb \
  ./internal/daemon ./internal/cli ./cmd/private-vmd
```

This focused gate does not prove live network namespace counters, mock-peer
packets, a real Proton handshake, cached official role images, KVM launch, or
physical USB preparation/export. Workstation and downloader acceptance also
requires the role-specific guest VPN RPC implementation to consume the typed
underlay and fixed probe targets; a host build paired with an older guestd must
fail the authenticated readiness gate and is not release evidence.

The approved-source tests additionally prove scanner registration requires one
complete approved report output, binds the authenticated scanner role/context,
accepts the exact begin/chunk/end/EOF sequence only, and is one-use. The
workstation case proves registration occurs only after guest export
verification, repeats current exported/unchanged inventory validation at open,
and rejects a changed identity. Daemon tests prove USB approval retains the
offline scanner and a successful exporter receipt stops and cleans it.

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

The volatile journal and strict QMP envelope decoders have corresponding local
single-worker smokes:

```bash
GOMAXPROCS=2 nix develop --offline --command \
  go test -p=1 ./internal/session -run='^$' \
  -fuzz='^FuzzDecodeVolatileSessionJournal$' -fuzztime=2s -parallel=1

GOMAXPROCS=2 nix develop --offline --command \
  go test -p=1 ./internal/qemu -run='^$' \
  -fuzz='^FuzzQMPEnvelope$' -fuzztime=2s -parallel=1
```

The targets enforce the decoder's 1 MiB journal bound or a 64 KiB QMP fuzz
input bound and exercise strict unknown-field, trailing-document, message-shape
and legal-transition validation without launching external processes.

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
- embedded guest identity and exact role/capabilities
- XFCE/lightdm target
- no SSH
- volatile journal
- authenticated VSOCK guestd readiness with the synthetic `fw_cfg` capability
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

Pure Nix build sandboxes do not expose the host `/dev/vhost-vsock` device. VM
gates therefore load the kernel `vsock_loopback` transport and exercise the
real guestd AF_VSOCK listener at CID 1. The test-only client is compiled only
for Linux, refuses every CID except 1, and retains the production transport
credentials, message/header bounds and token interceptors. Production QEMU
continues to require `vhost-vsock-pci` with an allocated CID of at least 3; its
typed device model and host-to-guest behavior are verified separately. This
split makes the TCG boot gate reproducible without weakening the production
CID policy or adding an impure device to CI.

The downloader and both scanner phase gates use a test-only client that first
proves an incorrect capability is rejected and then authenticates `Hello` with
that synthetic capability. The client is added only to VM-test configurations,
never to a production package or image. Run the two 2 GiB scanner gates
serially on the 16 GiB development host.

The exporter boot gate is run with:

```bash
nix build .#checks.x86_64-linux.exporter
```

It uses TCG and an explicit empty VLAN list. The test requires loopback to be the
only interface, rejects every TCP/UDP listener and desktop/network-management
component, confirms the LUKS2/ext4/partitioning/USB-inspection/checksum tools and
their embedded package/version/store-path inventory, and compares both embedded
image identity and `private-vm-guestd --version` against the exact exporter
capability set. The harness adds no writable quarantine disk and rejects any
USB-backed block device. It does not attach, inspect, format or write a USB
device.

The three workstation desktop gates are run with:

```bash
nix build .#checks.x86_64-linux.workstation-desktop
nix build .#checks.x86_64-linux.workstation-office-desktop
nix build .#checks.x86_64-linux.workstation-development-desktop
```

Each boots the exact canonical workstation module and bundle with explicit TCG
and no test VLAN, waits for LightDM autologin and the XFCE session, verifies both
SPICE agent processes and the virtio channel, validates its versioned bundle
manifest, installed/forbidden desktop applications, locked Firefox policy
values, and crash-reporter environment, and repeats the no-SSH-server/sudo and
no-TCP/UDP checks. The pure
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
  actual database installation while explicitly excluding the official main,
  daily and bytecode databases, so it cannot rely on Internet availability or
  a real credential.
  It also proves no FreshClam service/timer is present and the fixed guestd-owned
  definitions oneshot is disabled and inactive before authenticated RPC use.
  It verifies the offline specialisation switch exists and its fixed staging
  oneshot is disabled and inactive before authenticated RPC use.
- `scanner-offline` uses explicit QEMU `-nic none`, verifies zero non-loopback
  interfaces, attaches one read-only ext4 fixture, verifies the block read-only
  bit and `ro,nodev,nosuid,noexec` mount flags, then proves writing fails.
  The update and offline boots inject their exact typed `fw_cfg` phase values;
  offline also proves neither update nor staging unit is present.

Both scanner boots verify the compiled `scanner` role and the exact advertised
common-plus-scanner capability list. They also reject SSH/sudo, credential
directories and workstation/downloader commands. Run the VM checks one at a
time; they are deliberately not a multi-node test.

The public image workflow maps the six canonical image outputs to these exact
TCG gates in six independent standard-runner jobs. It builds no two canonical
images in one workspace. A scanner job is the sole exception to one boot per
job: its update and offline phase tests execute serially because both phases
belong to the same scanner image contract. Each row requires its canonical build
to emit exactly one existing direct `/nix/store` path and reports closure size
from that captured path, so closure reporting cannot select a different target
or trigger a second flake evaluation.

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

The source-level scanner gate is intentionally credential-free and runs with
one Go package worker:

```bash
CGO_ENABLED=0 GOMAXPROCS=2 go test -p=1 ./internal/scan
CGO_ENABLED=0 GOMAXPROCS=2 go vet ./internal/scan
CGO_ENABLED=0 GOMAXPROCS=2 go test -p=1 ./internal/guest ./cmd/private-vm-guestd
CGO_ENABLED=0 GOMAXPROCS=2 go vet ./internal/guest ./cmd/private-vm-guestd
python3 tools/validate_schemas.py
python3 tools/validate_examples.py
```

It generates ZIP/TAR fixtures in memory and proves traversal, absolute path,
symlink, hardlink, FIFO, encrypted archive, nesting, expansion-ratio and output
replacement failures. A local `net.Pipe` implements the ClamAV protocol fixture;
the production scratch fixtures prove the exact private-tmpfs relationship,
flags, ownership and 512 MiB ceiling, including missing, malformed, oversized
and cancelled verification plus reconstruction cleanup. A Nix source contract
and flake assertion keep those runtime expectations synchronized with the
scanner service unit. The PDF probe fixture proves fixed stdin-only all-page
arguments, maximum
dimensions across heterogeneous pages, and rejection of missing, duplicate,
out-of-range, inconsistent, over-limit and oversized-output evidence while
preserving cancellation and timeout codes. No daemon, definitions download or
hostile public corpus is required. Real
freshclam, offline boot/device enforcement and pinned PDF/Office/media tools
remain separate scanner-image and KVM acceptance gates.

The guest RPC portion uses an authenticated in-memory gRPC transport and two
scanner-service instances sharing only a fake retained-overlay receipt. It
proves update boot to offline boot sequencing, descriptor-safe inventory, a
complete fake malware verdict, reconstructed-only output, canonical report
authentication, bounded export framing, role-only registration, stable redacted
adapter failures, cancellation/timeout mapping and idempotent output cleanup.

## Network tests

VPN-001 unit and fuzz evidence uses synthetic WireGuard keys and mock resolvers
only. Parser tables cover the accepted IPv4/IPv6 profile, every hook and unknown
field, multiple peers, duplicate fields, invalid key shapes, unsafe DNS and
addresses, missing/partial/additional default routes, missing endpoint ports,
IPv4-mapped public/loopback values, special-use ranges, malformed key padding,
`PersistentKeepalive`, zoned addresses, line/input bounds, read failure and
destroyed input. Formatting and serialization tests prove that the private key,
endpoint, resolved view, guest-configuration reader, address and DNS values
cannot enter status JSON or diagnostic formatting. Typed-nil input and resolver
adapters are rejected without invocation, and Linux source tests include legacy
CIFS as well as SMB2/FUSE/NFS/9P remote-filesystem rejection.

Resolver tests prove literal-IP behavior, trusted-host hostname resolution,
absolute-name lookup, mapped/special/empty/oversized result rejection,
deduplication/order, cancellation and a bounded timeout. Memory-store tests
prove owner isolation, owner-local generation counters, atomic generation
replacement, exact-plan binding and post-callback resolved-view expiry,
cross-profile and cross-owner substitution rejection, invalidation on every
resolution attempt, non-cooperative resolver isolation, actionable rotation
status, idempotent remove/close and no restore after daemon shutdown.
Daemon/CLI tests cover bounded import framing, authenticated Unix transport,
source destruction on every outcome, stable local/RPC error mapping, shutdown
cleanup, and aggregate-only status output. Guest-config tests consume the ephemeral
reader and cover success, callback failure and cancellation; fixtures never use
a real Proton credential.

NET-001/NET-002 source tests use only a semantic in-memory Linux backend and
synthetic VPN plans. They cover deterministic collision-bounded naming,
overlapping host-route rejection and static IPv4/IPv6 allocation; partial
failure after namespace, veth, host and namespace configuration, TAP and each
policy transaction; cancellation and
timeout rollback; repeated cleanup after false-success deletion; and final
absence auditing. Concurrent tests prove provisioning, scoped TAP/config
handoffs and cleanup cannot overlap, caller cancellation cannot abandon an
accepted cleanup, stale handles fail closed, and VPN rotation invalidates every
handoff without obstructing cleanup.

Rule-model tests prove exact IPv4/IPv6 guest source, endpoint destination and
return destination matching, interface-bound default drops, and exact NAT.
Linux-adapter tests prove endpoints appear only in transient nft stdin, those
buffers are cleared on success and failure, endpoint-like stdout never enters
an error, generic exit status `1` cannot claim absence, and repeated exact
inventory of already absent resources performs no mutation. These tests do not
exercise host privileges or a real credential.

Production counter-auditor source tests feed bounded synthetic `nft -j` records
through the real parser. They prove exact host/namespace table selection,
versioned ownership, primary and later fail-closed audit-chain presence, every
IPv4/IPv6/DNS/private-range/unrelated-egress counter at zero, output destruction,
and rejection of missing, malformed, nonzero, stale and unowned evidence.
Cancellation and deadline failures preserve their typed context result; all
other failures are redacted. These source tests do not claim that live namespace
packet counters have run.

The opt-in `verify-network-live` gate re-executes the test binary under
unprivileged user, mount and network namespaces and mounts a private tmpfs on
`/run`, so its nested `ip netns`, TUN and nftables objects cannot enter host
networking. It uses the flake-pinned `ip`, `nft`, `sysctl` and `unshare` paths and
the production Linux backend. The gate proves real namespace/veth/TAP creation,
the exact IPv4 and IPv6 endpoint paths, DNS/LAN/metadata/unrelated-public drops,
both live policy tables with zero second-boundary counters, cancellation,
deadline propagation, repeated cleanup and exact final
absence. It constructs fixed synthetic addresses directly and never constructs
a VPN profile or WireGuard key. Output is bounded to the Go JSON stream plus one
versioned boolean-only evidence record.

The disposable outer namespace enables its own global IPv6 forwarding before
the packet proof. The gate demonstrated that the current runtime's owned-veth
setting alone is insufficient when outer `net.ipv6.conf.all.forwarding` is off.
By contrast, it asserts that outer `net.ipv4.ip_forward` remains off while the
current exact ingress-veth IPv4 forwarding setting passes the permitted packet.
The installed host module and `doctor --strict` must therefore supply and verify
that prerequisite, or a replacement ADR must redesign the outer forwarding
boundary. This source gate does not prove that production-host prerequisite.

NET-003 source tests prove that the guest kill switch is installed before any
underlay/tunnel configuration, permits only `proton0`, the exact UDP endpoint
and required neighbor discovery, and contains no clear-interface DNS or TCP
allowance. Adapter tests prove profile-derived nftables, address, route and
WireGuard values do not enter argv/environment; they travel through bounded
stdin readers, while DNS uses only the typed D-Bus boundary. Controller tests
cover complete/incomplete proofs, downloader binding, cancellation, timeout,
tunnel loss, role response and retryable tunnel-before-policy cleanup. Guest
RPC tests prove the protobuf profile slice is detached and cleared on success
and rejection. QEMU tests prove descriptors 3 and 4 are inherited and no TAP
name enters argv.

These tests remain unprivileged and synthetic. They also exercise the concrete
systemd-resolved D-Bus call model, fixed WireGuard handshake command, bounded
interface-bound connection adapter, loopback-only qBittorrent binding check,
typed workstation-warning/downloader-pause responses, and host lifecycle
composition. The orchestration fault matrix proves ordered start, refusal of
incomplete guest/counter proofs, cancellation, dirty-stop protection,
unexpected QEMU exit cleanup, retry and idempotence. Namespace packet tests, a
mock WireGuard peer, image composition, live QEMU ordering and the controlled
Proton smoke test remain image/acceptance gates. The isolated Linux topology
gate above now supplies the real namespace packet and production nftables
counter evidence without mutating the host network.

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

## Torrent source tests

TOR-001–TOR-003 source tests use only synthetic BTIH/metainfo values, semantic
fakes and an in-memory qBittorrent HTTP fixture. They cover malformed and
oversized input, hidden-terminal/stdin/file source selection, source
destruction and redacted failures; add-paused ordering, repeated pause during
metadata fetch, zero-payload evidence, path/case hazards, safe-policy blocked
types, explicit selection and all capacity stages; success, error,
cancellation, timeout/stall pause, VPN-loss pause, exact manifest matching,
sync/unmount, idempotent cleanup and retryable downloader absence audit.
Capacity-specific tests use distinct stage values and prove the minimum-stage
decision, insufficient quarantine/scanner/reconstruction/destination failures,
checked-arithmetic overflow, a fresh quarantine probe and downstream receipt
on reselection, cancellation/deadline propagation, stable redacted errors and
the production role-plan composition. An end-to-end production planner fixture
admits a small non-archive selection, rejects one-byte deficits independently
at all four stages, rejects input above the 128 MiB runtime ceiling and proves
archive/reconstruction/output bounds fit the exact 512 MiB scanner scratch.
Protobuf descriptor tests prevent paths,
devices, mounts, endpoints, names or hashes from entering the capacity receipt.

The HTTP contract test proves only loopback API origin, fixed quarantine path,
paused add and bounded/redacted responses. The Linux file verifier uses
`openat2` beneath the quarantine root with no symlinks, magic links or mount
crossing, requires one-link regular files of exact size and hashes with bounded
memory. Live image qBittorrent API compatibility, block-device mounting, VPN
packets and QEMU absence remain explicit acceptance tests.

The production-composition tests additionally prove that the per-boot
qBittorrent plaintext is absent from its volatile configuration, authenticated
requests carry only the bounded loopback SID, and the binding probe observes
`proton0`. Fixed-child tests cover start failure, canceled start, bounded
TERM/KILL cleanup, pidfd/process-group ownership, secret-free argv/environment
and idempotent stop in the same mount namespace as guestd. The quarantine
owner tests cover blank/ext4/unknown signatures, mount preparation,
cancellation cleanup, sync/unmount, absence audit, retry after failed unmount
and idempotent close without invoking a real block device or mount syscall.
The role-adapter tests configure the same typed underlay through both exact
workstation and downloader services, reject a mismatched role before controller
composition, clear request-only bytes on every return and prove that adding the
workstation methods does not register the downloader service.

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
9. TAP create/configure
10. namespace nft apply
11. host nft apply
12. QEMU start
13. QMP connect
14. guest handshake
15. USB claim

Then assert zero remaining resources or a specific recoverable cleanup record.

## Acceptance tests

A release must pass all entries in `project/acceptance-tests.yaml`.

Workstation transfer unit tests use only private temporary directories. They
cover a complete import/export, traversal and symlink rejection, digest failure
cleanup, no-overwrite staging, opaque inventory identities, verification,
changed-after-export detection, pinned-parent source behavior, Inbox pathname
replacement, exact terminal EOF, frame/chunk limits, cancellation, deadline,
and receiver-failure cleanup. Focused production-relay tests prove that a
trailing import or export frame prevents the end frame from reaching the next
commit boundary. The full host/daemon/VSOCK relay and dirty-stop acceptance
remain separate integration gates; guest-only evidence cannot mark those gates
complete.

The host workstation source gate additionally uses authenticated daemon fakes
to exercise import, aggregate inventory, export and verification, and a real
pair of local Unix sockets to prove the display relay, exact peer UID check,
fail-fast concurrent-client rejection without a queued hang, bounded
caller-death cleanup and identity-pinned replacement refusal. It does not start
QEMU or a graphical viewer.

Daemon role-lifecycle tests run every workstation startup gate through the
session actor, prove storage and runtime cleanup execute in reverse allocation
order, and inject failure at preflight, image verification, storage allocation,
and runtime allocation. Each failed start must converge to `DESTROYED` with no
active fake resource. Protected-stop tests prove dirty, changed, unreachable,
and `--require-clean`/`READY` states remain `ACTIVE` until explicit discard.
These tests establish the daemon ownership contract; real image, network,
VSOCK, display, and workspace-relay composition remain system gates.

Production-invoker tests run workstation plan/create/start, implicit
single-session selection, listing, protected stop, start-failure abort, request
ID failure, stable error-to-exit mapping, and the closed `SESSION_STATUS`
renderer over a private Unix gRPC fixture. No runtime path, guest endpoint, or
workspace content is representable in that payload.

Workspace production-invoker tests prove no-follow trusted import, receipt
mismatch rejection, aggregate-only inventory, fail-before-stream behavior when
a destination is unsupported, semantic USB enum selection with no path or file
bytes in the request, and changed-receipt rejection. Daemon destination tests
prove prepare-before-source, bounded source framing, independent receiver
re-read evidence, three-way digest matching, final READY verification, and
idempotent abort on failure, cancellation, timeout, digest mismatch, and cleanup
failure. Real USB writes remain the destructive system gate; encrypted bundles
remain fail closed pending their separate contract.

## Test safety

Tests never:

- use real Proton credentials in CI
- download public torrents
- write an unapproved physical USB on contributor machines
- modify host firewall outside unique test namespaces/tables
- require root without explicit integration-test opt-in
- print or retain fixture `pkcheck` stdout/stderr or raw `/proc` identity data
