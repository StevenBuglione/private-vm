# Go architecture

## Toolchain

Frozen v1 baseline:

- `go 1.26.0` language and module baseline
- exact `toolchain go1.26.5` with `GOTOOLCHAIN=local` in CI
- committed `go.sum` and `vendor/` dependency closure
- `CGO_ENABLED=0` for all product binaries
- race tests on Linux
- reproducible build flags
- version information injected through `-ldflags`

Guest graphical applications may require cgo only if a future native UI is
introduced. Such a change requires an ADR; the host binaries and role-compiled
guest daemons are currently statically linked.

## Binary responsibilities

### `cmd/private-vm`

Thin composition root. It creates configuration, API client, renderer, and
command tree. The process root converts `SIGINT` and `SIGTERM` into context
cancellation; the CLI maps cancellation to exit 21, while the invoked workflow
remains responsible for its bounded, idempotent cleanup.

`internal/cli` validates every argument and option before creating a sealed,
typed semantic intent. Commands with selectors, paths, policies or destructive
modes cannot dispatch an empty or arbitrary parameter map. Convenience aliases
construct the same intent and command ID as their canonical workflow entry
point. The default invoker fails closed with `NOT_IMPLEMENTED` until the owning
backlog task installs a tested orchestrator implementation.

Operational command pre-run resolves an immutable `internal/config.Config`
snapshot. The loader distinguishes absent boolean flags from explicit false
values and maps its redacted stable errors to exit 11 without wrapping raw file
or parser errors. Workstation request defaults are copied from that snapshot
into the sealed intent; changed flags replace only their corresponding values.
The daemon independently uses `config.LoadDaemon`, which accepts one required
root-owned system layer and no user layer. Privileged handlers must treat the
CLI snapshot as a request and revalidate it against the daemon snapshot.

Machine records use closed success, error and event envelopes plus reviewed
typed payloads. Encoding is buffered, size-bounded and written as one record;
wrapped error causes never cross the presentation boundary. Sensitive terminal
input disables echo and restores it on success, failure, timeout and
cancellation; terminal acquisition is process-serialized. Value and stream
requests have hard 1 MiB and 64 MiB ceilings. Value-collection buffers allocate
their final plaintext capacity once so superseded backing arrays cannot retain
copies.
Process standard-input ownership is serialized and read through a raw, bounded
Linux descriptor duplicate; cleanup restores the original status flags before
releasing the lease, and any close/restore failure invalidates a produced
secret. The embedding API rejects caller-owned `*os.File` values
instead of modifying or closing their poller/deadline state. Context-aware and
known in-memory readers remain valid test and embedding inputs. File input uses
`openat2` to reject symlinks in every path component and is regular-file and
size checked. POSIX regular-file open/read calls cannot be portably interrupted,
so the CLI input boundary rejects deadline-bearing file requests before I/O and
uses no detached helper goroutine; future transfer implementations require an
owned worker/cleanup boundary. Untimed calls check cancellation immediately
before and after I/O. Strict
credential input additionally requires caller ownership with no group, world
or executable permission bits. Linux rejects FUSE, NFS, SMB and 9P sensitive
input files because their reads cannot honor a local deadline.

### `cmd/private-vmd`

Starts the privileged server, recovery scan, authorization, and orchestrator.

### `cmd/private-vm-guestd`

Reads the compiled role from a build flag/config, starts the VSOCK service, and
registers only role-specific handlers.

The Nix guest derivations set `internal/guest.CompiledRole` with a linker flag.
No runtime role selector exists. guestd reads the 256-bit capability from the
fixed `fw_cfg` sysfs item, starts gRPC on VSOCK port 4050, and shuts down with a
bounded graceful-stop interval.

## Internal package boundaries

```text
attestation  verify GitHub/Sigstore provenance
cli          command definitions and output
config       typed TOML and migrations
daemon       Unix gRPC server and authorization
guest        VSOCK client/server and capability model
image        OCI pull/cache/manifest
network      netns, TAP, veth, nftables
orchestrator workflow state machines
policy       content and transition decisions
preflight    pure diagnostics
qemu         argument model, process, QMP
scan         report and reconstruction orchestration
secret       memfd/mlock/redaction wrappers
session      ownership model and cleanup
storage      LUKS outer container and disk files
torrent      qBittorrent API model
usb          enumeration, enrollment, claim
vpn          WireGuard parser and tests
workspace    bounded import/export
```

Packages must depend inward toward interfaces. External process execution is
centralized behind narrow interfaces so tests can use fakes.

`internal/guest` owns the volatile CID allocator, context-aware AF_VSOCK dialer,
VSOCK-only gRPC transport credentials, protected capability token, authentication
and request-context interceptors, exact role service registration, and verified
Hello handshake. Linux dialing uses a cancellable socket connect directly;
there is no detached dial goroutine.

`internal/vpn` owns the closed Proton WireGuard grammar, protected private-key
handle, trusted-host endpoint resolver and daemon-lifetime memory store. Parsing
is capped at 64 KiB and 256 lines. The private key is decoded directly from a
byte slice into `secret.Bytes`; profile, key, endpoint, resolved-view and
guest-configuration reader types reject serialization and redact diagnostic
formatting. Only a schema-versioned aggregate inspection is serializable. The
resolver accepts a narrow context-aware `LookupNetIP`
interface, has a hard ten-second ceiling, resolves hostnames as absolute names,
and returns at most 16 sorted unique addresses that pass the explicit reviewed
public-endpoint range policy. Resolver errors discard hostname and external
error text. DNS executes without the store mutex: an injected adapter that
violates its context contract can strand only its own `Resolve` caller, not
import, remove, close, or daemon shutdown.

The memory store has no path, marshal, restore or startup-loading operation and
admits at most eight profile names per owner and 64 across the daemon.
Generation counters are owner-local so one caller cannot infer another owner's
import activity. Import atomically replaces a named generation and destroys the
old key. Remove,
close and daemon restart converge on owned-key destruction. A resolved guest
configuration is reconstructed into a bounded byte buffer only while consuming
the exact opaque owner/name/generation/resolution-epoch plan that also supplies
the host firewall endpoints. The resolved view is usable only during its
`UsePlan` callback and fails closed if retained. Re-resolution invalidates and
clears the prior endpoint set before DNS starts; rotation, removal, failure and
close invalidate and clear it as well. The
private key is never converted to a Go string and the transient buffer is
cleared after success, failure or cancellation.

`internal/network` is the sole owner of deterministic per-session network
allocation. It derives bounded netns, veth, TAP and nftables names only from an
already validated opaque session ID, searches at most 64 deterministic address
slots, and reserves a slot before mutation. The Linux adapter exposes semantic
operations only; `ip`, `nft` and `sysctl` paths have exact package-controlled
basenames, output is bounded, stderr is discarded, and nftables transactions
arrive through stdin. A generic nonzero tool status is never interpreted as
resource absence. Cleanup first inventories exact names, attempts every resource
that creation may have touched, and releases ownership only after a final exact
inventory proves absence.

One lifecycle mutex is acquired before a network state becomes visible. It
serializes provisioning, scoped TAP/static-address/VPN-config handoffs and the
idempotent cleanup owner. Cleanup invalidates readiness immediately, uses its
own bounded context after accepting the request, keeps all attempt markers
until the final audit passes, and destroys the copied endpoint policy before
releasing the slot. The TAP has already moved into the session namespace before
`WithTAP` supplies a scoped duplicated descriptor and closes that parent-side
duplicate on callback return; trusted callbacks must not duplicate it again.
The QEMU process owner must terminate the child before network cleanup, so its
inherited descriptor cannot outlive the VM lifecycle.
No API reveals namespace/interface names, static addresses, endpoint tuples or
raw rule text. Only the aggregate `network-status.schema.json` inspection is
serializable.

## Volatile secret contract

`internal/secret.Bytes` is a bounded handle to shared private state. Copying the
Go handle is safe: every copy refers to the same state, and `Destroy` through
one invalidates all copies. A nil or zero-value handle is inert and cannot
duplicate or close an unrelated descriptor. The type rejects JSON, text,
binary, gob and XML serialization and implements redacted string and formatting
interfaces.

On Linux, creation uses a mode-0600 `memfd`, a shared writable mapping,
`MADV_DONTDUMP`, and grow, shrink, future-write and seal seals. `mlock` is
attempted but remains best effort because ordinary users may have a zero or
small `RLIMIT_MEMLOCK`. A supported-kernel memfd setup, mapping, dump-exclusion
or sealing failure is blocking. Only `ENOSYS` permits a documented heap
fallback; that fallback cannot export an inherited FD and provides weaker
copy/dump guarantees. Non-Linux storage is a compile-only heap fallback and is
not a supported production secret transport.

`DupFile` reopens the owned memfd as a read-only, independent open-file
description at offset zero. This is required because a normal duplicated FD
would share its offset and would cause the second `cryptsetup` key read to see
EOF. Callers own and close the returned CLOEXEC descriptor, and product process
launchers pass it only through `ExtraFiles`.

`WithReader` provides a forward-only view that copies into the callback's read
buffers and is invalidated when the callback returns; it never exposes the live
mutable backing slice. `Equal` provides the dedicated constant-time comparison
operation. A callback or downstream encoder can necessarily retain bytes it
chooses to read, and gRPC metadata necessarily creates a transient string.
Callbacks are therefore small, trusted and bounded. They must not re-enter a
method on the same shared secret handle because the lifecycle lock is held for
the callback's complete duration.

`Destroy` serializes against active readers and overwrites the current mapping.
It then best-effort syncs, unlocks, unmaps and closes after the overwrite; those
kernel cleanup results are not a perfect-erasure signal. Explicit destruction
reduces exposure but is not a perfect-erasure claim: compiler, runtime,
syscall, library, kernel, hypervisor and hardware
copies outside the owned mapping cannot all be identified or overwritten.

## Dependency policy

Direct and indirect module versions are pinned in `go.mod` and `go.sum`. The
committed `vendor/` tree is the release and Nix build input; Nix sets
`vendorHash = null` so it cannot silently fetch or substitute a different
module closure. CI verifies the exact Go release, module checksums, a clean
`go mod tidy -diff`, and byte-for-byte vendor regeneration before tests.

Current and planned narrowly scoped dependencies include:

- Cobra for CLI
- gRPC-Go and protobuf
- `mdlayher/vsock`
- `pelletier/go-toml/v2`
- `oras-go/v2`
- `klauspost/compress/zstd` for bounded in-process QCOW2 decompression
- `sigstore-go`
- `google/uuid` or standard random UUID implementation
- `golang.org/x/sys/unix`
- `golang.org/x/term`
- Prometheus is not required; no telemetry server

Dependency changes update `go.mod`, `go.sum`, and `vendor/` together in a
reviewed pull request. `govulncheck ./...` is blocking for unresolved applicable
findings; a suppression requires a documented risk decision and expiry.

## External command wrappers

Define typed interfaces:

```go
type QEMU interface {
    Launch(ctx context.Context, spec LaunchSpec) (Process, error)
}

type Cryptsetup interface {
    Format(ctx context.Context, req FormatRequest) error
    Open(ctx context.Context, req OpenRequest) (Mapping, error)
    Close(ctx context.Context, name string) error
}

type NFT interface {
    Apply(ctx context.Context, ruleset Ruleset) (Handle, error)
    Delete(ctx context.Context, handle Handle) error
}
```

Implementations invoke absolute executable paths with argument slices. No shell.

## Secret type

Create a type that:

- stores `[]byte`, never `string`
- optionally locks memory
- exposes read-only callback access
- redacts `String`, `GoString`, JSON, and error formatting
- zeros current backing bytes on `Destroy`
- documents that Go runtime copies cannot be perfectly guaranteed

## Path safety

Every daemon-created path is derived from an internal session ID, not user input.
Use `openat2` with restrictive resolution flags where available. Refuse symlinks
and unexpected ownership for those runtime paths. System configuration is the
narrow daemon-side exception needed by declarative NixOS `/etc` links: magic links are
rejected and an ordinary link is accepted only when the opened target descriptor
is a root-owned, non-writable regular file on an allowlisted local filesystem.
User-selected CLI configuration and policy files may likewise be ordinary
dotfile-manager links, but they are not daemon-created paths and their opened
targets must pass effective-user/root ownership, mode, type and filesystem
checks.

The volatile session store pins the runtime-root device and inode, serializes
dirfd-relative operations, and revalidates exact owner, group, type and mode on
every create/save/load/list/remove operation. Journal replacement is atomic and
strictly bounded to 1 MiB. Unknown or duplicate JSON fields, malformed event
chains, unsafe hardlinks, symlinks, root replacement and undocumented directory
entries all fail closed. Linux `openat2` support is mandatory for this boundary.

## Concurrency

- one session actor owns lifecycle state, typed role-workflow state, resource
  allocation/registration, event publication and cleanup
- commands enter through a bounded serialized channel
- event subscribers receive atomic replay-and-follow views and cannot mutate
  session state
- concurrent cleanup callers coalesce on one attempt; failure permits a later
  retry from the first incomplete reverse-order step
- allocation and cleanup registration are one actor command
- every subprocess has context cancellation and a wait owner
- no detached goroutines
- no channel send without bounded cancellation path

## Testing style

- table-driven unit tests
- fake external command executor
- fake clock
- fake filesystem where appropriate
- golden JSON schema/report tests
- fuzz parsers and QMP/protobuf boundary adapters
- integration tests in separate build tags
- no test requires real Proton credentials
