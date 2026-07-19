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
VSOCK-only gRPC transport credentials, locked capability token, authentication
and request-context interceptors, exact role service registration, and verified
Hello handshake. Linux dialing uses a cancellable socket connect directly;
there is no detached dial goroutine.

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
and unexpected ownership.

## Concurrency

- one orchestrator goroutine owns workflow state
- commands enter through a serialized transition channel
- event subscribers are read-only
- cleanup uses `sync.Once`
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
