# Go architecture

## Toolchain

Initial baseline:

- Go 1.26
- modules and vendoring for releases
- `CGO_ENABLED=0` where possible
- race tests on Linux
- reproducible build flags
- version information injected through `-ldflags`

Guest graphical applications may require cgo only if a future native UI is
introduced. The initial guest daemon remains static.

## Binary responsibilities

### `cmd/private-vm`

Thin composition root. It creates configuration, API client, renderer, and
command tree.

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

## Dependency recommendations

Pin current stable releases in `go.mod` during Phase 0:

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

The starter scaffold has no third-party dependencies so it can compile before
dependency pinning.

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
