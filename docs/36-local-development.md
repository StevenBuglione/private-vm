# Local development environment

## Nix

After `NIX-001` commits `flake.lock`:

```bash
nix develop
go test ./...
buf lint
buf generate
git diff --exit-code -- gen
test -z "$(git ls-files --others --exclude-standard -- gen)"
buf breaking --against '.git#branch=main'
nix flake check
nix build .#checks.x86_64-linux.host-module-contract
```

### 16 GiB workstation resource guard

The project workstation is swap-free and has 16 GiB RAM. Its user Nix
configuration must serialize derivations:

```ini
# ~/.config/nix/nix.conf
max-jobs = 1
cores = 2
```

Run only one heavyweight local command at a time and require at least 8 GiB
available memory before starting it. Use `GOMAXPROCS=2` and `go test -p=1` for
local Go gates. Build or boot role images one at a time; never run multiple
`nix flake check`, race-test or QEMU/TCG jobs concurrently. Remote protected
checks may run while dependency-safe source work continues, but their required
result is still enforced before merge.

On this host, place every local heavy lane in a user cgroup so a failed build
cannot invoke the kernel-wide OOM killer. Source/race gates use a 2 GiB ceiling;
one Nix evaluation or VM gate uses a 3 GiB ceiling:

```bash
systemd-run --user --scope --quiet \
  -p MemoryHigh=1536M -p MemoryMax=2G -p MemorySwapMax=0 \
  -p CPUQuota=200% \
  env GOMAXPROCS=2 go test -p 1 ./...

systemd-run --user --scope --quiet \
  -p MemoryHigh=2400M -p MemoryMax=3G -p MemorySwapMax=0 \
  -p CPUQuota=200% \
  nix --option max-jobs 1 --option cores 2 build --offline \
  .#checks.x86_64-linux.workstation-desktop
```

Do not run these two examples concurrently. A cgroup out-of-memory result is a
failed gate and must be investigated; it is not permission to raise the limit
or enable swap. Use the role-specific check name for other images.

`buf generate` removes stale generated files before invoking the immutable
plugin version/revision pins in `buf.gen.yaml`. A clean checkout must remain
unchanged after regeneration. When preparing a pull request, replace the branch
selector `branch=main` with `ref=<exact-base-commit>`, yielding
`.git#ref=<exact-base-commit>`.

## Go dependencies

Use the exact toolchain declared in `go.mod`; do not permit an automatic
toolchain download when reproducing CI:

```bash
GOTOOLCHAIN=local go env GOVERSION
GOTOOLCHAIN=local go mod verify
GOTOOLCHAIN=local go mod tidy -diff
GOTOOLCHAIN=local go mod vendor
git diff --exit-code -- go.mod go.sum vendor
test -z "$(git ls-files --others --exclude-standard -- go.mod go.sum vendor)"
GOTOOLCHAIN=local govulncheck ./...
```

The first command must print `go1.26.5`. Regeneration must leave `go.mod`,
`go.sum`, and the committed `vendor/` tree unchanged. Dependency updates commit
those three inputs together and must pass vulnerability review.

Build a CLI:

```bash
nix build .#private-vm
./result/bin/private-vm version
```

Build one image:

```bash
nix build .#image-workstation-basic
```

Do not boot an unreviewed image with host directories, credentials or USB
passthrough.

## Conventional Linux

Install:

```text
Go 1.26.5
protobuf compiler and Buf
QEMU/KVM
cryptsetup
nftables
iproute2
virt-viewer
Nix, for guest image development
```

Then:

```bash
go test ./...
go vet ./...
python3 tools/validate_schemas.py
```

## Test classes

- unit tests: no root, network, QEMU or external services;
- integration tests: Linux namespace/storage/QMP fakes or isolated test host;
- TCG boot tests: no nested KVM required;
- KVM end-to-end tests: dedicated self-hosted or local lab host only;
- destructive USB tests: dedicated test device and explicit environment gate.

## Environment gates

Tests that can mutate host state require both a build tag and an environment
variable, for example:

```text
go test -tags=integration ./integration/...
PRIVATE_VM_DESTRUCTIVE_TESTS=1 go test -tags=usb_destructive ./integration/usb
```

The implementation must verify the test device identity again inside the test.

The active public image matrix is intentionally remote and independent from the
16 GiB maintainer host. Continue dependency-safe source work while it runs, but
do not merge a change until every affected `image / <role>` job passes. Never
duplicate the image matrix locally in parallel merely to match GitHub timing.

## Privileged RPC boundary tests

The daemon integration suite uses a temporary Unix socket and requires no root
privileges. It verifies `SO_PEERCRED` ownership, group authorization behavior,
socket mode `0660`, API-version rejection, volatile `0700` session records,
serialized transitions, and retryable idempotent cleanup:

```bash
nix develop --command go test -race ./internal/daemon ./internal/session
nix develop --command go test ./internal/daemon -run='^$' \
  -fuzz='^FuzzDaemonRPCInputs$' -fuzztime=2s -parallel=1
```

The second command reproduces the active bounded fuzz smoke gate. Its
deterministic corpus covers every context-bearing daemon request protobuf shape
plus context and resource validation and the process stat, status, and pidfd-info
parsers; each generated input is capped at 64 KiB.

`private-vmd` itself refuses to run without effective UID 0. It loads only the
system file passed by `--config`; it never layers root's user configuration into
the privileged service. The production socket is always
`/run/private-vm/control.sock`, owned by `root:<configured-group>` (the default
group is `private-vm`).
