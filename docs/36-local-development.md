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
```

`buf generate` removes stale generated files before invoking the immutable
plugin version/revision pins in `buf.gen.yaml`. A clean checkout must remain
unchanged after regeneration. When preparing a pull request, replace the branch
selector `branch=main` with `ref=<exact-base-commit>`, yielding
`.git#ref=<exact-base-commit>`.

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

## Privileged RPC boundary tests

The daemon integration suite uses a temporary Unix socket and requires no root
privileges. It verifies `SO_PEERCRED` ownership, group authorization behavior,
socket mode `0660`, API-version rejection, volatile `0700` session records,
serialized transitions, and retryable idempotent cleanup:

```bash
nix develop --command go test -race ./internal/daemon ./internal/session
```

`private-vmd` itself refuses to run without effective UID 0. It loads only the
system file passed by `--config`; it never layers root's user configuration into
the privileged service. The production socket is always
`/run/private-vm/control.sock`, owned by `root:private-vm`.
