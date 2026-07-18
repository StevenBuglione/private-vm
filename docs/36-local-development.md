# Local development environment

## Nix

After `NIX-001` commits `flake.lock`:

```bash
nix develop
go test ./...
buf lint
nix flake check
```

Build a CLI:

```bash
nix build .#private-vm
./result/bin/private-vm version
```

Build one image:

```bash
nix build .#workstation-basic-image
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
