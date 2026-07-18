# Installation

## NixOS 26.05

Recommended.

Example host flake:

```nix
{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";
    private-vm.url = "github:StevenBuglione/private-vm";
  };

  outputs = { nixpkgs, private-vm, ... }: {
    nixosConfigurations.laptop = nixpkgs.lib.nixosSystem {
      system = "x86_64-linux";
      modules = [
        private-vm.nixosModules.default
        {
          services.private-vm = {
            enable = true;
            strictMode = true;
            enableUSBGuardIntegration = true;
          };
        }
      ];
    };
  };
}
```

Apply:

```bash
sudo nixos-rebuild switch --flake .#laptop
```

The module should:

- install CLI/daemon/remote-viewer/QEMU/cryptsetup/nftables/iproute2/USBGuard
- create `private-vm` group
- enable systemd service/socket
- create runtime/state directories
- configure Polkit
- configure tmpfiles
- optionally merge USBGuard rules
- add the chosen user to group only when explicitly configured
- avoid enabling libvirt

After group changes, re-login.

## Nix CLI-only development

```bash
nix develop
go test ./...
nix run .#private-vm -- doctor
```

A profile-only CLI install is not a complete runtime installation because the
root daemon and host integration are required.

## Debian/Ubuntu

```bash
sudo apt install ./private-vm_VERSION_amd64.deb
sudo usermod -aG private-vm "$USER"
```

Declared dependencies should include:

- qemu-system-x86/qemu-utils
- ovmf
- virt-viewer
- cryptsetup
- nftables
- iproute2
- usbguard
- policykit-1/polkitd
- util-linux
- e2fsprogs
- zstd

Package names vary; packaging tests must verify actual target releases.

## Fedora/RHEL

```bash
sudo dnf install ./private-vm-VERSION-1.x86_64.rpm
sudo usermod -aG private-vm "$USER"
```

Dependencies:

- qemu-kvm/qemu-img
- edk2-ovmf
- virt-viewer
- cryptsetup
- nftables
- iproute
- usbguard
- polkit
- util-linux
- e2fsprogs
- zstd

## Generic Linux

```bash
tar --zstd -xf private-vm_VERSION_linux_amd64.tar.zst
cd private-vm_VERSION_linux_amd64
sudo ./private-vm system install --dry-run
sudo ./private-vm system install --accept
```

The installer:

- validates systemd/cgroups/KVM
- prints exact file/service/group changes
- verifies bundled manifest
- refuses unsupported init systems
- never downloads and executes additional scripts

## Post-install

```bash
private-vm doctor --strict
private-vm images sync --role workstation --bundle basic
private-vm vpn import
private-vm usb enroll
```

## Upgrade

Package manager upgrade replaces binaries and units. Image updates are separate:

```bash
private-vm images sync
private-vm images verify --all
```

The daemon protocol must support a bounded compatibility window. Active sessions
are never hot-upgraded.

## Uninstall

```bash
private-vm session cleanup --all
sudo private-vm system uninstall --dry-run
sudo private-vm system uninstall --accept
```

Uninstall must not delete image cache or configuration without separate flags.
It must never delete user exports.
