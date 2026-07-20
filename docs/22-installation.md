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
            strict = true;
            authorizedUsers = [ "steven" ];
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
- enable the systemd daemon service, which creates the Unix control socket
- create runtime/state directories
- enable Polkit, install `pkcheck`, and install only the
  `org.private-vm.usb.prepare` action
- configure tmpfiles
- enable USBGuard with a default-block policy
- add the chosen user to group only when explicitly configured
- avoid enabling libvirt

The module does not create backup-exclusion evidence by default. After the
operator has actually excluded `/var/lib/private-vm/scratch` from every host
backup, indexer and snapshot policy, set:

```nix
services.private-vm.scratchBackupExcluded = true;
```

This writes the exact validation marker required for disk-backed encrypted
scratch. The option is an operator assertion only; private-vm does not claim a
third-party backup tool honors the marker. Without that assertion, LUKS scratch
fails closed while capacity-qualified tmpfs sessions remain possible.

After group changes, re-login.

`authorizedUsers` accepts only existing explicitly declared NixOS accounts,
rejects duplicate entries, and is empty by default. The module never grants
socket access to every interactive user implicitly. The package also installs
the Bash, Zsh and Fish completions, `private-vm(1)` and `private-vmd(8)` manual
pages, the candidate-only udev discovery rule, and a documentation-only
USBGuard enrollment fragment. The udev rule does not authorize or pass through
a USB device; exact enrollment and the daemon policy remain authoritative.

The daemon runtime directory is `root:<configured-group>` mode `0750`, its
persistent state directory is mode `0700`, and the daemon creates
`/run/private-vm/control.sock` as `root:<configured-group>` mode `0660`. The
module installs the Polkit policy independently of a custom application-package
override. Its sole action is reserved for the later implemented destructive USB
prepare transition; the current unimplemented USB RPCs do not prompt. Ordinary
session management remains governed by the daemon socket group and per-session
owner checks.

The service receives the configured group explicitly and has a pinned PATH for
all read-only Doctor probes (`pkcheck`, QEMU, cryptsetup, nftables, iproute2,
e2fsprogs, virt-viewer, USBGuard and util-linux). The
`host-module-contract` flake check evaluates a custom group and a binary-only
package override to prove these integration invariants without building an
entire host closure.

Online roles also require `net.ipv6.conf.all.forwarding=1` in the outer host
namespace. The NixOS module declares and asserts this value. Other packages
must install an equivalent static sysctl fragment and activate it through the
distribution's normal mechanism or a reboot before starting the daemon. Doctor
reports a blocking diagnostic until the kernel value is exactly `1`; the daemon
does not change this global setting dynamically.

The daemon configuration is `/etc/private-vm/config.toml`. It must be a
root-owned regular local file with no group/world write or executable bits; the
packaged example is `examples/config.example.toml`. The daemon reads it once at
startup. A user may add an effective-user-owned file at
`$XDG_CONFIG_HOME/private-vm/config.toml`, but it supplies request preferences
only and cannot replace daemon enforcement. Neither file may contain a VPN key,
password, token, magnet or other secret.

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
sudo systemctl enable --now private-vmd.service
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
sudo systemctl enable --now private-vmd.service
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

The DEB and RPM are produced from one closed package-content specification.
They contain no lifecycle shell hooks. systemd-sysusers creates only the
`private-vm` group and systemd-tmpfiles creates the runtime/cache/scratch
directories with reviewed modes. The udev rule merely tags a mass-storage
candidate; it never authorizes, mounts or passes through a USB device.

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

The generic command works only from the extracted archive whose `manifest.json`
is beside the CLI. It accepts no destination override. The closed manifest binds
all sixteen files to fixed host paths, modes, sizes and SHA-256 digests. The
installer rejects an active daemon before install or upgrade, so clean up and
stop all sessions first. Its exact systemd actions have an empty environment,
discard subprocess output and are bounded. A failed file or activation step
rolls back; an unprovable rollback is exit 24 and requires operator inspection.

After installation, the same commands use the fixed root-owned installed
manifest for uninstall. Configuration, image cache, USB enrollment state and
user exports are preserved and are not accepted as removal-plan inputs.

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

Both native packages mark `/etc/private-vm/config.toml` as a non-replacing
configuration file. `/var/lib/private-vm` and user exports are not package-owned,
so an upgrade or ordinary removal cannot silently delete their contents.

## Uninstall

```bash
private-vm session cleanup --all
sudo private-vm system uninstall --dry-run
sudo private-vm system uninstall --accept
```

Uninstall must not delete image cache or configuration without separate flags.
It must never delete user exports.

For an ordinary package-manager removal, first run cleanup and explicitly stop
and disable `private-vmd.service`; the release acceptance VM proves no daemon
process remains after package removal. The generic Go uninstaller performs the
same bounded stop/disable operation as part of its reviewed transaction.
