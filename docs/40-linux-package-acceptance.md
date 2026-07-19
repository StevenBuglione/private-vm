# Linux package acceptance

## Source contract

`packaging/packages/linux-package.json` is the closed package-content and
dependency contract for the Debian/Ubuntu and Fedora/RHEL artifacts. The Nix
derivations in `nix/linux-packages.nix` translate it to nFPM input and expose
`packages.x86_64-linux.deb` and `packages.x86_64-linux.rpm`.

The package specification owns only immutable program and integration files.
It intentionally does not own `/run/private-vm`, `/var/lib/private-vm`, the
image cache, ciphertext scratch, user exports or a USBGuard enrollment rule.
The daemon configuration is mode `0600` with `config|noreplace` semantics.

There are no package lifecycle scripts or shell hooks. Group creation uses the
declarative systemd-sysusers entry, while directory creation and modes use the
declarative systemd-tmpfiles entry. Enabling, stopping and disabling the service
is an explicit administrator operation or a transaction performed by the
bounded Go generic installer; package hooks never orchestrate a live session.

Validate the source boundary without building packages:

```bash
nix develop --offline --command python3 tools/check_packaging_assets.py
nix eval --raw .#deb.drvPath
nix eval --raw .#rpm.drvPath
```

## Required clean-system matrix

Each release candidate must build the two artifacts once, then copy the same
immutable artifact by digest into a fresh VM for every row:

| Guest | Artifact | Install command | Required dependency names |
| --- | --- | --- | --- |
| Ubuntu supported LTS | DEB | `apt install ./private-vm.deb` | Debian override in the package contract |
| Debian current stable | DEB | `apt install ./private-vm.deb` | Debian override in the package contract |
| Fedora current | RPM | `dnf install ./private-vm.rpm` | RPM override in the package contract |

For each row, the verifier must record redacted JUnit/JSON evidence for:

1. package metadata, SHA-256 and SPDX verification before installation;
2. declared dependency resolution from the clean distribution repositories;
3. exact regular-file destinations, owners and modes, with no unexpected path;
4. one `private-vm` sysusers group, tmpfiles modes, candidate-only udev rule and
   exactly one Polkit action (`org.private-vm.usb.prepare`);
5. completions and both manual pages;
6. daemon start, socket owner/group/mode and `doctor --strict --json`;
7. upgrade from the previous supported release while a sentinel configuration
   and image-cache file retain their hashes;
8. cleanup, service stop/disable and package removal, followed by proof that no
   `private-vmd` process or unit is active; and
9. preservation of configuration, image cache and user exports until an
   independently confirmed purge operation exists.

The distribution VMs, actual dependency resolution, package-manager upgrade,
systemd activation and removal gates are system evidence. Derivation evaluation
and the source validator do not claim those gates passed.
