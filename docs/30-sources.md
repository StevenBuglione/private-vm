# Verified external sources

Verified on 2026-07-18.

## NixOS

- NixOS 26.05 release announcement:
  https://nixos.org/blog/announcements/2026/nixos-2605/
- NixOS 26.05 manual, image building:
  https://nixos.org/manual/nixos/stable/
- Nixpkgs `make-disk-image.nix`:
  https://github.com/NixOS/nixpkgs/blob/master/nixos/lib/make-disk-image.nix
- NixOS USBGuard module:
  https://github.com/NixOS/nixpkgs/blob/master/nixos/modules/services/security/usbguard.nix

## GitHub

- Standard public runner specifications and free/unlimited public use:
  https://docs.github.com/en/actions/how-tos/write-workflows/choose-where-workflows-run/choose-the-runner-for-a-job
- Container registry OCI support and anonymous public pulls:
  https://docs.github.com/en/packages/working-with-a-github-packages-registry/working-with-the-container-registry
- Artifact attestations:
  https://docs.github.com/actions/security-for-github-actions/using-artifact-attestations/using-artifact-attestations-to-establish-provenance-for-builds
- Secure use and action pinning:
  https://docs.github.com/en/actions/reference/security/secure-use

## QEMU/Linux

- QEMU command-line/SPICE options:
  https://qemu.readthedocs.io/en/v9.2.4/system/invocation.html
- QEMU QMP reference:
  https://qemu.readthedocs.io/en/master/interop/qemu-qmp-ref.html
- Linux VSOCK:
  https://docs.kernel.org/admin-guide/sysctl/net.html
- Go VSOCK package:
  https://pkg.go.dev/github.com/mdlayher/vsock

## Proton VPN

- WireGuard config generation:
  https://protonvpn.com/support/wireguard-configurations
- P2P and qBittorrent interface binding:
  https://protonvpn.com/support/bittorrent-vpn
- Port-forwarding considerations:
  https://protonvpn.com/support/port-forwarding

## Scanning and storage

- ClamAV scanning:
  https://docs.clamav.net/manual/Usage/Scanning.html
- USBGuard rule language:
  https://usbguard.github.io/documentation/rule-language.html
- cryptsetup LUKS format:
  https://www.man7.org/linux/man-pages/man8/cryptsetup-luksFormat.8.html
- ORAS Go:
  https://github.com/oras-project/oras-go

## Go

- Go downloads; current stable at verification was Go 1.26.5:
  https://go.dev/dl/

## Desktop

- Mozilla Firefox enterprise policy templates:
  https://mozilla.github.io/policy-templates/
- Mozilla Firefox crash reporter environment controls:
  https://firefox-source-docs.mozilla.org/toolkit/crashreporter/crashreporter/

External behavior can change. The implementation must pin dependencies and keep
source assumptions covered by CI rather than relying on this list indefinitely.
