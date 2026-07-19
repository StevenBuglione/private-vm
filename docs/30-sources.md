# Verified external sources

Verified on 2026-07-18. IMG-003 Sigstore and REL-003 GitHub/OCI details were
rechecked on 2026-07-19.

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
  (4 CPU, 16 GB RAM, 14 GB SSD and the `ubuntu-24.04` label rechecked
  2026-07-19)
- Container registry OCI support and anonymous public pulls:
  https://docs.github.com/en/packages/working-with-a-github-packages-registry/working-with-the-container-registry
  (new container packages default private; anonymous pull requires public
  visibility, rechecked 2026-07-19)
- Artifact attestations:
  https://docs.github.com/actions/security-for-github-actions/using-artifact-attestations/using-artifact-attestations-to-establish-provenance-for-builds
- `actions/attest` inputs and `bundle-path` output:
  https://github.com/actions/attest
- Artifact attestations REST API (current DSSE/Rekor bundle example):
  https://docs.github.com/rest/orgs/orgs#list-attestations
- Deployment environments and protection rules:
  https://docs.github.com/en/actions/reference/workflows-and-actions/deployments-and-environments
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

## Address policy

- IANA IPv4 Special-Purpose Address Registry:
  https://www.iana.org/assignments/iana-ipv4-special-registry/
- IANA IPv6 Special-Purpose Address Registry:
  https://www.iana.org/assignments/iana-ipv6-special-registry/
- IANA IPv6 Global Unicast Address Space:
  https://www.iana.org/assignments/ipv6-unicast-address-assignments/

## Scanning and storage

- ClamAV scanning:
  https://docs.clamav.net/manual/Usage/Scanning.html
- USBGuard rule language:
  https://usbguard.github.io/documentation/rule-language.html
- cryptsetup LUKS format:
  https://www.man7.org/linux/man-pages/man8/cryptsetup-luksFormat.8.html
- ORAS Go:
  https://github.com/oras-project/oras-go
- ORAS push/pull model:
  https://oras.land/docs/how_to_guides/pushing_and_pulling
- OCI image manifest specification:
  https://github.com/opencontainers/image-spec/blob/main/manifest.md

## Go

- Go downloads; current stable at verification was Go 1.26.5:
  https://go.dev/dl/
- sigstore-go v1.2.2 release and API, pinned at commit
  `55aa6240784677449a564e66a0fca7a6a3605ecd`:
  https://github.com/sigstore/sigstore-go/releases/tag/v1.2.2

The embedded public-good root is copied from sigstore-go v1.2.2
`examples/trusted-root-public-good.json` as
`internal/image/trust/sigstore-public-good-trusted-root-v1.2.2.json`; its
SHA-256 is `4364d7724c04cc912ce2a6c45ed2610e8d8d1c4dc857fb500292738d4d9c8d2c`.
Updating it requires a reviewed pinned sigstore-go release and current Sigstore
public-good TUF target, comparison of Fulcio/CT/Rekor keys and validity windows,
an updated filename/embed/hash/source record, all cryptographic/offline tests,
`go mod tidy -diff`, and regenerated `vendor/`. Runtime network replacement of
the trust snapshot is forbidden.

## Desktop

- Mozilla Firefox enterprise policy templates:
  https://mozilla.github.io/policy-templates/
- Mozilla Firefox crash reporter environment controls:
  https://firefox-source-docs.mozilla.org/toolkit/crashreporter/crashreporter/

External behavior can change. The implementation must pin dependencies and keep
source assumptions covered by CI rather than relying on this list indefinitely.
