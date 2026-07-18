# ADR 0001: NixOS is the canonical guest image source

- Status: Accepted
- Date: 2026-07-18

## Context

The project needs public, reviewable and reproducible workstation, downloader,
scanner and exporter images. Building interactive distribution installers through
Packer would duplicate configuration, require nested virtualization or slow
software emulation in CI, and make package state harder to audit.

## Decision

All release guest images are produced from pinned NixOS 26.05 module
configurations through Nix. Packer is permitted only as an optional acceptance
test harness around an already-built image.

## Consequences

- `flake.lock` becomes part of the release trust root.
- Every package and service in each image is declarative.
- Conventional Linux hosts consume the same prebuilt images from GHCR.
- The project must validate the exact Nix image output against the pinned
  Nixpkgs revision in task `NIX-001`.
