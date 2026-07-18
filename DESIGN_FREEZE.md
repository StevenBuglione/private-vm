# Design freeze for v1

This file distinguishes settled requirements from implementation choices that
may change without reopening the product design.

## Non-negotiable v1 requirements

- Four separate guest roles: workstation, downloader, scanner and exporter.
- Workstation, downloader and scanner are graphical XFCE environments.
- Exporter is headless, networkless and is the only role with USB access.
- Sessions use direct QEMU/KVM and immutable NixOS base images.
- Every root is disposable; no session resumes after host reboot.
- Large scratch data is encrypted with a random per-session key held only in
  volatile state.
- The host never mounts guest, quarantine or transfer-USB filesystems.
- Online guests have host- and guest-layer VPN-only egress enforcement.
- qBittorrent is bound to `proton0`.
- Scanning occurs offline with quarantine attached read-only.
- Safe policy rejects malware, errors, skipped content and unsupported active
  content, and promotes only reconstructed output.
- Official images require digest and provenance verification.
- Product logic is Go or Nix, not shell.
- No telemetry and no intentional persistent plaintext session details.

## Decisions that require an ADR change

- Guest operating system
- hypervisor/runtime manager
- desktop protocol
- number or responsibilities of guest roles
- host/guest RPC transport
- trust model for official images
- USB ownership model
- persistence guarantees
- default scanner approval policy

## Deferrable implementation details

- Cobra versus another Go CLI parser
- gRPC codec tuning and chunk size
- exact local status-panel toolkit
- optional Plasma image
- optional audio backend
- exact OCI compression settings
- package build system for deb/rpm
- optional encrypted-bundle output after USB v1 works

A coding agent must not simplify a non-negotiable requirement merely to reach a
demo. It may sequence features through milestones, but the public interface must
not imply missing security controls are active.
