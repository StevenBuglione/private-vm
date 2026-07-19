# ADR 0013: Role-scoped online guest VPN RPCs

## Status

Accepted for frozen v1.

## Context

The host orchestrator starts both workstation and downloader roles through the
same typed network lifecycle. The authenticated configure and verify methods
were present only on `DownloaderGuestService`. Registering that service in a
workstation would violate exact role capability registration, while omitting
the methods leaves the workstation host lifecycle unable to install its guest
kill switch and tunnel.

## Decision

Add `ConfigureWireGuard` and `VerifyVPN` to `WorkstationGuestService` without
moving or deleting the downloader methods. Both services use the same bounded
request and boolean-only status types. Guestd decorates the existing workspace
owner with a reusable network lifecycle fixed to workstation policy. The
downloader remains separately composed with its torrent controller and gated
qBittorrent owner.

Guestd registers exactly the generated service for its compiled role. A
workstation therefore exposes no downloader torrent method, and a downloader
exposes no workspace method. The host selects the generated client from the
already verified guest role; there is no runtime role selector inside either
guest handler.

## Consequences

- Both online roles can satisfy one host orchestration interface over
  authenticated AF_VSOCK without a generic network RPC or TCP service.
- Typed underlay/profile clearing and one-time controller creation remain
  identical across roles.
- Workstation images require systemd-resolved, WireGuard tooling and a narrowly
  expanded guestd network capability set.
- This is additive at the protobuf service level. Existing downloader clients
  retain the same method paths and message types.
