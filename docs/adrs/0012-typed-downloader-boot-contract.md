# ADR 0012: Typed downloader boot contract

## Status

Accepted for frozen v1.

## Context

The host network owner allocates a private point-to-point underlay, while the
guest owns the kill switch, WireGuard tunnel, controlled leak probes and local
qBittorrent process. The prior guest RPC carried only the WireGuard profile,
so a production guest controller had no authenticated way to receive its
host-selected underlay or operator-controlled probe fixtures. A runtime role
selector, environment variable, command argument or configuration file would
either weaken role identity or create a disclosure/persistence path.

## Decision

`ConfigureWireGuardRequest` carries closed typed messages for the private IPv4
and IPv6 underlay and for the controlled DNS/IPv4/IPv6 probe fixtures. IP
addresses are canonical byte strings with separately bounded prefix lengths
and ports. The authenticated downloader service validates these values before
creating its single VPN controller. It accepts that creation only once.

The fields are request-only. They are not represented in status, errors,
events, logs or durable state. The WireGuard profile remains a separately
bounded byte field which is cleared on every return path. The daemon remains
the only component allowed to derive the underlay from its network lease.

## Consequences

- Guest network composition can be concrete without argv, environment, disk or
  TCP transport.
- The host and guest use one typed underlay rather than independently guessing
  addresses.
- Probe fixture deployment remains an operator/release acceptance concern, but
  the guest refuses missing, private, special-use or malformed targets.
- This is a protocol-minor-compatible additive protobuf change; older guests
  fail the new required semantic validation instead of silently using defaults.
