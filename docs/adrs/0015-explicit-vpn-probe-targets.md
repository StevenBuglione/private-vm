# ADR 0015: Explicit controlled VPN probe targets

## Status

Accepted for frozen v1.

## Context

The guest VPN verifier must prove DNS, IPv4 and IPv6 tunnel reachability and
underlay blocking against controlled public fixtures. ADR 0013 correctly
forbids the guest from inventing targets, but the host configuration previously
had no typed source for them. A hidden constant at the VSOCK boundary would be
hard to audit or replace, while environment or command-line values would create
unreviewed process metadata.

## Decision

The immutable non-secret `[vpn]` configuration contains one bounded DNS name
and exact public global-unicast IPv4 and IPv6 address/port targets. Defaults use
Cloudflare's documented `one.one.one.one`, `1.1.1.1:853` and
`[2606:4700:4700::1111]:853` DNS-over-TLS endpoints. Operators may replace all
three values in reviewed TOML.

The reviewed endpoint source is Cloudflare's official
[`1.1.1.1` DNS-over-TLS documentation](https://developers.cloudflare.com/1.1.1.1/encryption/dns-over-tls/).

The daemon validates the values at configuration load, converts them once to
`guestvpn.ProbeTargets`, and passes them only inside the authenticated VSOCK
configure request. The guest validates them independently. Status, events,
errors and logs cannot return the targets.

## Consequences

- Production online-role composition has a complete, testable target source.
- Leak checks can be moved to operator-owned infrastructure without rebuilding.
- The configuration is intentionally non-secret; changing a target requires a
  daemon restart and cannot affect an already-started session.
- Availability of the selected third-party fixture is an operational
  dependency. Failure blocks online readiness rather than weakening the check.
