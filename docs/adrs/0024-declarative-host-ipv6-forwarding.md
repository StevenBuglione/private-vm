# ADR 0024: Declarative host IPv6 forwarding prerequisite

## Status

Accepted for frozen v1.

## Context

The daemon routes each online guest through a private network namespace and an
owned veth pair. An isolated Linux integration test proved that IPv4 forwarding
works while the outer host's `net.ipv4.ip_forward` remains `0`, because the
daemon enables forwarding only on its owned host veth. The same test proved
that IPv6 packets do not traverse the outer namespace when forwarding is
enabled only on that veth, the namespace veth, and the TAP. The minimal outer
setting that permits the exact IPv6 Proton endpoint tuple is
`net.ipv6.conf.all.forwarding=1`.

Changing a host-global sysctl dynamically during session allocation would give
a session cleanup owner responsibility for pre-existing host policy and could
alter Router Advertisement behavior on unrelated uplinks. Failing to declare
the prerequisite would make the dual-stack contract depend on undocumented
host state.

## Decision

The NixOS host module declaratively sets and asserts
`net.ipv6.conf.all.forwarding=1`. Distribution packages must install the
equivalent static sysctl fragment. Doctor checks the active kernel value
read-only and blocks when it is unavailable or not exactly `1`; the daemon
never changes the host-global value. Operators remain responsible for
declarative uplink and Router Advertisement configuration and must verify host
IPv6 after activation.

The daemon keeps the outer global IPv4 forwarding switch disabled and enables
IPv4 forwarding only on its private-vm-owned host veth. Namespace-local IPv4
and IPv6 forwarding remain session-owned and are destroyed with the namespace.

## Consequences

- Dual-stack forwarding has an explicit, testable host prerequisite instead of
  silently succeeding only on some hosts.
- Session cleanup never has to restore host-global network state.
- NixOS and distribution-package installations converge on the same active
  requirement.
- Host IPv6 Router Advertisement behavior may change when the module activates;
  installation and recovery guidance must call this out and verify connectivity.
- Future removal of the global setting requires a live Linux proof and a new
  ADR describing bounded ownership of every replacement mutation.
