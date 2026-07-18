# ADR 0006: Enforce VPN-only egress at host and guest layers

- Status: Accepted
- Date: 2026-07-18

## Decision

Each Internet-enabled guest gets a dedicated host network namespace and TAP.
Host nftables allows its clear-network egress only to the resolved Proton
WireGuard endpoint and required bootstrap traffic. Inside the guest, nftables
permits application traffic only over `proton0`. qBittorrent is additionally
bound to `proton0`.

## Consequences

A failed guest firewall does not create direct Internet access, and a failed host
rule does not bypass the guest kill switch. Any leak-test failure blocks the run.
