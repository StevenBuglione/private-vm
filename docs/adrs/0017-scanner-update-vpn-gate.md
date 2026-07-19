# ADR 0017: scanner definition updates use the role-scoped VPN gate

## Status

Accepted

## Context

The scanner uses one retained root overlay for an online definition-update boot
and a later offline scan boot. Host endpoint filtering alone permits only the
Proton WireGuard endpoint; it is not evidence that the guest kill switch,
`proton0`, routes, DNS and bypass probes succeeded. An automatically started
FreshClam service or timer could also race guest VPN configuration.

## Decision

`ScannerGuestService` additively exposes the same typed
`ConfigureWireGuard` and `VerifyVPN` messages used by the other online roles.
Only the scanner-compiled service registers those methods. The update QEMU boot
uses the shared `StartNetworked` owner and cannot expose its scanner client to
the definition workflow until authenticated Hello, guest configure and verify,
host egress proof and loss-monitor startup all succeed.

The scanner image disables the automatic ClamAV updater and timer. It contains
one fixed, non-wanted definitions-update oneshot for the serialized guestd
adapter; the offline specialization disables that unit entirely. The update
device graph has a NIC and no quarantine. After bounded shutdown and absence
audit, the same root overlay is booted with `-nic none` and exactly one
read-only quarantine disk.

## Consequences

- No definition request can run on a merely host-filtered underlay.
- Scanner update loses connectivity by retaining the guest kill switch and by
  powering off through the same VPN-loss response owner.
- Offline scanner images still advertise the compiled role API, but QEMU
  supplies no NIC and VPN configuration therefore cannot succeed.
- Scanner manifests add `wireguard-config` and `vpn-verification` capabilities;
  schemas, image checks and generated protobufs change together.
- Destination promotion remains a separately composed semantic relay and fails
  closed until a workstation or exporter owner verifies the complete stream.
