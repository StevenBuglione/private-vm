# ADR 0012: Daemon-owned scanner handoff and promotion

- Status: Accepted
- Date: 2026-07-19

## Context

The frozen guest protocol already exposes the role-restricted scanner phases,
but the host daemon had no semantic API connecting a sealed downloader to a
distinct scanner session. Calling the scanner guest directly from the CLI would
bypass Unix peer authorization, session ownership, the single workflow owner,
QEMU device policy and authenticated-report verification. Reusing generic role
start would also be insufficient: the scanner must boot the same overlay twice
with mutually exclusive device graphs.

The quarantine begins in a downloader-owned encrypted storage domain. Scanning
requires an exclusive read-only lease without giving the scanner a second
cleanup owner for the underlying storage or permitting downloader cleanup to
invalidate a live scanner.

## Decision

`private-vmd` exposes five scanner operations: start, status, aggregate report,
approve and reject. `start` accepts only an owned, active downloader in
`QUARANTINE_SEALED`; it creates a separate scanner session and serializes the
complete update-to-offline workflow. The daemon API exposes only aggregate
counts and stable codes. Canonical report JSON, names, hashes, finding
identifiers, guest tokens, paths and runtime device details remain behind the
daemon.

The injected scanner runtime must atomically acquire an exclusive sealed-
quarantine lease for the scanner cleanup owner. The source downloader remains
locked during acquisition and scanning, and generic abort/cleanup admission is
serialized by the same per-session operation lock. The runtime contract must
prove that downloader cleanup cannot invalidate the lease and that only the
scanner cleanup owner releases it.

The daemon performs these ordered gates:

1. preflight and scanner image verification;
2. scanner storage plus exclusive quarantine lease registration;
3. update VM with Proton networking and no quarantine;
4. definition update, freshness evidence and update VM shutdown;
5. same-overlay offline VM with no NIC and read-only quarantine;
6. guest isolation verification, inventory, scan and reconstruction;
7. volatile report-MAC verification and aggregate report publication;
8. explicit promotion to one fresh workstation or enrolled USB, or rejection;
9. VM stop and idempotent reverse-order cleanup with absence audits.

The production guest relay accepts only a scanner client that completed the
authenticated VSOCK Hello handshake and attaches the per-boot token in gRPC
metadata. It retains a verified report only in daemon memory so a rejected VM
can be stopped before user inspection. Promotion is reported successful only
after the destination relay and end-to-end hash proof finish.

## Consequences

- The CLI never dials VSOCK and cannot select devices, paths, QEMU arguments or
  output identifiers.
- Update and offline VM resources have separate registered cleanup steps while
  the retained overlay and quarantine lease have one scanner-session owner.
- A missing runtime adapter, report verifier, promotion relay or absence audit
  fails closed; it is not represented as a successful scanner check.
- Implementations must test source-cleanup races, cancellation, timeout,
  scanner/QEMU death and failed absence audits before live scanner acceptance.
- Adding another scan destination or exposing report detail requires a new
  protocol/schema review; arbitrary paths remain prohibited.
