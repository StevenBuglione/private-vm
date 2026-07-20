# ADR 0024: Declared torrent destination capacity receipts

## Status

Accepted for frozen v1.

## Context

Payload selection must prove capacity for quarantine download, scanner
handoff/read-only scan, reconstruction scratch and the eventual destination.
The original production downloader measured one quarantine `statfs` value and
copied it into every stage. That was not evidence for the scanner or receiver,
and the destination was not declared until after download.

The host may not mount any of those guest filesystems. RPCs also may not expose
paths, device nodes, mount points, endpoints or arbitrary runtime selectors.

## Decision

`torrent select` requires a closed workstation-or-USB destination enum before
payload transfer. On every selection the daemon creates a versioned numeric
capacity receipt from independent immutable role plans. The authenticated
guest receives that receipt over VSOCK, re-probes its own quarantine free bytes
and performs the checked four-stage plan. The receipt contains no filesystem or
runtime selector.

Missing, zero or unavailable evidence fails closed with
`TORRENT_CAPACITY_EVIDENCE_UNAVAILABLE`. In particular, naming USB does not
invent capacity before an enrolled destination provides it. Selection may be
repeated only by recomputing both daemon evidence and guest quarantine
capacity.

## Consequences

- No quarantine `statfs` result can stand in for scanner, reconstruction or
  destination capacity.
- The host continues to treat every guest filesystem as opaque.
- Callers must choose the intended destination earlier in the workflow.
- A destination integration must provide typed capacity evidence before it can
  admit payload; unsupported destinations remain safely unavailable.
