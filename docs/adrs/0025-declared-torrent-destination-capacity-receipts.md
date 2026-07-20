# ADR 0025: Declared torrent destination capacity receipts

## Status

Accepted for frozen v1.

## Context

Payload selection must prove capacity for quarantine download, scanner
handoff/read-only scan, reconstruction scratch and the eventual destination.
The original production downloader measured one quarantine `statfs` value and
copied it into every stage. That was not evidence for the scanner or receiver,
and the destination was not declared until after download.

The first receipt implementation exposed a second fail-closed inconsistency:
the general 4 GiB session margin was charged independently to the scanner's
fixed 512 MiB tmpfs. No selection could pass even though small bounded inputs
fit the production scanner.

The host may not mount any of these guest filesystems. RPCs also may not expose
paths, device nodes, mount points, endpoints or arbitrary runtime selectors.

## Decision

`torrent select` requires a closed workstation-or-USB destination enum before
payload transfer. On every selection the daemon creates a versioned numeric
capacity receipt from independent immutable role plans. The authenticated
guest receives that receipt over VSOCK, re-probes its own quarantine free bytes
and performs the checked four-stage plan. The receipt contains no filesystem or
runtime selector.

Quarantine, read-only scan, reconstruction scratch and destination use separate
10-percent margins with 64 MiB floors. The max(10%, 4 GiB) reserve applies only
to the aggregate session estimate. The frozen production scanner contract keeps
the tmpfs at 512 MiB and caps selected input at 128 MiB, cumulative archive
expansion at 128 MiB, reconstruction working bytes at 192 MiB and one output at
96 MiB. The runtime uses these same limits, stops after one candidate output
and leaves bounded scratch headroom.

Missing, zero or unavailable evidence fails closed with
`TORRENT_CAPACITY_EVIDENCE_UNAVAILABLE`. Naming USB does not invent capacity
before an enrolled destination provides it. Selection may be repeated only by
recomputing both daemon evidence and guest quarantine capacity.

## Consequences

- No quarantine `statfs` result can stand in for scanner, reconstruction or
  destination capacity.
- Small safe selections can pass on the 16 GiB supported host without raising
  guest RAM or the scanner tmpfs.
- Oversized input, expansion, working-set or destination requirements fail
  before payload transfer.
- The host continues to treat every guest filesystem as opaque.
- Callers must choose the intended destination earlier in the workflow.
- A destination integration must provide typed capacity evidence before it can
  admit payload; unsupported destinations remain safely unavailable.
