# ADR 0019: Authenticated scanner-to-fresh-workstation relay

- Status: Accepted
- Date: 2026-07-19

## Context

ADR 0012 reserves scanner promotion for a semantic daemon-owned destination
operation. The implementation now has to connect the scanner guest's
`ExportApprovedFile` stream to a newly created workstation guest's `ImportFile`
stream without a host path, shared filesystem, host mount or second owner for
either session. The scanner report can describe several reconstructed outputs,
but the v1 CLI deliberately exposes neither names nor output IDs.

Starting the workstation only after destroying the scanner is incompatible
with a direct volatile stream unless the host persists plaintext. The earlier
wording is therefore refined: the destination VM may overlap the scanner only
as the authenticated receiver, but no viewer or destination session ID is
released until transfer verification and scanner destruction finish.

## Decision

For `scan approve --open-in workstation`, `private-vmd` creates a new
workstation session through the normal strict preflight, plan, image, storage,
runtime and session-actor path. It does not accept a caller-supplied destination
session. The destination remains unadvertised while the relay runs.

Safe v1 workstation promotion requires the complete authenticated approved
report to contain exactly one sanitized output. This is the selected output;
zero or multiple outputs fail closed because the v1 CLI has no safe output
selector. The host requests only that opaque report output ID from the scanner
guest. The scanner validates the volatile report MAC again and emits a bounded
begin/chunk/end stream. The daemon requires the begin descriptor and sender end
digest to equal the report, independently hashes the relayed bytes, assigns a
fresh workstation transfer ID, and requires the workstation's receiver receipt
to match the same size and SHA-256.

The relay is one-way and in-memory. It has no host pathname, mount operation,
generic guest client, arbitrary output ID or device control. The workstation
is destroyed through its session cleanup owner after any creation, relay,
framing, hash, scanner-stop or scanner-cleanup failure. On success, the scanner
is stopped and cleaned first; only then does the daemon return the fresh
destination session ID and the CLI launches the user-owned viewer over the
existing private Unix SPICE socket.

## Consequences

- The scanner and destination overlap briefly, but no viewer is connected and
  the destination is not externally identified during that overlap.
- Scanner sender, daemon relay and workstation receiver must all prove the same
  SHA-256 and byte count before approval succeeds.
- A report with multiple sanitized outputs must be narrowed by a future typed
  selection protocol; v1 does not guess or reveal an output.
- Viewer launch failure does not invalidate an already verified promotion. The
  active session can be found with `session list` and opened with
  `desktop connect`.
- USB promotion remains a separate exporter-owned destination and receives no
  workstation session snapshot.
