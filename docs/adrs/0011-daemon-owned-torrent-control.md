# ADR 0011: Daemon-owned semantic torrent control

- Status: Accepted
- Date: 2026-07-19

## Context

The frozen guest protocol already exposes downloader methods, while the host
daemon protocol originally exposed only generic role lifecycle and workspace
transfer methods. Connecting the CLI directly to guest VSOCK would bypass Unix
peer authorization, per-session ownership and the one workflow-transition
owner. Reusing workspace transfer would also erase the distinct security
meaning and bounds of torrent input.

## Decision

`private-vmd` exposes a narrow torrent service surface: bounded input,
metadata, selection, start/resume, pause, status and seal. Each request names
one daemon-owned active downloader session. The daemon serializes admission and
workflow transitions; an injected `TorrentOrchestrator` may only relay those
semantic operations to the already authenticated guest. It receives no raw
commands, URLs, save paths, guest tokens, QEMU arguments or device selectors.

Torrent input uses one contextual begin frame followed by non-empty chunks no
larger than 16 KiB. The daemon streams synchronously without whole-input
buffering. Metadata and guest responses may traverse volatile authenticated
RPC, but CLI machine output is aggregate-only and omits torrent names, paths,
hashes and identifiers.

## Consequences

The CLI can no longer require a process-local injected submitter in production
and never dials VSOCK. A concrete daemon role runtime must still supply the
authenticated guest client and exact downloader cleanup proof; absent that
provider, the daemon returns `NOT_IMPLEMENTED` and does not weaken the boundary.
Failure after a workflow transition invokes the session cleanup owner. Download
stream cancellation converges on the paused state before returning.

