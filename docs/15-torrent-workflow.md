# Torrent workflow

## Input privacy

Preferred:

```bash
private-vm run torrent
```

Then read magnet without terminal echo.

The explicit equivalent is `private-vm torrent add --magnet-tty`. Official
builds do not accept a magnet value in argv.

Automation:

```bash
printf '%s' "$MAGNET" | private-vm torrent add --magnet-stdin
```

`.torrent` files are imported through explicit bounded stream. The host computes a
hash but does not parse the file.

## Downloader setup

- verified downloader image
- fresh root overlay
- encrypted quarantine disk
- Proton-only network
- qBittorrent save path fixed to quarantine
- no alternate paths
- guestd confirms qBittorrent interface binding

The downloader image and Go controller share the fixed mount
`/mnt/quarantine`; payload is restricted to `/mnt/quarantine/payload`.

## Metadata-only stage

qBittorrent receives torrent paused. The guest waits for metadata but leaves all
file priorities at zero or download paused.

Return:

- display name, redacted in persistent contexts
- info hash
- total size
- files and relative paths
- file sizes
- suspected type from filename
- dangerous path/type flags
- piece size/count
- tracker count without persisting URLs
- free-space requirements

## Selection safety

Reject metadata containing:

- absolute paths
- `..`
- NUL
- Windows device names where destination semantics matter
- path count/length beyond limits
- duplicate normalized paths
- case-collision hazards
- selected bytes above policy maximum

Executable types are shown as blocked under safe policy before download.

## Capacity planning

Conservative stage formulas:

```text
quarantine_required = selected + filesystem_overhead + quarantine_margin
scan_required = selected + scan_margin
reconstruction_required = archive_expansion + reconstruction_work + scratch_margin
destination_required = maximum_output + filesystem_overhead + destination_margin
session_required = root_overlay + quarantine_required + reconstruction_required + session_margin
```

Quarantine, scan, reconstruction and destination margins are each 10 percent
with a 64 MiB floor. The aggregate session reserve remains max(10%, 4 GiB), but
it is not charged again against the 512 MiB scanner scratch stage.

For unknown archive expansion, use policy maximum rather than compressed size.
The safe policy's general upper bounds remain 4 GiB per regular file and 4 GiB
of expanded archive work. The 512 MiB production scanner is deliberately more
restrictive: capacity admission and runtime both cap selected input at 128 MiB,
cumulative archive expansion at 128 MiB and one reconstructed output at 96 MiB.
The reconstruction working budget is 192 MiB for one intermediate plus one
final output; later candidate outputs are rejected before allocation.

## Download

- qBittorrent remains bound to `proton0`
- VPN monitor pauses on failure
- guestd reports progress without persisting names
- no auto-open
- no completion hook
- no seeding after completion by default
- optional seeding requires a separate future policy; not v1

## Completion

1. pause torrent
2. force filesystem sync
3. verify selected files exist and sizes match metadata
4. hash files
5. stop qBittorrent
6. unmount quarantine in guest
7. power off downloader
8. detach disk
9. mark quarantine sealed
10. destroy downloader overlay

The scanner never shares a running session with downloader.

## Implemented source contract

TOR-001 through TOR-003 are implemented in the source boundary as follows:

- magnet input is strict `magnet:?` with exactly one canonical BTIH topic,
  capped at 8 KiB, read through hidden terminal or owned stdin, and destroyed
  after the synchronous authenticated handoff;
- `.torrent` input is a no-follow local regular-file stream capped at 16 MiB;
  the CLI never parses it or sends its source path onward;
- guest streaming accepts one input kind, 16-KiB chunks, at most 1,024 frames
  and one final marker, detaching and clearing every protobuf chunk;
- the CLI-to-daemon stream starts with one contextual input-kind frame and ends
  at stream EOF; the daemon never buffers the complete magnet or metainfo and
  relays only through its typed authenticated downloader orchestrator;
- the qBittorrent API origin and save path are compiled constants, additions
  are paused, metadata requires zero payload bytes and all file priorities are
  reset to zero before selection;
- path traversal, absolute/backslash paths, Windows device names, excessive
  counts/lengths, Unicode-normalized duplicates and case collisions reject;
  executable/script/package/disk-image suffixes are blocking in safe policy;
- selection re-probes encrypted-quarantine free bytes in the downloader guest
  and combines them with separate daemon-attested scanner handoff,
  reconstruction-scratch and declared-destination limits. It recalculates all
  stages with checked arithmetic and stage-specific margins before every
  selection; the 4 GiB floor applies only to aggregate session headroom and no
  stage is populated by copying another stage's `statfs`;
- cancellation, timeout, stream failure, stall and typed VPN loss force a
  bounded pause attempt; completion verifies exact selected regular files and
  hashes before qBittorrent shutdown and quarantine sync/unmount;
- a scanner-ready receipt exists only after the host cleanup owner proves the
  downloader absent. Failed absence audits are retryable without resealing.

The host daemon owns semantic add, metadata, selection, start/resume, pause,
status and seal RPCs. It accepts them only for the caller's active downloader,
serializes workflow admission, pauses on interrupted download streams, and
invokes the independent session cleanup owner when a post-admission metadata
operation fails. CLI machine output is aggregate-only and cannot represent
torrent names, file paths, identifiers or hashes.

The focused source suite uses only synthetic values and an in-memory
qBittorrent HTTP fixture. Live qBittorrent version/configuration, encrypted
quarantine block I/O, VPN packet loss, QEMU destruction and scanner attachment
remain system acceptance gates; source tests do not report those gates as
passed.

The production daemon composition supplies the authenticated VSOCK downloader
client, exact QEMU/quarantine cleanup owner and a typed downstream-capacity
source. `torrent select` requires `--destination`; missing evidence and the USB
destination before enrollment/capacity attestation fail closed with
`TORRENT_CAPACITY_EVIDENCE_UNAVAILABLE`. The host never opens or mounts the
opaque quarantine, scanner or destination filesystem while creating this
receipt.
