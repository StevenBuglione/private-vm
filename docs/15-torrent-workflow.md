# Torrent workflow

## Input privacy

Preferred:

```bash
private-vm run torrent
```

Then read magnet without terminal echo.

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

Conservative formula:

```text
session_required =
  root_overlay_budget
+ selected_download_bytes
+ filesystem_overhead
+ archive_expansion_budget
+ reconstruction_budget
+ safety_margin
```

Default safety margin: max(10%, 4 GiB).

For unknown archive expansion, use policy maximum rather than compressed size.

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
