# Scanning and sanitization

## Principles

- Treat antivirus as evidence, not proof.
- Treat every parser as vulnerable.
- Run parsing only in an offline disposable scanner.
- Promote reconstructed content rather than originals under safe policy.
- Reject uncertainty.

## Definition update boot

The scanner starts with network and no quarantine disk.

Required checks:

- Proton verified
- `freshclam` successful
- official databases present
- database timestamps within policy age
- engine/database compatibility
- no update error or rate-limit ambiguity

Then scanner shuts down. Its root overlay is retained only for the same session.

## Offline scan boot

The daemon launches the same scanner overlay:

- no `-netdev`
- no NIC device
- quarantine attached read-only
- guest verifies no non-loopback interfaces
- guest verifies block device read-only
- mount options `ro,nodev,nosuid,noexec`

A failure is non-overridable.

## Inventory

Before opening through desktop applications:

- recursively enumerate with `openat`-style safe traversal
- `lstat` every entry
- reject device nodes, sockets, FIFOs
- detect symlinks and hardlinks
- identify content with libmagic/file
- hash every regular file
- compare extension to type
- record sizes and paths

## ClamAV

Use a configured `clamd` Unix socket or one-time `clamscan`. `clamd` is preferred
for multiple files after definitions load.

Explicitly configure:

- official database only where required
- file-size limit above policy maximum
- scan-size limit above archive policy
- recursion depth
- archive scanning
- heuristic alerts
- encrypted-content alerts
- timeouts

The report parser treats:

- `FOUND` as reject
- errors as reject
- skipped due to max size as reject
- max scan size as reject
- timeout as reject
- encrypted alert as reject pending inspection
- process crash as reject

Never use automatic delete.

## Archive extraction

Extraction runs as a dedicated unprivileged user inside a private mount namespace
and bounded tmpfs.

Before extraction, list archive entries and reject:

- absolute paths
- traversal
- links escaping root
- device nodes
- excessive count
- excessive path length
- excessive declared size
- unsupported encryption

After extraction:

- verify actual tree
- enforce actual expanded size
- inventory and rescan
- recurse to policy depth
- delete temporary tree after report/output

## Reconstruction backends

### PDF

1. parse/rasterize pages inside scanner
2. cap page count and dimensions
3. write lossless or high-quality images
4. rebuild a new PDF
5. remove metadata
6. rescan output
7. verify page count
8. hash

Candidate tools: MuPDF or Poppler for rendering, img2pdf/qpdf for reconstruction.
Pin the exact toolchain in Nix.

### Office

1. render with LibreOffice headless to PDF
2. rasterize/rebuild PDF
3. reject conversion errors, macros that prevent rendering, or unsupported content
4. rescan output

### Images

1. decode fully
2. cap dimensions/pixels
3. strip EXIF/XMP/ICC unless explicitly retained
4. re-encode to PNG/JPEG according to policy
5. rescan

### Audio/video

1. probe in scanner only
2. cap streams/duration/resolution
3. full decode and re-encode with ffmpeg
4. remove metadata, attachments, and chapters
5. produce MP4/AAC-H.264 baseline or configured safe target
6. rescan output

### Plain text

- validate encoding
- reject NUL/binary mismatch
- normalize only when policy requests
- scripts remain blocked based on type and context

## Unsupported content

Under safe policy, unsupported formats are rejected. Do not silently copy the
original.

## Scan report

See `schemas/scan-report.schema.json`.

The report includes each tool version and exact decision reason. It remains
volatile unless the user explicitly exports it.
