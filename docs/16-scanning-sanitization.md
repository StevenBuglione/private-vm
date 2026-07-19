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
The image has no automatic FreshClam timer or boot-started updater. The daemon
exposes the definitions client only after the typed scanner VPN configure and
verify RPCs plus host egress proof succeed. The fixed updater oneshot is
reserved for the serialized guestd `UpdateDefinitions` adapter.

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
after definitions load, but guestd submits and accounts for one regular file at
a time; recursive directory and multi-file batch submissions are forbidden.

Explicitly configure:

- official database only where required
- a 4 GiB ClamAV file-size ceiling matched exactly by
  `limits.max_single_file_bytes`
- a 4 GiB ClamAV scan-size ceiling matched by the maximum total expanded
  archive work
- recursion depth
- archive scanning
- heuristic alerts
- encrypted-content alerts
- a 300-second ClamAV one-file invocation ceiling matched by
  `limits.scan_timeout_seconds`

`limits.max_input_bytes` is the cumulative selected/quarantine-capacity bound;
it may be larger than 4 GiB only when every individual regular file remains at
or below `max_single_file_bytes`. `scan_timeout_seconds` bounds each one-file
ClamAV invocation, including process/RPC completion; the same ceiling is set as
ClamAV's internal per-file limit. The complete inventory, reconstruction and
report workflow has a separate bounded orchestration deadline and cannot
reinterpret this field as an unbounded session allowance.

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

The sum of all expanded archive members and temporary archive work is bounded
to `limits.max_expanded_bytes`, which is at most 4 GiB in v1 even when the
encrypted quarantine contains a larger cumulative selection.

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

## Host orchestration

The CLI sends scanner intent only to `private-vmd` over the Unix control socket.
The daemon accepts a source only after downloader QEMU absence and
`QUARANTINE_SEALED` evidence. It creates a distinct scanner session, acquires an
exclusive sealed-quarantine lease, and registers storage, update-runtime and
offline-runtime cleanup before advancing their states.

The update VM has networking and no quarantine. After current definitions are
verified it is stopped. The offline VM reuses the exact overlay, has no NIC and
receives the quarantine read-only. Guestd must independently verify no network,
block read-only state and `ro,nodev,nosuid,noexec` mount options before content
operations. The daemon relays the role-specific guest service over authenticated
VSOCK, verifies the canonical report MAC and exposes only aggregate report data
to the CLI.

Approval is a destination operation, not a label. It succeeds only after one
documented workstation or USB relay verifies its integrity. Rejection stops the
scanner without invoking promotion. Both paths finish through the scanner
session's idempotent cleanup owner.

The immutable scanner image embeds its direct parser/reconstruction package
versions in `/etc/private-vm/scanner-toolchain.json` and repeats those identities
in `/etc/private-vm/scanner-sbom.spdx.json`. A missing, empty or mismatched entry
is an image-build failure; the scanner workflow must copy the verified versions
into the eventual scan report rather than probing an untracked host tool.

## Source implementation contract

`internal/scan` owns the scanner security decisions; it does not delegate them
to shell. The update receipt binds current official ClamAV evidence to one
opaque scanner-overlay identity. The offline verifier requires that same
overlay, no non-loopback interface, one read-only quarantine attachment and
the exact sorted mount options `nodev,noexec,nosuid,ro`.

Inventory uses descriptor-relative Linux traversal with `openat2` beneath the
quarantine root. It never follows links, crosses a mount boundary or invokes a
classifier with a filename. Regular files are reopened and compared by
device/inode/mode/size, hashed completely and checked again after the read.
Symlinks, multiple hard links, devices, sockets, FIFOs, replacements and any
count/byte/path uncertainty reject the scan.

ClamAV content is sent with bounded `INSTREAM` frames over its Unix socket.
Only a strict NUL-terminated `stream:` verdict is accepted. `FOUND`, encrypted
content, skipped/unreadable files, scan limits, timeouts, protocol ambiguity and
transport errors are blocking. Raw clamd responses are never returned or
logged.

ZIP and TAR manifests are validated before extraction. Absolute/traversing,
duplicate, encrypted, linked and special entries reject. Declared count,
per-file size, total expansion, depth and compression ratio are checked before
writing, and actual extracted content is reinventoried. Extraction can run only
as a non-root worker in a verified private tmpfs boundary; its identity-pinned
directory is removed on success, failure or cancellation.

Reconstruction accepts the validated `safe` policy only. External tools receive
content on stdin and return content on stdout with fixed filename-free
arguments. PDF output is raster-only and page-count checked, Office first
renders to PDF and then uses the same raster path, PNG/JPEG is fully decoded and
re-encoded as PNG, and media is fully decoded/re-encoded with metadata,
attachments and chapters omitted. Every output has a new volatile file object,
bounded size, verified MIME/hash/tool evidence and a mandatory ClamAV rescan.
Unsupported and active types fail closed.

The canonical report schema records scanner/image/definition identity,
isolation and phase completion, every input verdict, archives, findings, tools,
transformations and output rescans. It is authenticated with HMAC-SHA-256 using
the 32-byte volatile session capability. Verification occurs before JSON
decoding, rejects noncanonical/unknown/trailing JSON, and permits promotion only
for a complete authenticated `approved` report. There is no torrent or magnet
identifier field.
