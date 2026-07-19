# Scanner core acceptance evidence

This record covers the source-level implementation for `SCAN-001` through
`SCAN-006`. It deliberately does not claim the scanner image or external tools
were exercised by these low-memory tests.

| Task | Source boundary | Focused evidence |
| --- | --- | --- |
| `SCAN-001` | update/definition receipt and same-overlay offline transition | quarantine-present, absent network/VPN, stale/incomplete definitions, overlay mismatch and non-loopback offline interface reject |
| `SCAN-002` | descriptor-relative inventory and identity-pinned reopen | hashes and MIME disagreement record; symlink, hardlink, FIFO, special file, replacement, cancellation and count/byte/path limit reject |
| `SCAN-003` | bounded clamd Unix `INSTREAM` protocol | clean/malware/encrypted/skipped/limit/error/timeout verdicts parse strictly; changed sizes, oversized responses and incomplete streams reject; readers close |
| `SCAN-004` | ZIP/TAR preflight, extraction and reinventory | absolute/traversal, symlink/hardlink, special, encrypted, nested and high-ratio fixtures reject; unprivileged tmpfs extraction cleans idempotently and will not delete a substituted path |
| `SCAN-005` | reconstruction orchestration and volatile outputs | PDF all-page size/count evidence and Office raster path, PNG/JPEG re-encode, media/text policy, output bounds, MIME/hash, structure verification, mandatory rescan, failure/cancellation cleanup and active/unsupported rejection |
| `SCAN-006` | strict canonical report plus volatile HMAC | complete approval verifies; tampering, wrong/destroyed key, incomplete phases, blocking verdicts, unrescanned output and noncanonical JSON reject |

The scanner guest RPC integration adds a single serialized phase owner over
these boundaries. Its credential-free test creates an update service, retains
only the typed definition receipt, creates a fresh offline service, and executes
inventory, malware scan, reconstruction, report authentication and approved
export through authenticated gRPC. Progress is filename/hash-free, an
out-of-order or changed-policy call fails closed, cross-role services remain
absent, and cancellation/timeout paths clean partial reconstructed output.

The host RPC integration adds the complementary daemon owner. Starting from an
owned sealed downloader, it creates a separate scanner session and advances the
complete update → stop → same-overlay offline → inventory → scan → reconstruct
→ authenticated-report sequence. Status/report output is aggregate-only.
Approval invokes exactly one typed promotion target before it publishes
approval; rejection never invokes promotion. Unix-daemon integration tests
cover success, failure, cancellation, timeout and cleanup-audit failure.

Local commands use `CGO_ENABLED=0`, `GOMAXPROCS=2` and `-p 1`. They use no VPN
credential, magnet, torrent, public download or physical USB.

Remaining system acceptance before these issues may be treated as fully closed:

- boot the update scanner with Proton and no quarantine, run real `freshclam`,
  and retain the exact overlay;
- reboot that overlay with no QEMU NIC and the quarantine block device read-only,
  prove the guest mount and failed write;
- run the pinned libmagic, ClamAV, Ghostscript/Poppler, LibreOffice and ffmpeg
  toolchain against the versioned hostile corpus;
- compose the host scanner runtime with image-pinned storage/QEMU/QMP/VSOCK
  providers and the guest image's retained-overlay receipt,
  freshclam/libmagic/clamd/archive and reconstruction adapters;
- exercise the implemented authenticated scanner-to-fresh-workstation relay and
  the exporter path end to end in booted guests;
- verify cleanup through scanner/QEMU death and daemon recovery.
