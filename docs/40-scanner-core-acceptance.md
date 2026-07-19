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
| `SCAN-005` | reconstruction orchestration and volatile outputs | PDF and Office raster path, PNG/JPEG re-encode, media/text policy, output bounds, MIME/hash, structure verification, mandatory rescan, failure/cancellation cleanup and active/unsupported rejection |
| `SCAN-006` | strict canonical report plus volatile HMAC | complete approval verifies; tampering, wrong/destroyed key, incomplete phases, blocking verdicts, unrescanned output and noncanonical JSON reject |

Local commands use `CGO_ENABLED=0`, `GOMAXPROCS=2` and `-p 1`. They use no VPN
credential, magnet, torrent, public download or physical USB.

Remaining system acceptance before these issues may be treated as fully closed:

- boot the update scanner with Proton and no quarantine, run real `freshclam`,
  and retain the exact overlay;
- reboot that overlay with no QEMU NIC and the quarantine block device read-only,
  prove the guest mount and failed write;
- run the pinned libmagic, ClamAV, Ghostscript/Poppler, LibreOffice and ffmpeg
  toolchain against the versioned hostile corpus;
- prove the authenticated scanner RPC envelope and promotion relay end to end;
- verify cleanup through scanner/QEMU death and daemon recovery.
