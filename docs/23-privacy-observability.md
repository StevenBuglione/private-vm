# Privacy, logging, and observability

## Default logging

The daemon may persist only coarse records:

```text
service started/stopped
version
session created/destroyed with random ID and UID
role
success/failure code
cleanup recovery count
```

Do not persist:

- magnet links
- info hashes
- torrent names
- tracker URLs
- filenames
- file hashes unless user exports report
- VPN endpoint/private key
- public IP
- DNS answers
- USB volume content
- guest screenshots
- QMP raw messages
- scan file paths

## Session events

Detailed events live under `/run/private-vm/<id>` and disappear at teardown.

## QEMU output

Default:

- serial disabled unless a debug build/session explicitly enables it
- stdout/stderr to volatile per-session file with size cap
- no journald standard output
- report extracts only safe error classification

## Debug mode

`--log-level debug` never disables redaction. A separate development build flag
may expose fixture-only details, but official binaries do not provide a
"dangerously log secrets" option.

## Metrics

No network metrics endpoint and no telemetry. Local `status --json` derives live
metrics from session state.

## Crash handling

- core dumps disabled for CLI, daemon, guestd, and QEMU scopes
- no automatic crash upload
- panic output redacted and bounded
- official bug reports request user-exported diagnostic bundle
- diagnostic bundle must display manifest before creation

## Diagnostic bundle

`private-vm system diagnostics --export FILE` may include:

- versions
- feature probes
- package/install status
- redacted configuration
- recent safe daemon errors
- no active session content
- no secret values

User reviews the manifest before writing it.

## Approved wording

Use:

> private-vm does not intentionally persist plaintext session state.

Avoid:

- "leaves absolutely no trace"
- "100% anonymous"
- "unhackable"
- "virus-proof"
- "guaranteed safe"
