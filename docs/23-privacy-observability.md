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
- VPN endpoint/private key/profile source path
- public IP
- DNS answers
- USB volume content
- guest screenshots
- QMP raw messages
- scan file paths
- peer PID, process start time, supplementary groups, or raw `/proc` evidence
- raw external-command stdout, stderr, environment, or wrapped failure text

Unix peer identity evidence is bounded, parsed, and revalidated in memory for
each authorization decision. Missing or changed PID/start-time/UID/group
evidence is exposed only as `AUTHORIZATION_DENIED`; the response does not reveal
which identity check failed. Request-context and selector failures likewise use
the typed safe messages and remediation in `docs/33-error-catalog.md`, never the
rejected raw value.

VPN profile parse and endpoint-resolution errors deliberately discard the raw
input, hostname, DNS answers and wrapped resolver cause. Profile and resolved
endpoint types reject machine serialization and render fixed redaction tokens.
`vpn inspect` uses only the reviewed aggregate status schema. Debug logging does
not alter these contracts. A profile exists only in the daemon's protected
memory store and the bounded guest-delivery callback; neither is included in a
diagnostic bundle.

The unprivileged CLI alone opens a selected profile file. Its source path is not
sent over RPC. Profile bytes travel only in bounded client-streaming protobuf
chunks over the authenticated Unix socket; they are never placed in argv or the
environment and are not formatted into RPC errors. CLI, protobuf-chunk and
daemon receive buffers are cleared after each ownership boundary.

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

## Privileged helper output

The daemon permits only the absolute `pkcheck` executable selected at startup
and only the fixed `org.private-vm.usb.prepare` action. It launches `pkcheck`
with an empty environment, discards both stdout and stderr, and converts denial
or failure to a safe classification rather than wrapping the child-process
output. Its PID/start-time/UID subject is revalidated before invocation.

`ClaimUSB` is a non-destructive exact-identity USBGuard claim. It binds the
claim to the exporter session and its cleanup owner without invoking Polkit.
`PrepareUSB` is the destructive boundary: it obtains the fixed Polkit decision
immediately before the exporter performs the mutation. The decision must not be
moved earlier into claim, planning, confirmation, or logging paths.

RPC cancellation and bounded-deadline failures are reported as
`REQUEST_CANCELED` and `REQUEST_TIMEOUT` with safe remediation. An RPC server
startup failure occurs before typed RPC is available, so `private-vmd` emits one
fixed `DAEMON_START_FAILED` line and suppresses the wrapped configuration,
socket, process-evidence, and helper cause.

## Crash handling

- core dumps disabled for CLI, daemon, guestd, and QEMU scopes
- Linux secret memfd mappings additionally use `MADV_DONTDUMP`; failure to set
  it is blocking even though process-scope core limits remain mandatory
- no automatic crash upload
- panic output redacted and bounded
- official bug reports request user-exported diagnostic bundle
- diagnostic bundle must display manifest before creation

`mlock` is best effort and is not described as a guarantee. Secret ownership
ends with explicit overwrite and destruction of the package-owned mapping, but
transient Go, encoder, gRPC, kernel, hypervisor or hardware copies may remain.
This limitation is why privacy wording never claims perfect erasure.

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

Without `--export`, `private-vm system diagnostics` only renders the redacted
manifest and performs no write. Under `--json`, the manifest is returned in the
same versioned success envelope documented in `docs/07-cli-reference.md`.

## Approved wording

Use:

> private-vm does not intentionally persist plaintext session state.

Avoid:

- "leaves absolutely no trace"
- "100% anonymous"
- "unhackable"
- "virus-proof"
- "guaranteed safe"
