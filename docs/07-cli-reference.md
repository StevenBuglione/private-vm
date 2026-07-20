# CLI reference

## Global flags

```text
--config PATH
--json
--no-color
--non-interactive
--timeout DURATION
--log-level error|warn|info|debug
--strict
--version
--help
```

Debug logging must still redact sensitive values.

Operational commands resolve configuration in built-in, system, user and
explicit non-secret flag order before dispatch. `--config PATH` replaces the
default user layer with one required file. It never replaces the root daemon's
system policy. Configuration and policy fields cannot contain secrets; load or
validation failures return a stable `CONFIG_*` error with exit 11. See
`docs/08-config-policy.md` for the complete field and file-trust contract.

`--help` and shell-completion scripts are intentionally human/tooling text, not
machine records. Combining `--json` with `--help`, invoking the root with only
`--json`, or passing `--json` to `completion` fails with `CLI_USAGE` (exit 2)
instead of silently emitting non-JSON output.

`private-vm --version` is the root shorthand for `private-vm version`. Both
forms print the same build information and honor `--json`.

## Sensitive input

Commands accept credentials and magnet values only from an explicitly selected
terminal, process standard input, or file source. Terminal reads serialize
access to `/dev/tty`, disable echo, and restore the original terminal state on
success, error, timeout, or cancellation. Standard-input and file reads are
byte-bounded and never add the value, source path, or underlying read error to
the rendered error record. The hard implementation ceilings are 1 MiB for a
value transferred into protected volatile secret storage and 64 MiB for a
stream; individual commands use smaller limits where their protocol permits.

On Linux, sensitive files are opened with parent and final-component symlink
resolution disabled. They must be regular local files; FUSE, NFS, SMB and 9P
sources fail closed. Because POSIX regular-file open/read syscalls cannot be
portably interrupted, a deadline-bearing file request fails before opening its
path; future file-transfer workflows must provide their own owned worker and
cleanup boundary. Credential imports additionally require effective-user
ownership and prohibit group, world, and executable permission bits.

## Exit codes

| Code | Meaning |
|---:|---|
| 0 | success |
| 2 | usage error |
| 10 | host preflight failure |
| 11 | configuration or schema failure |
| 12 | image/provenance failure |
| 13 | VPN/network enforcement failure |
| 14 | storage/capacity failure |
| 15 | QEMU/runtime failure |
| 16 | guest handshake/protocol failure |
| 17 | torrent workflow failure |
| 18 | scan rejected or incomplete |
| 19 | USB identity/export failure |
| 20 | workspace transfer/integrity failure |
| 21 | user cancellation |
| 22 | dirty workspace prevents stop |
| 23 | authorization denied |
| 24 | cleanup incomplete |
| 70 | internal error |

## Commands

### `private-vm init`

Creates user configuration directories, checks daemon installation, and guides
image/VPN/USB setup. It does not import secrets without an explicit subcommand.

### `private-vm version`

```bash
private-vm version [--json]
private-vm --version [--json]
```

Prints the application version, source commit, build date, Go version, operating
system and architecture. It performs no daemon connection or host mutation.

### `private-vm doctor`

```bash
private-vm doctor [--strict] [--repair-safe] [--json]
```

`--repair-safe` may fix only non-destructive ownership, directory, or service
state. It must not change firewall, format disks, enable hibernation settings, or
enroll USB devices.

The read-only report blocks online-role planning when
`net.ipv6.conf.all.forwarding` is not exactly `1`. The NixOS module declares
this prerequisite; distribution packages must install an equivalent sysctl
fragment. Doctor never changes it. Global IPv4 forwarding is neither required
nor enabled because the daemon confines IPv4 forwarding to its owned veth.

### `private-vm plan`

```bash
private-vm plan workstation --bundle development
private-vm plan torrent --policy safe --destination usb
```

Produces the complete resource and security plan without launching QEMU.

### Desktop

```text
private-vm desktop start [--bundle basic|office|development]
                         [--audio] [--memory SIZE] [--cpus N]
private-vm desktop connect [--session ID]
private-vm desktop status [--session ID]
private-vm desktop stop [--session ID] [--require-clean|--discard]
private-vm desktop restart-viewer [--session ID]
private-vm desktop bundles list
private-vm desktop bundles inspect NAME
```

`desktop start` performs strict planning before it creates a volatile session,
then invokes the daemon's serialized role start. If the start RPC does not
complete, the CLI submits a bounded abort so a created record cannot be
abandoned. Omitting `--session` is accepted only when exactly one owned
workstation matches. `desktop stop` permits `CLEAN` and, unless
`--require-clean` is set, fully verified `READY`; other states require the
explicit destructive `--discard` choice.

`desktop connect` and `desktop restart-viewer` resolve one active owned
workstation through the daemon, then run the root-owned `remote-viewer`
executable as the invoking user against the fixed UID-only Unix display proxy.
There is no viewer-command, socket-path or TCP option. `desktop start` never
launches a viewer and returns when the daemon reports the workstation active.
The two viewer commands intentionally run `remote-viewer` in the foreground;
they return when it exits and cancel it when the CLI context or global
`--timeout` expires (five minutes by default, at most 24 hours). Viewer exit or
timeout does not stop the VM. The display proxy permits one active client and
immediately closes every concurrent connection instead of queueing it.

### Workspace

```text
private-vm workspace import FILE [--session ID]
private-vm workspace inbox [--session ID]
private-vm workspace list [--session ID]
private-vm workspace inspect PATH [--session ID]
private-vm workspace export OUTPUT --to usb|encrypted-bundle [--session ID]
private-vm workspace verify (--last|--export ID) [--session ID]
private-vm workspace discard --all [--session ID]
```

No v1 command imports a directory.

`workspace import` opens and hashes one no-follow regular host file, streams it
without exposing its path to the daemon or guest, and requires the daemon and
guest SHA-256 receipt to match. `workspace list` and `workspace inbox` return an
aggregate `WORKSPACE_STATUS` record; machine output contains only state and
counts. `workspace discard --all` is the explicit destructive choice and stops
the disposable workstation through the protected daemon stop path.

The production CLI sends the exact opaque output ID and closed `usb`
destination enum to `ExportWorkspaceToDestination`; it never receives output
bytes or supplies a host path. The daemon prepares a typed destination
transaction before opening the authenticated workstation stream. That
transaction must persist and independently re-read the receiver bytes and
clean its resources. Only equality between the guest/daemon digest and the
receiver digest invokes guest verification; failure leaves the workstation
dirty and triggers bounded transaction abort. The concrete USB transaction is
composed by the exporter workflow. `encrypted-bundle` remains explicitly
unavailable until its separate storage/encryption ADR is approved. `workspace
verify` revalidates that exactly one selected guest receipt
is current and unchanged; destination re-read verification happens during the
export command and is not reconstructed from persistent CLI state. `--last`
is accepted only when exactly one current verified receipt exists; otherwise
the caller must use one explicit output ID.

Scanner-to-workstation promotion uses a sealed typed host hook that accepts
only the sole output in a complete authenticated approved report. The daemon
creates and starts a fresh unadvertised workstation through the normal role
path, relays bounded frames without a host path, requires scanner/relay/receiver
SHA-256 equality, cleans the scanner, and only then returns the destination
session ID and launches the user-owned Unix viewer. Any pre-success failure
cleans the fresh workstation. Reports with zero or multiple sanitized outputs
fail closed in v1; ordinary trusted-file import cannot bypass this boundary.

### Torrent

```text
private-vm torrent start [--policy safe|quarantine]
private-vm torrent add --magnet-tty
private-vm torrent add --magnet-stdin
private-vm torrent add --torrent-file FILE
private-vm torrent metadata
private-vm torrent select --files 1,2,4
private-vm torrent plan
private-vm torrent download
private-vm torrent pause
private-vm torrent resume
private-vm torrent status
private-vm torrent complete
```

Torrent subcommands automatically select the sole active downloader owned by
the caller and fail when none or more than one exists. They always traverse the
Unix daemon and its session authorization boundary; the CLI never dials guest
VSOCK directly. Machine results expose only state, byte/file counts and stable
remediation. Torrent names, paths, hashes, peer identifiers and input values are
omitted; exact file review remains inside the isolated downloader display.

`--magnet STRING` is absent by default. A deliberately unsafe argv flag may be
added only for debugging builds, never official release UX.

`--magnet-tty` uses the process-serialized `/dev/tty` reader, disables echo and
restores terminal state on every return path. `--magnet-stdin` uses the bounded
owned standard-input adapter. `.torrent` input is a no-follow regular-file
stream capped at 16 MiB; its path is consumed by the unprivileged CLI and is not
sent to guestd. Exactly one source is required.

### Scan

```text
private-vm scan start --session ID
private-vm scan status --session ID
private-vm scan report --session ID
private-vm scan approve --session ID --open-in workstation|--to usb
private-vm scan reject --session ID
```

For `scan start`, `--session` is the downloader session whose state is
`QUARANTINE_SEALED`. The command creates and returns a different scanner session
ID. `status`, `report`, `approve` and `reject` require that scanner ID. The run
alias uses the identical daemon stream and cannot bypass update, offline,
read-only, report-authentication or cleanup gates.

Scanner machine output uses `SCANNER_STATUS`. It contains the scanner session
ID, workflow state, decision, aggregate input/finding/output counts, total
sanitized bytes, stable code and remediation. Successful `--open-in
workstation` output additionally contains `destination_session_id`; all other
scanner results omit it. It never contains the source
session ID, report JSON, logical names, hashes, finding identifiers, paths or
guest/runtime details. `approve` returns success only after the selected
destination relay and integrity verification complete; `reject` never invokes a
promotion relay.

### VPN

```text
private-vm vpn import [--from-file FILE|--stdin]
private-vm vpn inspect
private-vm vpn test
private-vm vpn rotate [--from-file FILE|--stdin]
private-vm vpn remove
```

`inspect` redacts private key and sensitive fields.

`import` accepts at most 64 KiB after the selected sensitive-input adapter has
applied its ownership, mode, filesystem and deadline checks. The daemon parses
the bytes directly into protected volatile storage. A successful import
atomically replaces and destroys the prior generation; it creates no profile
file. `remove` is idempotent, and daemon shutdown or restart destroys every
imported generation.

Without a source flag, an interactive invocation securely prompts on
`/dev/tty` for the path of an existing profile; it does not attempt to accept a
multi-line WireGuard file as one terminal line. The selected file must pass the
same caller-owner, mode-0600, regular-file and no-symlink checks as
`--from-file`. Non-interactive callers must select `--from-file` or `--stdin`.

The CLI sends one contextual begin frame followed by at most 64 non-empty
16-KiB chunks over `/run/private-vm/control.sock`. The source path is consumed
only by the unprivileged CLI and is not part of the RPC. Chunks and input
buffers are cleared after use; the profile is never placed in argv or the
environment. `rotate` uses this exact import path and source-selection contract.

`inspect` returns only the versioned status in
`schemas/vpn-profile-status.schema.json`: presence, an opaque generation,
IPv4/IPv6 booleans, address/DNS counts and rotation state. It never returns the
profile source path, key, endpoint, address, DNS value or resolver output.
`test` performs the bounded trusted-host endpoint check before guest launch.
The state is `current` only after that succeeds. Resolution failure sets
`rotation_required`; `rotate` prompts for a newly generated Proton profile and
uses the same atomic import path. It never generates or persists a key itself.

### USB

```text
private-vm usb list
private-vm usb inspect --device ID
private-vm usb enroll --device ID [--label PRIVATE_VM_TRANSFER]
                              [--accept-port-binding]
private-vm usb prepare --format luks2-ext4
private-vm usb export --session EXPORTER_SESSION --claim CLAIM_ID \
                      --scanner-session SCANNER_SESSION --output OUTPUT_ID
private-vm usb verify
private-vm usb forget
```

`prepare` is destructive and requires an exact displayed device identity plus
two exact interactive confirmations. It creates one exporter session, claims
the current enrollment, displays the daemon-generated plan, reads the LUKS2
passphrase without echo, and streams it through the authenticated control
socket. The success record returns only the opaque exporter session, claim and
enrollment IDs plus aggregate identity/capacity evidence. Failure aborts the
same session and invokes its registered cleanup owner.

`export` selects one policy-approved reconstructed scanner output by opaque
session/output IDs. It never accepts a host or guest path. Success requires all
source/relay/exporter/reread equality, flush, atomic-rename, unmount, detach,
exporter-stop and session-cleanup booleans. The success record contains no
filename, digest or device path.

`list`, `inspect`, `enroll`, `verify`, and `forget` traverse the authenticated
Unix daemon and are owner-bound by kernel peer credentials. Their typed output
contains an opaque observation ID, transient kernel block path, VID/PID, model,
serial, USBGuard hash, physical port, complete interface classes, capacity,
eligibility and a complete identity fingerprint. Raw USBGuard command output is
never returned, and the kernel path is never persisted or accepted as later
authorization. `--accept-port-binding` is required only
when the inspected device has no stable serial and explicitly pins the record
to the displayed port. Enrollment is saved under the installed daemon-owned
enrollment root in one mode-`0700`, numeric-UID-owned directory with a mode
`0600` regular file. `forget` is idempotent and does not inspect or mutate the
physical device.

### Images

```text
private-vm images list
private-vm images sync [--role ROLE] [--bundle BUNDLE]
private-vm images pull REF
private-vm images verify REF
private-vm images inspect REF
private-vm images build --role ROLE [--bundle BUNDLE]
private-vm images test REF [--backend qemu|packer]
private-vm images prune
```

`images pull` resolves a tag to an immutable OCI manifest digest before layer
download. It exposes no cache entry until all bounded component transfers,
digest checks, extraction, manifest/SBOM/provenance verification and an atomic
read-only install succeed. Cancellation, timeout or verification failure
removes the hidden partial entry. A mutable tag is never an execution identity
or persisted cache key.

### Sessions

```text
private-vm session list
private-vm session status --session ID
private-vm session report --session ID [--export FILE]
private-vm session stop --session ID
private-vm session abort --session ID
private-vm session cleanup [--session ID|--all]
```

Session and desktop lifecycle commands use only semantic RPCs on the private
Unix control socket. Their `--json` success record uses `SESSION_STATUS` and the
closed `cli-success` schema. It contains only the opaque session ID, role,
lifecycle phase, and workflow state.

### Policy

```text
private-vm policy list
private-vm policy show NAME
private-vm policy validate FILE
```

### Run aliases

```text
private-vm run workstation [--bundle basic|office|development]
                           [--audio] [--memory SIZE] [--cpus N]
private-vm run torrent [--policy safe|quarantine]
private-vm run scanner --session ID
```

These are convenience aliases for the corresponding planned workflows. Each
alias calls the same configuration, preflight, planning, authorization and
orchestration paths as the expanded commands; an alias cannot bypass a check.
`run workstation` and `desktop start` normalize identical bundle, audio, memory
and CPU options into the same workstation intent and dispatch the same stable
command ID, `workstation.start`. Their defaults and validation are identical.

### System

```text
private-vm system status
private-vm system install --dry-run
private-vm system install --accept
private-vm system uninstall --dry-run
private-vm system uninstall --accept
private-vm system diagnostics [--export FILE]
```

The generic Linux install and uninstall commands require exactly one of
`--dry-run` and `--accept`. Both verify the closed bundle or installed manifest
and produce the same exact mutation plan; `--accept` additionally records that
the plan was applied. Uninstall preserves configuration, image cache, enrolled
identity state and user exports.

`system diagnostics` displays a redacted diagnostic-bundle manifest. With
`--export`, the user must review that manifest before the bounded bundle is
written. It never includes active session content or secret values.

### Completion

```text
private-vm completion bash
private-vm completion zsh
private-vm completion fish
```

Completion output is a bounded shell script. It does not accept `--json`.

## Stable machine output

`--json` emits newline-terminated JSON records. Success and event records go to
standard output; errors go to standard error. Every record has
`schema_version = 1`, a stable uppercase `code`, and a literal `ok` value.
Unknown top-level fields are invalid. Command-specific `data` objects are
produced by typed implementations; their fields are not an extension mechanism
for callers.

Success records use:

```json
{
  "schema_version": 1,
  "ok": true,
  "code": "VERSION_REPORTED",
  "data": {
    "version": "0.1.0-dev",
    "commit": "0123456789abcdef0123456789abcdef01234567",
    "date": "2026-07-18T12:00:00Z",
    "go_version": "go1.26.5",
    "os": "linux",
    "arch": "amd64"
  }
}
```

Error records use:

```json
{
  "schema_version": 1,
  "ok": false,
  "code": "CONFIG_INVALID",
  "exit_code": 11,
  "message": "Configuration validation failed.",
  "remediation": "Correct the reported field without placing secrets in TOML."
}
```

Event records use a monotonically increasing sequence within a session or
command stream. `data` is the direct typed event payload selected for the stable
event code; it is not another envelope or an untyped caller extension:

```json
{
  "schema_version": 1,
  "ok": true,
  "code": "IMAGE_PULL_PROGRESS",
  "sequence": 7,
  "session_id": "pvm-11111111111111111111111111111111",
  "data": {
    "current": 64,
    "total": 128,
    "unit": "MiB"
  }
}
```

`session_id` is optional on errors and events because some failures occur before
a session exists. Successes intentionally omit it; a session-producing command
places the identifier in its typed `data` object. The checked-in schemas and
examples are canonical. No envelope or payload may contain keys, magnets,
filenames, file hashes, endpoints, public IPs, or raw external-command output.
Human output may change cosmetically; codes and schema versions follow semantic
versioning.
