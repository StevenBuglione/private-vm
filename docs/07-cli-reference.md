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
the rendered error record. The hard implementation ceilings are 1 MiB for a value
transferred into locked secret memory and 64 MiB for a stream; individual
commands use smaller limits where their protocol permits.

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

### Workspace

```text
private-vm workspace import FILE [--session ID]
private-vm workspace inbox [--session ID]
private-vm workspace list [--session ID]
private-vm workspace inspect PATH [--session ID]
private-vm workspace export --to usb|encrypted-bundle [--session ID]
private-vm workspace verify [--last|--export ID]
private-vm workspace discard --all [--session ID]
```

No v1 command imports a directory.

### Torrent

```text
private-vm torrent start [--policy safe|quarantine]
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

`--magnet STRING` is absent by default. A deliberately unsafe argv flag may be
added only for debugging builds, never official release UX.

### Scan

```text
private-vm scan start --session ID
private-vm scan status --session ID
private-vm scan report --session ID
private-vm scan approve --session ID --open-in workstation|--to usb
private-vm scan reject --session ID
```

### VPN

```text
private-vm vpn import [--from-file FILE|--stdin]
private-vm vpn inspect
private-vm vpn test
private-vm vpn rotate
private-vm vpn remove
```

`inspect` redacts private key and sensitive fields.

### USB

```text
private-vm usb list
private-vm usb inspect --device ID
private-vm usb enroll --device ID
private-vm usb prepare --format luks2-ext4
private-vm usb verify
private-vm usb forget
```

`prepare` is destructive and requires an exact displayed device identity plus
interactive confirmation unless a signed automation policy explicitly permits it.

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

### Sessions

```text
private-vm session list
private-vm session status --session ID
private-vm session report --session ID [--export FILE]
private-vm session stop --session ID
private-vm session abort --session ID
private-vm session cleanup [--session ID|--all]
```

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
private-vm system diagnostics [--export FILE]
```

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
