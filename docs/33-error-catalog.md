# Error and diagnostic catalog

Codes are stable API. Human wording may improve without changing the code.

## Exit-code classes

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

This table is identical to the canonical contract in
`docs/07-cli-reference.md`. Exit values outside this set are not part of the v1
CLI API.

## Stable CLI-layer errors

| Code | Exit | Safe meaning |
|---|---:|---|
| `CLI_USAGE` | 2 | Command syntax, an argument or an option was invalid. |
| `SAFE_REPAIR_NOT_IMPLEMENTED` | 10 | `doctor --repair-safe` was requested, but the bounded repair path is not implemented. No repair was attempted. |
| `HOST_PREFLIGHT_FAILED` | 10 | One or more blocking host diagnostics prevent the requested operation. |
| `OPERATION_TIMEOUT` | 15 | The operation exceeded its bounded timeout and was stopped. |
| `NOT_IMPLEMENTED` | 15 | The documented security-sensitive command exists but refuses to run until its implementation and acceptance gates pass. |
| `OPERATION_CANCELLED` | 21 | The caller or process context cancelled the operation. |
| `OUTPUT_RENDER_FAILED` | 70 | The CLI could not safely encode or write bounded output. Wrapped writer or encoder details are not exposed. |
| `INTERNAL_ERROR` | 70 | An invalid or unclassified internal result was normalized to the redacted internal-error contract. |
| `COMPLETION_FAILED` | 70 | Shell completion generation exceeded its bound or could not be safely produced or written. |

## Configuration and policy errors

All `CONFIG_*` errors returned by the CLI use exit 11. `POLICY_*` errors use
exit 11 when surfaced by policy validation. Messages and remediations are
redacted and never include a selected path, rejected key/value or wrapped
parser, migration or filesystem cause.

| Code | Safe meaning |
|---|---|
| `CONFIG_READ` | A selected layer is missing, unreadable or fails file trust checks. |
| `CONFIG_TOO_LARGE` | Input or migrated output exceeds 1 MiB. |
| `CONFIG_PARSE` | TOML types, syntax or fields do not match the closed contract. |
| `CONFIG_SCHEMA_VERSION` | `schema_version` is missing, invalid or unsupported. |
| `CONFIG_MIGRATION` | The migration registry/hook is missing or invalid. |
| `CONFIG_SECRET_FIELD` | A forbidden secret-bearing field name was detected. |
| `CONFIG_PATH` | The default user configuration base is not a clean absolute path. |
| `CONFIG_INVALID` | The merged effective snapshot violates a semantic invariant. |
| `POLICY_READ` | A selected policy is unreadable or fails file trust checks. |
| `POLICY_TOO_LARGE` | Policy input or migrated output exceeds 1 MiB. |
| `POLICY_PARSE` | TOML types, syntax or fields do not match the policy contract. |
| `POLICY_SCHEMA_VERSION` | Policy `schema_version` is missing, invalid or unsupported. |
| `POLICY_MIGRATION` | A policy migration registry/hook is missing or invalid. |
| `POLICY_SECRET_FIELD` | A forbidden secret-bearing policy field was detected. |
| `POLICY_INVALID` | Policy identity, mode or fixed semantics are invalid. |
| `POLICY_LIMIT` | A finite content/archive/timeout bound is invalid. |
| `POLICY_WEAKENING` | A mandatory fail-closed or reconstruction rule was disabled. |

These meanings are safe for logs and automation. Human error records add a
bounded remediation but never serialize a wrapped cause or raw command output.

## Volatile-secret package errors

These stable sentinels are safe internal classifications. They never include a
secret value, descriptor path or wrapped syscall output. A CLI or RPC boundary
maps them to the owning workflow's documented error code rather than emitting
the Go error text directly.

| Sentinel | Safe meaning |
|---|---|
| `ErrEmpty` | No secret bytes were supplied. |
| `ErrTooLarge` | Secret input exceeded the hard 16 MiB package ceiling. |
| `ErrUnavailable` | Protected storage or an initialized handle is unavailable. |
| `ErrDestroyed` | The shared secret state was already destroyed. |
| `ErrNotMemfd` | This platform/backing cannot provide inherited-FD delivery. |
| `ErrCallback` | A bounded secret-reader callback was not supplied. |
| `ErrSerialization` | A supported serialization path was rejected. |

## Mandatory blocking diagnostic codes

### Host

- `HOST_OS_UNSUPPORTED`
- `SYSTEMD_REQUIRED`
- `CGROUP_V2_REQUIRED`
- `KVM_UNAVAILABLE`
- `KVM_PERMISSION_DENIED`
- `QEMU_UNSUPPORTED`
- `RUNTIME_NOT_TMPFS`
- `DISK_SWAP_ACTIVE`
- `HIBERNATION_ENABLED`
- `INSUFFICIENT_MEMORY`
- `INSUFFICIENT_SCRATCH`
- `ORPHAN_CLEANUP_FAILED`

### Supply chain

- `IMAGE_DIGEST_MISMATCH`
- `IMAGE_ATTESTATION_MISSING`
- `IMAGE_ATTESTATION_INVALID`
- `IMAGE_REPOSITORY_MISMATCH`
- `IMAGE_WORKFLOW_MISMATCH`
- `IMAGE_ROLE_MISMATCH`
- `IMAGE_ARCH_MISMATCH`
- `IMAGE_API_INCOMPATIBLE`
- `IMAGE_SBOM_MISSING`

### Network

- `VPN_PROFILE_INVALID`
- `VPN_ENDPOINT_UNRESOLVED`
- `HOST_EGRESS_POLICY_FAILED`
- `VPN_HANDSHAKE_FAILED`
- `DNS_LEAK_DETECTED`
- `IPV4_BYPASS_DETECTED`
- `IPV6_BYPASS_DETECTED`
- `TORRENT_INTERFACE_UNBOUND`

### Scanner

- `SCANNER_DEFINITIONS_STALE`
- `SCANNER_NETWORK_PRESENT`
- `QUARANTINE_NOT_READ_ONLY`
- `MALWARE_DETECTED`
- `SCAN_ERROR`
- `SCAN_FILE_SKIPPED`
- `SCAN_LIMIT_REACHED`
- `ARCHIVE_ENCRYPTED`
- `ARCHIVE_LIMIT_REACHED`
- `TYPE_MISMATCH`
- `ACTIVE_CONTENT_BLOCKED`
- `SANITIZER_FAILED`
- `REPORT_INCOMPLETE`

### USB

- `USB_NOT_ENROLLED`
- `USB_IDENTITY_MISMATCH`
- `USB_AMBIGUOUS`
- `USB_COMPOSITE_INTERFACE`
- `USB_HOST_FILESYSTEM`
- `USB_MOUNTED`
- `USB_TOO_SMALL`
- `USB_WRITE_FAILED`
- `USB_HASH_MISMATCH`

### Workspace

- `WORKSPACE_UNEXPORTED`
- `WORKSPACE_CHANGED`
- `IMPORT_PATH_UNSAFE`
- `TRANSFER_SIZE_EXCEEDED`
- `TRANSFER_OFFSET_INVALID`
- `TRANSFER_HASH_MISMATCH`

A hard diagnostic marked “never overridable” in the requirements cannot be
suppressed by config, environment or CLI flags.
