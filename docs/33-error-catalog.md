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

## Stable daemon RPC errors

Except for process startup, daemon-generated application failures cross gRPC as
a status plus one `ErrorDetail`. The status text is limited to the stable code
and safe message; the detail carries the same code, a non-empty safe
remediation, and the retryable flag below. It never carries peer identity
evidence, rejected raw values, wrapped filesystem or process errors, or
external-command output.

Transport failures that gRPC rejects before an application interceptor runs,
including the 8 KiB header-list and 4 MiB message limits, use bounded native
gRPC status without `ErrorDetail`. They never include a rejected payload or
become a new stable daemon application code.

| Code | gRPC status | Retryable | Safe meaning | Remediation |
|---|---|---:|---|---|
| `AUTHORIZATION_DENIED` | `PermissionDenied` | no | Kernel peer identity or private-vm group authorization could not be verified. | Run the client as root or as a verified member of the `private-vm` group. |
| `PROTOCOL_VERSION_MISMATCH` | `FailedPrecondition` | no | The request API version is absent or incompatible. | Upgrade `private-vm` and `private-vmd` together. |
| `REQUEST_ID_INVALID` | `InvalidArgument` | no | The opaque request ID is absent or malformed. | Supply an opaque 8-128 character request identifier. |
| `SESSION_ID_REQUIRED` | `InvalidArgument` | no | A session-scoped method omitted its session ID. | Supply an active session ID returned by `CreateSession`. |
| `SESSION_ID_INVALID` | `InvalidArgument` | no | The supplied session ID is not a valid opaque `pvm-...` identifier. | Use the opaque session ID returned by `CreateSession`. |
| `RPC_CONTEXT_CONTRACT_INVALID` | `Internal` | no | A daemon method and its request-context contract do not match. | Install matching verified `private-vm` binaries. |
| `GUEST_ROLE_INVALID` | `InvalidArgument` | no | Planning or creation did not select one of the four supported roles. | Choose workstation, downloader, scanner, or exporter. |
| `IMAGE_BUNDLE_INVALID` | `InvalidArgument` | no | The workstation bundle is unsupported or was supplied for another role. | Choose basic, office, or development for a workstation; omit the bundle for other roles. |
| `POLICY_NAME_INVALID` | `InvalidArgument` | no | The selected policy name is unsupported. | Choose safe or quarantine. |
| `RESOURCE_REQUEST_INVALID` | `InvalidArgument` | no | Requested resources exceed or violate the supported bounds. | Use at most 64 vCPUs, 256 GiB RAM, 2 TiB root, and 16 TiB scratch. |
| `TRANSFER_BEGIN_REQUIRED` | `InvalidArgument` | no | The import stream ended or supplied a non-begin first frame. | Start the stream with a bounded `TransferBegin` record. |
| `SESSION_NOT_FOUND` | `NotFound` | no | The requested session does not exist. | List sessions owned by the current user and retry with an active session ID. |
| `SESSION_OWNER_MISMATCH` | `PermissionDenied` | no | The requested session belongs to another user. | Use a session created by the current user. |
| `SESSION_QUOTA_EXCEEDED` | `ResourceExhausted` | yes | The per-user session limit was reached. | Stop or clean up an existing session before creating another. |
| `SESSION_TRANSITION_INVALID` | `FailedPrecondition` | no | The requested lifecycle transition is not valid for the current state. | Inspect session status and request an operation valid for its current state. |
| `WORKFLOW_TRANSITION_INVALID` | `FailedPrecondition` | no | The requested role workflow transition is not valid for the current role/state. | Inspect the role workflow and request its documented successor. |
| `CLEANUP_INCOMPLETE` | `FailedPrecondition` | yes | One or more owned resources could not be proven absent. | Preserve the recovery record, correct the host condition, and retry cleanup. |
| `EVENT_CURSOR_NOT_ALLOWED` | `InvalidArgument` | no | A nonzero event cursor was supplied to `GetSession`. | Use `after_sequence` only with `StreamEvents`. |
| `EVENT_CURSOR_INVALID` | `InvalidArgument` | no | The event cursor is ahead of the current lifetime sequence. | Reconnect at or below the current sequence. |
| `EVENT_CONSUMER_TOO_SLOW` | `ResourceExhausted` | yes | A subscriber exhausted its bounded event queue. | Reconnect with the last confirmed sequence. |
| `EVENT_LIMIT_REACHED` | `ResourceExhausted` | no | The bounded lifetime event limit was reached. | Stop and clean up the session; do not continue without complete evidence. |
| `DAEMON_SHUTTING_DOWN` | `Unavailable` | yes | Shutdown has begun and new sessions are blocked. | Retry after the daemon is running again. |
| `REQUEST_CANCELED` | `Canceled` | yes | The request was canceled before completion. | Retry the operation only if its session state permits it. |
| `REQUEST_TIMEOUT` | `DeadlineExceeded` | yes | The request exceeded its bounded deadline. | Inspect session status before retrying the operation. |
| `NOT_IMPLEMENTED` | `Unimplemented` | no | The method is intentionally fail-closed until its implementation gates pass. | Do not bypass the security boundary; install a build that implements and verifies the operation. |
| `INTERNAL_ERROR` | `Internal` | yes | An unclassified daemon failure was normalized. | Retry once; if the error persists, inspect redacted daemon diagnostics. |

`GetVersion(Empty)` is the sole daemon method exempt from `RequestContext`.
Every other unary method is rejected before its handler if its method/context
contract is unknown or invalid. Streaming methods perform the corresponding
context or first-frame validation in their bounded handlers.

Polkit does not add an error code to this table yet. `ClaimUSB` is currently a
non-destructive `NOT_IMPLEMENTED` stub and does not invoke `pkcheck`. The only
permitted helper action is `org.private-vm.usb.prepare`, reserved for the
implemented destructive prepare step immediately before mutation. Helper
stdout/stderr is discarded and a future RPC boundary must map denial, timeout,
or failure to a typed safe code rather than exposing raw `pkcheck` output.

### Daemon startup failure

Startup occurs before gRPC details are available. On any startup failure,
`private-vmd` exits with process status 1 and emits exactly this safe line:

```text
private-vmd: DAEMON_START_FAILED: the daemon could not start; inspect redacted system service diagnostics and verify the installed configuration
```

The wrapped configuration, group lookup, runtime directory, socket, `/proc`, or
`pkcheck` cause is suppressed. `DAEMON_START_FAILED` is a daemon-process
sentinel, not an additional v1 CLI exit-code class.

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

## Startup recovery classifications

Startup recovery returns the existing blocking `ORPHAN_CLEANUP_FAILED`
diagnostic and maps a daemon RPC retry to `CLEANUP_INCOMPLETE`. Its version-1
redacted evidence may contain only the following internal classifications. The
report never contains a session ID, object locator, identity fingerprint or
wrapped backend error.

| Code | Safe meaning |
|---|---|
| `RECOVERY_INVENTORY_FAILED` | The bounded private-vm orphan inventory did not complete. |
| `RECOVERY_INVENTORY_LIMIT` | Candidate or session count exceeded the fixed startup bound. |
| `RECOVERY_INVENTORY_DUPLICATE` | The trusted inventories reported the same typed object twice. |
| `RECOVERY_REGISTRY_CONFLICT` | A candidate could not be exclusively claimed against the live registry. |
| `RECOVERY_KEY_STATE_UNKNOWN` | Loss of the volatile private-vm key source could not be proven. |
| `RECOVERY_IDENTITY_REJECTED` | Initial identity or private-vm ownership validation failed. |
| `RECOVERY_IDENTITY_CHANGED` | Exact identity changed between inventory and mutation. |
| `RECOVERY_CLEANUP_FAILED` | A typed idempotent cleanup operation failed. |
| `RECOVERY_ABSENCE_UNPROVEN` | An individual artifact could not be proven absent. |
| `RECOVERY_SESSION_ABSENCE_UNPROVEN` | The complete cross-subsystem session audit was incomplete. |
| `RECOVERY_BASE_IMAGE_AUDIT_FAILED` | The pre-cleanup immutable-base identity seal was unavailable. |
| `RECOVERY_BASE_IMAGE_CHANGED` | The immutable-base identity seal changed during recovery. |
| `RECOVERY_CANCELED` | Startup recovery was canceled before all absence audits completed. |
| `RECOVERY_TIMEOUT` | A bounded inventory, identity, cleanup or audit step timed out. |

## Image pull/cache errors

These stable internal classifications map to CLI exit 12 at the image command
boundary, except cancellation and timeout, which normalize to the canonical
`OPERATION_CANCELLED` exit 21 and `OPERATION_TIMEOUT` exit 15 records. Their
messages and remediations never include a registry response, source reference,
cache path or wrapped filesystem/network failure.
The Go error retains its wrapped cause for trusted `errors.Is`/`errors.As`
classification, but implements safe formatting and Go-string behavior so
ordinary, detailed and structural `fmt` verbs cannot reveal that cause.

| Code | Safe meaning |
|---|---|
| `IMAGE_REFERENCE_INVALID` | The OCI reference is malformed or omits both tag and digest. |
| `IMAGE_RESOLVE_FAILED` | A repository or reference could not be resolved to an immutable manifest descriptor. |
| `IMAGE_OCI_MANIFEST_INVALID` | The OCI v1 manifest, descriptor set, media type, title or component count is unsupported. |
| `IMAGE_ARTIFACT_LIMIT` | Manifest, metadata, compressed image, installed image, component count or deadline limits are invalid or exceeded. |
| `IMAGE_DIGEST_MISMATCH` | Resolved, downloaded or installed bytes do not match their canonical SHA-256 identity. |
| `IMAGE_DOWNLOAD_FAILED` | A bounded OCI response could not be fetched, read or closed completely. |
| `IMAGE_EXTRACTION_FAILED` | The zstd image or fixed cache file could not be decoded, written, synchronized or closed. |
| `IMAGE_CACHE_INVALID` | Cache ownership, mode, type, layout, schema or recorded file integrity is invalid. |
| `IMAGE_CACHE_CONFLICT` | A digest entry could not be atomically published or reconciled with a valid concurrent entry. |
| `IMAGE_VERIFICATION_FAILED` | The mandatory manifest/SBOM/provenance verifier rejected the complete staged entry. |
| `IMAGE_VERIFICATION_UNAVAILABLE` | No IMG-002/IMG-003 verifier was installed, so no cache entry was published. |
| `IMAGE_MANIFEST_INVALID` | The published manifest is missing, malformed, noncanonical or violates the frozen-v1 build contract. |
| `IMAGE_ROLE_MISMATCH` | The published image role differs from the requested compartment. |
| `IMAGE_BUNDLE_MISMATCH` | The workstation bundle differs, or a non-workstation image does not use an explicit null bundle. |
| `IMAGE_ARCHITECTURE_MISMATCH` | The image architecture does not match the immutable amd64/x86_64 or arm64/aarch64 host mapping. |
| `IMAGE_GUEST_API_MISMATCH` | The image guest API major/minor is outside the immutable host compatibility policy. |
| `IMAGE_QEMU_VERSION_MISMATCH` | The image QEMU requirement is noncanonical or unsupported by the host policy. |
| `IMAGE_CAPABILITY_MISMATCH` | The capability list is not the exact sorted common-plus-role contract. |
| `IMAGE_SBOM_REQUIRED` | The official strict artifact has no readable SPDX layer. |
| `IMAGE_SBOM_INVALID` | The SPDX 2.3 document or its image/Nix-closure binding is malformed, incomplete or noncanonical. |
| `IMAGE_PROVENANCE_REQUIRED` | The immutable cache entry has no complete recorded Sigstore provenance bundle. |
| `IMAGE_PROVENANCE_INVALID` | The bounded offline bundle, signature, trust chain, Rekor proof, SCT or observer timestamp is invalid. |
| `IMAGE_PROVENANCE_IDENTITY_MISMATCH` | The authenticated repository, workflow, immutable release ref, commit or compressed-image identity is not official. |
| `IMAGE_PROVENANCE_PREDICATE_INVALID` | The signed closed SLSA/GitHub Actions payload violates the exact official producer profile. |
| `IMAGE_PULL_CANCELLED` | The caller cancelled before atomic publication; partial data was removed. |
| `IMAGE_PULL_TIMEOUT` | The bounded pull deadline expired; partial data was removed. |

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

### Storage

- `STORAGE_CAPACITY_EVIDENCE_INVALID`
- `STORAGE_CAPACITY_EXHAUSTED`
- `STORAGE_RESERVATION_CONFLICT`
- `STORAGE_BASE_IDENTITY_CHANGED`
- `STORAGE_IMAGE_ACTIVE`
- `STORAGE_BACKUP_EXCLUSION_UNVERIFIED`
- `STORAGE_LOOP_IDENTITY_MISMATCH`
- `STORAGE_MAPPER_IDENTITY_MISMATCH`
- `STORAGE_MOUNT_IDENTITY_MISMATCH`
- `STORAGE_ROLLBACK_INCOMPLETE`

### QEMU runtime

- `QEMU_EXECUTABLE_UNTRUSTED`
- `QEMU_SPEC_INVALID`
- `QEMU_SOCKET_UNSAFE`
- `QEMU_PEER_IDENTITY_MISMATCH`
- `QEMU_QMP_PROTOCOL_INVALID`
- `QEMU_QMP_DISCONNECTED`
- `QEMU_START_TIMEOUT`
- `QEMU_EXIT_UNEXPECTED`
- `QEMU_CLEANUP_INCOMPLETE`

### Network

- `VPN_PROFILE_INVALID`
- `VPN_ENDPOINT_UNRESOLVED`
- `NETWORK_REQUEST_INVALID`
- `NETWORK_TOPOLOGY_EXISTS`
- `NETWORK_COLLISION_EXHAUSTED`
- `NETWORK_TOPOLOGY_FAILED`
- `HOST_EGRESS_POLICY_FAILED`
- `NETWORK_TOPOLOGY_NOT_READY`
- `NETWORK_CLEANUP_INCOMPLETE`
- `GUEST_VPN_REQUEST_INVALID`
- `GUEST_KILL_SWITCH_FAILED`
- `GUEST_VPN_CONFIGURATION_FAILED`
- `GUEST_VPN_VERIFICATION_FAILED`
- `GUEST_VPN_TUNNEL_LOST`
- `GUEST_VPN_CLEANUP_INCOMPLETE`
- `VPN_HANDSHAKE_FAILED`
- `DNS_LEAK_DETECTED`
- `IPV4_BYPASS_DETECTED`
- `IPV6_BYPASS_DETECTED`
- `TORRENT_INTERFACE_UNBOUND`

VPN profile operations additionally use these stable safe codes:

| Code | Exit | Safe meaning | Remediation |
|---|---:|---|---|
| `VPN_PROFILE_INVALID` | 13 | The bounded input does not match the frozen Proton WireGuard grammar. | Generate a profile with one peer, complete default routes, literal DNS addresses and no hooks. |
| `VPN_ENDPOINT_UNRESOLVED` | 13 | The endpoint lookup failed, timed out, was empty/oversized or returned an unsafe address. | Generate and import a current Proton profile, then retry the bounded check. |
| `VPN_PROFILE_NOT_IMPORTED` | 13 | The selected name has no daemon-memory profile generation. | Import a current profile before starting a networked role. |
| `VPN_PROFILE_STORE_CLOSED` | 13 | Daemon-lifetime volatile storage has closed and cannot restore keys. | Restart the daemon and import the profile again. |
| `VPN_ENDPOINT_CHECK_REQUIRED` | 13 | The imported generation has not completed endpoint verification. | Run the trusted-host endpoint check before delivery. |
| `VPN_PROFILE_ROTATED` | 13 | The generation changed between endpoint planning and delivery. | Resolve the current generation and rebuild its endpoint policy. |
| `VPN_PROFILE_LIMIT` | 13 | The daemon's bounded volatile profile-name limit was reached. | Remove an unused profile before importing another name. |
| `VPN_PROFILE_BEGIN_REQUIRED` | 13 | The first import frame is absent or not a contextual begin frame. | Start the bounded stream with `VPNProfileImportBegin`. |
| `VPN_PROFILE_STREAM_INVALID` | 13 | Import chunks are empty, oversized, excessive or use an unexpected frame shape. | Send at most 64 non-empty chunks of at most 16 KiB. |
| `VPN_PROFILE_TOO_LARGE` | 13 | Sensitive input exceeds the 64-KiB profile limit. | Generate a standard bounded Proton WireGuard profile. |
| `VPN_PROFILE_SOURCE_UNSAFE` | 13 | The selected source file fails owner, mode, regular-file or no-follow checks. | Use a caller-owned mode-0600 regular file without symlinks. |
| `VPN_PROFILE_READ_FAILED` | 13 | The selected sensitive-input adapter could not read the profile safely. | Select a readable owner-only file or bounded standard input. |
| `VPN_REQUEST_INVALID` | 13 | The CLI VPN intent or local control-socket configuration is invalid. | Use the documented VPN command syntax and installed control socket. |
| `DAEMON_UNAVAILABLE` | 13 | A VPN RPC failed without a valid safe daemon `ErrorDetail`. | Verify `private-vmd` and its Unix control socket, then retry. |

Host-network operations additionally use these stable safe codes:

| Code | Exit | Safe meaning | Remediation |
|---|---:|---|---|
| `NETWORK_REQUEST_INVALID` | 13 | The internal session or opaque VPN-plan network contract is invalid. | Create networking only for an active internal session and current resolved VPN plan. |
| `NETWORK_TOPOLOGY_EXISTS` | 13 | This session already owns a network topology. | Reuse it or complete its verified cleanup before retrying. |
| `NETWORK_COLLISION_EXHAUSTED` | 13 | No collision-free slot was found within the bounded allocation search. | Clean verified private-vm network orphans and retry. |
| `NETWORK_TOPOLOGY_FAILED` | 13 | A semantic namespace, veth, TAP, route or forwarding operation failed. | Run strict diagnostics, clean verified owned resources and retry. |
| `HOST_EGRESS_POLICY_FAILED` | 13 | An exact endpoint nftables transaction failed. | Do not start QEMU; verify nftables support, clean the session network and rebuild from a current VPN plan. |
| `NETWORK_TOPOLOGY_NOT_READY` | 13 | A stale or incomplete network handle was used for a guest handoff. | Complete topology and policy creation or create a new session after cleanup. |
| `NETWORK_CLEANUP_INCOMPLETE` | 24 | At least one owned network resource could not be removed or audited absent. | Keep the session in cleanup state and retry verified cleanup. |
| `GUEST_VPN_REQUEST_INVALID` | 13 | The requested guest role, underlay or lifecycle transition is invalid. | Use the typed online-role workflow and start from a fresh verified guest. |
| `GUEST_KILL_SWITCH_FAILED` | 13 | The guest default-drop policy was not installed atomically. | Do not start guest applications; stop and clean the session. |
| `GUEST_VPN_CONFIGURATION_FAILED` | 13 | WireGuard, routing or tunnel DNS configuration failed. | Keep the kill switch armed, stop the guest and retry with a current profile. |
| `GUEST_VPN_VERIFICATION_FAILED` | 13 | At least one required handshake, tunnel, bypass or binding proof is absent. | Keep applications stopped and run the controlled verification again. |
| `GUEST_VPN_TUNNEL_LOST` | 13 | Continuous verification detected a previously verified tunnel failure. | Keep the kill switch armed, pause network work, and reconnect or stop. |
| `GUEST_VPN_CLEANUP_INCOMPLETE` | 24 | Tunnel or kill-switch teardown did not complete in safe order. | Retain cleanup state and retry tunnel removal before policy removal. |

Guest RPC cancellation and deadline failures use `GUEST_VPN_CANCELLED` and
`GUEST_VPN_TIMEOUT` in gRPC `ErrorDetail`; their CLI projection remains the
canonical cancellation/runtime-timeout mapping.

The redacted VPN status schema uses corresponding state codes
`VPN_ENDPOINT_CHECK_REQUIRED`, `VPN_PROFILE_CURRENT` and
`VPN_PROFILE_ROTATION_REQUIRED`. They contain remediation but never profile,
endpoint, address, DNS, source-path or resolver details. Caller cancellation and
operation timeouts continue to use the canonical CLI/RPC context mappings at
their eventual boundary.

### Torrent

| Code | Exit | Safe meaning |
|---|---:|---|
| `TORRENT_REQUEST_INVALID` | 17 | The current state or typed request is invalid. |
| `TORRENT_STREAM_INVALID` | 17 | The host torrent begin/chunk framing is invalid. |
| `TORRENT_STATE_INVALID` | 17 | The active downloader is not in the required workflow state. |
| `TORRENT_INPUT_INVALID` | 17 | Magnet/metainfo syntax or stream framing is invalid. |
| `TORRENT_INPUT_TOO_LARGE` | 17 | Magnet or metainfo exceeded its fixed bound. |
| `TORRENT_SOURCE_UNSAFE` | 17 | The selected metainfo file failed local regular/no-follow checks. |
| `TORRENT_INPUT_READ_FAILED` | 17 | Secure input could not be read or synchronously transferred. |
| `TORRENT_METADATA_TIMEOUT` | 17 | Paused metadata did not become safely available in time. |
| `TORRENT_METADATA_UNSAFE` | 17 | Metadata contains payload bytes, unsafe paths, collisions or invalid bounds. |
| `TORRENT_SELECTION_INVALID` | 17 | Explicit indexes are absent, duplicate or outside metadata. |
| `TORRENT_EXECUTABLE_BLOCKED` | 17 | Safe policy blocks the selected executable-like type. |
| `TORRENT_CAPACITY_INSUFFICIENT` | 14 | A required encrypted workflow stage lacks conservative capacity. |
| `TORRENT_PAYLOAD_NOT_APPROVED` | 17 | Payload start was requested before selection/capacity approval. |
| `TORRENT_DOWNLOAD_STALLED` | 17 | No bounded progress occurred before the stall ceiling. |
| `TORRENT_DOWNLOAD_FAILED` | 17 | qBittorrent reported invalid state, progress or an operation failure. |
| `TORRENT_VPN_LOST` | 13 | Typed VPN loss paused transfer and requires re-verification. |
| `QUARANTINE_SEAL_FAILED` | 17 | Exact completion/hash/shutdown/sync/unmount proof failed. |
| `DOWNLOADER_CLEANUP_INCOMPLETE` | 24 | Host absence audit failed; scanner readiness remains blocked. |
| `TORRENT_CANCELLED` | 21 | Guest operation was cancelled after a bounded pause attempt. |
| `TORRENT_TIMEOUT` | 15 | Guest operation exceeded its deadline after a bounded pause attempt. |

All messages and remediations omit magnets, torrent identifiers, display/file
names, content hashes, endpoints, source paths and qBittorrent output.

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
- `REPORT_AUTHENTICATION_FAILED`
- `REPORT_KEY_UNAVAILABLE`
- `REPORT_TOO_LARGE`
- `SCANNER_UPDATE_FAILED`
- `SCANNER_UPDATE_QUARANTINE_PRESENT`
- `SCANNER_OVERLAY_MISMATCH`
- `QUARANTINE_MOUNT_UNSAFE`
- `SCAN_OPENAT2_REQUIRED`
- `SCAN_ENTRY_CHANGED`
- `SCAN_SYMLINK_REJECTED`
- `SCAN_HARDLINK_REJECTED`
- `SCAN_SPECIAL_FILE_REJECTED`
- `CLAMAV_UNAVAILABLE`
- `ARCHIVE_PATH_UNSAFE`
- `ARCHIVE_LINK_REJECTED`
- `ARCHIVE_SPECIAL_FILE_REJECTED`
- `ARCHIVE_CLEANUP_INCOMPLETE`
- `SANITIZER_UNSUPPORTED_TYPE`
- `SANITIZED_OUTPUT_INVALID`
- `SANITIZED_OUTPUT_REJECTED`
- `SANITIZED_OUTPUT_CLEANUP_INCOMPLETE`
- `SCANNER_STATE_INVALID`
- `SCANNER_SESSION_MISMATCH`
- `SCANNER_POLICY_INVALID`
- `SCANNER_POLICY_CHANGED`
- `SCANNER_EVIDENCE_UNAVAILABLE`
- `SCANNER_RECEIPT_UNAVAILABLE`
- `SCANNER_RECEIPT_WRITE_FAILED`
- `SCANNER_TOOLCHAIN_UNAVAILABLE`
- `SCAN_CANCELLED`
- `SCAN_TIMEOUT`
- `SCAN_STREAM_FAILED`
- `SANITIZED_OUTPUT_UNAVAILABLE`
- `SANITIZED_OUTPUT_CHANGED`

Scanner guest RPC errors use one `ErrorDetail` containing the same stable code,
safe message, remediation, retryability and current scanner state. Wrapped
filesystem errors, tool output, logical names, hashes and malware signature text
are discarded before status construction. Cancellation uses `Canceled`, timeout
uses `DeadlineExceeded`, bounded limit failures use `ResourceExhausted`, missing
image adapters use `Unavailable`, and phase, policy, isolation, report or output
integrity failures use `FailedPrecondition` unless the request itself is invalid.

### USB

- `USB_NOT_ENROLLED`
- `USB_IDENTITY_MISMATCH`
- `USB_AMBIGUOUS`
- `USB_COMPOSITE_INTERFACE`
- `USB_HOST_FILESYSTEM`
- `USB_MOUNTED`
- `USB_READ_ONLY`
- `USB_TOO_SMALL`
- `USB_CONFIRMATION_REQUIRED`
- `USB_ALREADY_CLAIMED`
- `USB_WRITE_FAILED`
- `USB_HASH_MISMATCH`
- `USB_DISCOVERY_FAILED`
- `USB_CLEANUP_INCOMPLETE`

### Workspace

- `ROLE_START_FAILED`
- `WORKSPACE_DIRTY`
- `WORKSPACE_UNREACHABLE`
- `WORKSPACE_UNEXPORTED`
- `WORKSPACE_CHANGED`
- `WORKSPACE_INVENTORY_FAILED`
- `WORKSPACE_ENTRY_UNSAFE`
- `WORKSPACE_CAPACITY_EXCEEDED`
- `WORKSPACE_HASH_FAILED`
- `WORKSPACE_OUTPUT_NOT_FOUND`
- `WORKSPACE_OUTPUT_CHANGED`
- `IMPORT_STAGING_CONFLICT`
- `IMPORT_TARGET_EXISTS`
- `EXPORT_NOT_STREAMED`
- `EXPORT_VERIFICATION_MISMATCH`
- `IMPORT_PATH_UNSAFE`
- `TRANSFER_BEGIN_REQUIRED`
- `TRANSFER_ID_INVALID`
- `TRANSFER_DESCRIPTOR_INVALID`
- `TRANSFER_SEQUENCE_INVALID`
- `TRANSFER_END_INVALID`
- `TRANSFER_INCOMPLETE`
- `TRANSFER_CANCELED`
- `TRANSFER_SYNC_FAILED`
- `TRANSFER_SIZE_EXCEEDED`
- `TRANSFER_OFFSET_INVALID`
- `TRANSFER_HASH_MISMATCH`

A hard diagnostic marked “never overridable” in the requirements cannot be
suppressed by config, environment or CLI flags.
