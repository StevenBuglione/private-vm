# RPC protocol

## Transport selection

- CLI to daemon: gRPC over Unix-domain socket.
- Daemon to guest: gRPC over AF_VSOCK.
- QEMU lifecycle: QMP JSON over Unix-domain socket.

The protobuf files in `api/privatevm/v1/` are the source of truth.

## Authentication

### CLI to daemon

The daemon obtains Unix peer credentials from the accepted socket and associates
the RPC with UID, GID, and PID. The socket is owned by `root:private-vm` and mode
`0660`.

Destructive USB operations also require a Polkit authorization decision.

### Daemon to guest

For every boot:

1. daemon allocates unique guest CID
2. daemon creates random 32-byte token in locked volatile memory
3. QEMU receives token via `fw_cfg` from inherited FD
4. guestd reads token from sysfs
5. gRPC metadata includes `x-private-vm-session-token`
6. token is compared in constant time
7. guest role and image identity are verified

Token is never persisted in image or disk.

## Versioning

```text
protocol_major
protocol_minor
```

- Major mismatch: refuse.
- Guest minor lower than required capability: refuse.
- Unknown optional fields: ignore according to protobuf behavior.
- Every capability is explicit.

## Streaming

File streams use:

```text
Begin:
  transfer_id
  relative_name
  expected_size
  expected_sha256
  media_type
Chunks:
  sequence
  bytes (<= 1 MiB)
End:
  total_size
  sha256
```

Rules:

- no absolute paths
- no `..`
- no NUL
- UTF-8 normalized display names
- receiver chooses final local path
- size checked before allocation
- cumulative byte limit
- deadline and idle timeout
- hash computed while streaming
- partial output deleted on failure
- no automatic overwrite

## Daemon services

Core methods:

- `GetVersion`
- `Doctor`
- `PlanSession`
- `CreateSession`
- `GetSession`
- `ListSessions`
- `StartRole`
- `StopRole`
- `AbortSession`
- `CleanupSession`
- `StreamEvents`
- `ImportWorkspaceFile`
- `ExportWorkspaceFile`
- `ClaimUSB`
- `ReleaseUSB`

No arbitrary command execution method is permitted.

## Guest services

Shared:

- `Hello`
- `GetStatus`
- `Shutdown`
- `StreamEvents`

Workstation:

- `GetWorkspaceState`
- `ImportFile`
- `ListExportFiles`
- `ExportFile`
- `MarkExportVerified`
- `ShowNetworkWarning`

Downloader:

- `ConfigureWireGuard`
- `VerifyVPN`
- `AddTorrent`
- `GetTorrentMetadata`
- `SelectTorrentFiles`
- `StartDownload`
- `PauseDownload`
- `GetDownloadStatus`
- `SealQuarantine`

Scanner:

- `UpdateDefinitions`
- `GetDefinitionsStatus`
- `VerifyOfflineMode`
- `Inventory`
- `Scan`
- `Reconstruct`
- `GetScanReport`
- `ExportApprovedFile`

Exporter:

- `InspectUSB`
- `PrepareUSB`
- `WriteFile`
- `VerifyFile`
- `FinalizeUSB`

## Error model

gRPC status is accompanied by typed `ErrorDetail`:

```text
code
safe_message
remediation
retryable
session_state
field_violations[]
```

Never return a private key, magnet link, full sensitive path, or unredacted file
content in an error.
