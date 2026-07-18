# Error and diagnostic catalog

Codes are stable API. Human wording may improve without changing the code.

## Exit-code classes

| Code | Meaning |
|---:|---|
| 0 | success |
| 2 | CLI usage |
| 10 | host or plan preflight blocked |
| 11 | image trust failure |
| 12 | authorization failure |
| 20 | runtime failure |
| 30 | scan/policy rejection |
| 31 | transfer/export failure |
| 40 | cleanup incomplete |
| 70 | internal invariant failure |

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
