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

### System

```text
private-vm system status
private-vm system install --dry-run
private-vm system install --accept
private-vm system uninstall --dry-run
```

### Completion

```text
private-vm completion bash
private-vm completion zsh
private-vm completion fish
```

## Stable machine output

JSON errors use:

```json
{
  "ok": false,
  "code": "VPN_DIRECT_EGRESS_SUCCEEDED",
  "exit_code": 13,
  "message": "Direct IPv4 egress was reachable outside proton0.",
  "remediation": "Do not continue. Inspect the host namespace and guest nftables policy.",
  "session_id": "optional"
}
```

Human output may change cosmetically; codes and schema versions follow semantic
versioning.
