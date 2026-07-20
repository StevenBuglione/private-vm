# User workflows

## Initial setup on NixOS

```bash
nix flake init
# Add private-vm input/module as shown in docs/22-installation.md
sudo nixos-rebuild switch --flake .#your-host

private-vm init
private-vm doctor --strict
private-vm images sync
private-vm vpn import
private-vm usb enroll
```

`vpn import` securely prompts for an existing owner-only profile path; use
`--from-file FILE` or `--stdin` to select an explicit non-interactive source.
The imported key is not copied into ordinary configuration.

## Start a graphical workstation

```bash
private-vm desktop start --bundle development
```

Expected output:

```text
[PASS] Host preflight
[PASS] Workstation image digest and provenance
[PASS] Ephemeral encrypted session store
[PASS] Host Proton endpoint allowlist
[PASS] Guest WireGuard handshake
[PASS] IPv4 direct-egress leak test
[PASS] IPv6 direct-egress leak test
[PASS] DNS tunnel test
[READY] Opening private workstation
```

## Import a trusted host file

```bash
private-vm workspace import ./design-notes.pdf
```

The CLI displays size and hash before transfer. The guest writes it to
`~/Inbox/design-notes.pdf`.

## Export workstation output

Inside the guest, save output under `~/Export`.

```bash
private-vm workspace list
private-vm workspace export --to usb
private-vm workspace verify --last
private-vm desktop stop --require-clean
```

## Torrent workflow

```bash
private-vm run torrent
```

The CLI prompts without echo:

```text
Select input:
  1) magnet link
  2) .torrent file
```

After metadata:

```text
Torrent metadata received.
3 files, 18.4 GiB total.

[1] video.mkv         18.1 GiB  media
[2] notes.txt         12 KiB    text
[3] installer.exe     310 MiB   executable (blocked by safe policy)

Select files: 1,2
```

The plan shows:

```text
Download selected:             18.1 GiB
Quarantine reserve:            20.0 GiB
Scanner temporary reserve:     40.0 GiB
Reconstructed output estimate: 22.0 GiB
USB free capacity:              55.4 GiB
Policy:                         safe
Result:                         PASS
```

## Scan report

```bash
private-vm scan report --session <id>
```

Example verdicts:

```text
APPROVED_SANITIZED
REJECTED_MALWARE
REJECTED_SCAN_LIMIT
REJECTED_ENCRYPTED_ARCHIVE
REJECTED_UNSUPPORTED_EXECUTABLE
REJECTED_POLICY
ERROR_INCOMPLETE
```

## Open sanitized output in a new workstation

```bash
private-vm scan approve --session <id> --open-in workstation
```

The daemon starts a fresh, unadvertised workstation as the authenticated
receiver and streams the single approved reconstructed output directly into
its Inbox. No host path or mount exists. It verifies scanner, relay and
workstation SHA-256 equality, destroys the scanner, then returns the destination
session ID and opens the user-owned Unix-socket viewer. Any earlier failure
destroys the fresh workstation too. A report with zero or multiple outputs
fails closed in v1 because the CLI intentionally does not expose output IDs.

## Abort

```bash
private-vm session abort --session <id>
```

The CLI returns only after cleanup audit or returns a specific cleanup failure
that `private-vm session cleanup --session <id>` can remediate. Recovery of all
verified private-vm-owned orphans uses `private-vm session cleanup --all`.

## JSON automation

```bash
private-vm doctor --strict --json
private-vm plan torrent --json < request.json
private-vm session status --session <id> --json
```

Sensitive values are never accepted through JSON files.
