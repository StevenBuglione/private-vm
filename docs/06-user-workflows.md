# User guide

`private-vm` is security-sensitive pre-release software. The daemon-backed
workstation, torrent, scanner, VPN and USB command paths are implemented, but
the repository has not passed every target-host, physical-USB, live-Proton,
reboot-recovery and public-release gate. Use synthetic data until the matching
gate in `docs/43-verification-runbook.md` has passed on the machine you intend
to use. A skipped, blocked or unavailable gate is not success.

The complete option and output contract is in `docs/07-cli-reference.md`. This
guide provides the shortest safe operating sequence.

## 1. Install the host integration

NixOS 26.05 is the primary installation target. Add the module to the host
flake as shown in `docs/22-installation.md`, set the exact authorized user, then
rehearse activation with one Nix job and two cores:

```bash
sudo nixos-rebuild build --flake .#HOST --option max-jobs 1 --option cores 2
sudo ./result/bin/switch-to-configuration dry-activate
sudo ./result/bin/switch-to-configuration test
```

Before the first USBGuard activation, disconnect the transfer USB and every
nonessential USB device, retain a local recovery console and verify the prior
NixOS generation is bootable. Check keyboard, pointer and IPv6 connectivity
after the temporary activation. Commit the generation with `switch` only after
those checks pass.

Log out and back in after group membership changes. Then verify the installed
binary, daemon and read-only host preflight:

```bash
private-vm version --json
systemctl is-active private-vmd.service
stat -c '%U %G %a %F' /run/private-vm/control.sock
private-vm doctor --strict --json
```

The socket must be a Unix socket owned by `root` and the configured group with
mode `660`. Strict Doctor must exit 0 before any real session. Do not override a
blocking diagnostic. An unencrypted host root is an explicit warning, while
disk swap, resume/hibernation or missing volatile/encrypted session storage is
blocking.

DEB, RPM and generic-archive installation instructions are also in
`docs/22-installation.md`. The generic archive must be reviewed with
`private-vm system install --dry-run` before `--accept`.

## 2. Understand the current command boundary

These paths are connected to concrete production adapters:

- `version` and read-only `doctor`;
- generic-archive `system install` and `system uninstall`;
- workstation start/display/status/stop and explicit workspace transfer;
- session list/status/stop/abort/cleanup;
- volatile VPN import/inspect/test/rotate/remove;
- torrent start/input/metadata/select/plan/download/pause/resume/status/complete;
- scanner start/status/report/approve/reject; and
- USB list/inspect/enroll/verify/forget/prepare/export.

The following visible v1 commands still deliberately return `NOT_IMPLEMENTED`
instead of simulating success: `init`, standalone `plan`, desktop bundle
catalogue commands, image management commands, session report export, policy
catalogue commands, system status and system diagnostics. Build role images
through the flake outputs documented in `docs/19-image-build.md` until the image
CLI adapter is completed. Encrypted-bundle workspace export is also unavailable.

This distinction matters: the complete Cobra surface is a versioned interface,
not evidence that every adapter has passed acceptance.

## 3. Load a Proton WireGuard profile

Keep the caller-owned profile outside the repository in a mode-`0700`
directory, with the file owned by the invoking user and mode `0600`. Import it
through the bounded file adapter:

```bash
private-vm vpn import --from-file /absolute/private/path/profile.conf
private-vm vpn inspect --json
private-vm vpn test --json
```

The CLI consumes the path; the daemon receives only a bounded stream and keeps
the parsed profile in protected volatile memory. The profile is lost when it is
removed or the daemon restarts. Never pass profile contents through argv or an
environment variable. `vpn inspect` intentionally omits keys, endpoint,
addresses and DNS values.

## 4. Run a graphical workstation

The integrated image CLI adapter is still missing, so an ordinary installation
cannot yet populate the verified runtime cache through `private-vm images`.
Treat workstation and downstream end-to-end use as blocked until that adapter
passes its acceptance gate. Once a verified cache has been populated by the
completed adapter, the operating sequence is:

```bash
private-vm desktop start --bundle basic --memory 3GiB --cpus 2 --json
private-vm session list --json
private-vm desktop connect --session SESSION_ID
```

`desktop start` does not launch the viewer. `desktop connect` runs the trusted
`remote-viewer` as the invoking user against the private Unix display proxy.
Closing the viewer does not stop the VM.

Import exactly one trusted regular file; directories and symlinked path
components are rejected:

```bash
private-vm workspace import /absolute/path/to/file --session SESSION_ID
private-vm workspace list --session SESSION_ID --json
```

Review and select the guest's opaque output identifier, prepare an enrolled USB
as described below, and export only that output:

```bash
private-vm workspace export OUTPUT_ID --to usb --session SESSION_ID
private-vm workspace verify --export OUTPUT_ID --session SESSION_ID
private-vm desktop stop --session SESSION_ID --require-clean
```

If unexported or changed content remains, stop fails closed. Use `--discard`
only when destruction of the whole disposable workspace is intended.

## 5. Run torrent to scanner

This workflow has the same verified-image-cache blocker described above. The
daemon, guest and CLI workflow boundaries are implemented and source-tested;
the following is the exact operating sequence once the image adapter and target
host gates pass.

Start the downloader and submit exactly one secure input source:

```bash
private-vm torrent start --policy safe --json
private-vm torrent add --magnet-tty
# or: private-vm torrent add --torrent-file /absolute/path/file.torrent
private-vm torrent metadata --json
```

Review names and file indexes only inside the isolated downloader display.
Machine output contains aggregate counts, not torrent names or paths. Select the
indexes and downstream destination before payload download:

```bash
private-vm torrent select --files 1,2 --destination usb
private-vm torrent plan --json
private-vm torrent download --json
private-vm torrent status --json
private-vm torrent complete --json
```

Do not continue if the tunnel is lost, capacity evidence is unavailable or the
downloader does not reach the sealed-quarantine state. Start the scanner with
the downloader session ID returned by `session list`:

```bash
private-vm scan start --session DOWNLOADER_SESSION_ID --json
private-vm scan status --session SCANNER_SESSION_ID --json
private-vm scan report --session SCANNER_SESSION_ID --json
```

The scanner must complete its online definitions boot, reboot the same overlay
offline, attach quarantine read-only and produce a complete authenticated
report. Approve exactly one reconstructed output to a new workstation or to the
prepared USB workflow:

```bash
private-vm scan approve --session SCANNER_SESSION_ID --open-in workstation
# or: private-vm scan approve --session SCANNER_SESSION_ID --to usb
```

Any malware finding, limit, skipped file, unsupported active content, stale
definitions or incomplete report blocks promotion. A successful scan is not a
claim that content is safe.

## 6. Enroll and prepare a USB

USB preparation erases the enrolled device. The host must never mount it.
Discovery and enrollment are non-destructive:

```bash
private-vm usb list --json
private-vm usb inspect --device DEVICE_ID --json
private-vm usb enroll --device DEVICE_ID --label PRIVATE_VM_TRANSFER --json
private-vm usb verify --json
```

Compare serial, port, VID/PID, capacity, USBGuard hash, interface list and full
identity fingerprint with the physical device. A serial-less device additionally
requires `--accept-port-binding` at enrollment.

Only in a scheduled destructive window, with the identity rechecked and the
device still unmounted, run:

```bash
private-vm usb prepare --format luks2-ext4 --json
```

Enter both exact displayed confirmations and the LUKS2 passphrase at the
protected terminal prompts. Do not script or save them. Preserve the returned
opaque exporter session and claim IDs, then export one approved scanner output:

```bash
private-vm usb export \
  --session EXPORTER_SESSION_ID \
  --claim CLAIM_ID \
  --scanner-session SCANNER_SESSION_ID \
  --output OUTPUT_ID \
  --json
```

Success requires all three hash-equality fields and every sync, rename,
unmount, detach, exporter-stop and cleanup field to be `true`. Otherwise treat
the export as failed and do not mount the USB on the host.

## 7. Stop and recover

Normal and forced cleanup are semantic daemon operations:

```bash
private-vm session status --session SESSION_ID --json
private-vm session stop --session SESSION_ID
private-vm session abort --session SESSION_ID
private-vm session cleanup --session SESSION_ID
private-vm session cleanup --all
```

Do not manually remove a similarly named process, mapper, interface, namespace
or file. Exact ownership evidence is required. Advanced reboot orphan recovery
still fails closed until exact QEMU/cgroup/network/VSOCK/USB ownership evidence
is integrated; see `docs/28-operations-runbook.md`.

## 8. Verify this checkout

Run the memory-bounded, redacted procedure in
`docs/43-verification-runbook.md`. It explains why the local source evidence
command returns `RELEASE_GATES_INCOMPLETE` after its local cases pass and lists
the separate gates required before real-data use or a release.
