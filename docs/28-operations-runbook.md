# Operations and recovery runbook

## Session will not stop

```bash
private-vm session status --session ID --json
private-vm session abort --session ID
private-vm session cleanup --session ID
private-vm doctor --strict
```

Do not manually delete files before cleanup reports the owning QEMU/mapping/mount.

## Orphaned ciphertext after reboot

Expected when the host lost power. The key was volatile.

```bash
sudo systemctl restart private-vmd
private-vm session cleanup --all
private-vm doctor --strict
```

The daemon validates ownership/naming before deleting.

Startup recovery additionally pins exact object identity, proves there is no
current registry owner, verifies loss of the volatile session key source,
cleans in dependency order, audits the full resource set, and checks that base
images did not change. A machine-readable report is valid only against
`schemas/recovery-report.schema.json`; it intentionally contains counts and
stable codes but no session ID, path, process identity, device identity or
backend output.

An `ORPHAN_CLEANUP_FAILED` or `CLEANUP_INCOMPLETE` result is blocking. Preserve
the volatile report, correct the reported host condition, and retry the command.
Do not manually unlink a similarly named object: a filename is not ownership
evidence.

## VPN test fails

1. Do not continue.
2. Run `private-vm vpn inspect`.
3. Confirm Proton profile includes current endpoint and IPv4/IPv6 default routes.
4. Generate a new Proton WireGuard profile if endpoint is stale.
5. Run `private-vm vpn test`.

Do not weaken host nftables to "make it work."

## Scanner definitions fail

- stop workflow
- do not attach quarantine
- retry with a new scanner overlay

For scanner-core source evidence, run the four bounded commands in
`docs/24-testing.md`. A source pass proves parser, policy, report-MAC and cleanup
behavior only. Before release, also run the scanner update/offline image gates
and KVM corpus workflow; do not infer no-NIC, read-only block attachment,
freshclam success or external reconstruction-tool behavior from unit tests.
- inspect safe error code
- rotate image if engine/database incompatible

Never scan with stale definitions by overriding strict policy.

## Scan reports limit/skipped file

Reject output. Increase a reviewed policy limit only after proving resource
capacity. Restart scanner from clean overlay and rescan everything.

## USB identity changed

Do not export. Inspect the device and re-enroll only if the physical device is
known and expected. A changed interface set is a critical warning.

## Export interrupted

Do not mount on host. Start a fresh exporter verification session. Reformat if
integrity cannot be proven.

## Viewer closed

The VM may still run:

```bash
private-vm desktop status
private-vm desktop connect
```

Closing remote-viewer does not imply teardown.

## Daemon upgrade with active session

Supported behavior: package manager should refuse/recommend stopping sessions.
Do not hot-restart daemon during active workflow unless recovery compatibility is
tested.

## Security incident

1. disconnect network if host compromise suspected
2. stop using exports from affected session
3. preserve only explicitly requested diagnostic evidence
4. record image and binary digests
5. revoke affected release digest if supply-chain issue
6. publish advisory and fixed version
7. do not overstate containment
