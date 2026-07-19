# Generic Linux installer acceptance

## Artifact contract

`packages.x86_64-linux.generic-archive` produces one deterministic
`tar.zst` tree. The archive contains only the two host binaries, non-secret
default configuration, systemd/Polkit/tmpfiles/sysusers/udev integration,
documentation, completions and a closed `manifest.json`.

`manifest.json` is schema version 1 and binds every allowed source to one fixed
absolute destination, byte count, mode and SHA-256. The Go decoder is bounded,
rejects unknown/duplicate/trailing fields and requires the exact sixteen-entry
mapping. Installation hashes every regular non-symlink input before mutation
and again while copying it. A caller cannot add a destination, request a mount,
run a command or select arbitrary systemd units.

The only persistent installation record is
`/usr/share/private-vm/install-manifest.json`; it contains public package hashes
and no session or credential data. Uninstall verifies every non-configuration
installed file against that record before stopping the service or removing a
path.

## Transaction semantics

`private-vm system install --dry-run` performs all compatibility, manifest,
bundle and target-type checks without mutation. `--accept` additionally
requires root, stages each replacement beside its destination, synchronizes it,
and retains the prior file until the complete fixed-path copy succeeds.

Activation has four typed, exact operations: systemd-sysusers for the one group,
systemd-tmpfiles for declared directories, `systemctl daemon-reload`, and
`systemctl enable --now private-vmd.service`. The command runner uses an empty
environment, discards output and has a 45-second ceiling. It exposes no generic
subprocess API. Install/upgrade is blocked while the daemon is active, so an
active session is never hot-upgraded.

Failure, cancellation or timeout reverses file replacements and disables a
partially activated service. Failure to prove rollback or delete staging data
returns `SYSTEM_ROLLBACK_INCOMPLETE` with exit 24. Configuration, image cache,
enrollment state and user exports are never removal targets.

## Lightweight source evidence

```bash
GOMAXPROCS=2 go test -p=1 ./internal/systeminstall ./internal/cli ./cmd/private-vm
go vet ./internal/systeminstall ./internal/cli ./cmd/private-vm
python3 tools/validate_schemas.py
python3 tools/validate_examples.py
nix eval --raw .#generic-archive.drvPath
```

The tests cover success, preflight failure, non-root refusal, cancellation,
timeout, content tampering, symlink rejection, activation rollback,
configuration/cache preservation, uninstall and pre-deactivation installed-file
verification.

## System gates still required

Source evidence does not prove the archive builds, decompresses identically,
activates on a distribution host, or survives a package upgrade. The release
runbook must execute these gates serially in fresh Ubuntu, Debian and Fedora
VMs:

1. build the archive and verify its release digest, SPDX and provenance;
2. extract as an unprivileged user and run root `--dry-run` then `--accept`;
3. verify group, files/modes, daemon/socket and `doctor --strict --json`;
4. prove an active daemon blocks an upgrade;
5. stop/clean sessions, upgrade, and prove configuration/cache hashes unchanged;
6. run uninstall dry-run/accept and prove no daemon/process/unit remains; and
7. prove configuration, image cache and user exports remain.
