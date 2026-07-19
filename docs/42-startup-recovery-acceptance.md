# Startup recovery source acceptance

This record describes the local source-only D-005 recovery evidence. It does
not claim a host reboot, a real daemon crash, or mutation of real QEMU,
networking, mapper, mount, USB or ciphertext resources. Filesystem tests remove
only private temporary records and synthetic ciphertext.

## Implemented boundary

`internal/recovery` provides one sequential startup reconciliation owner with:

- bounded trusted inventory and closed resource kinds;
- opaque internal session IDs plus exact ownership fingerprints that the
  backend must recompute before mutation;
- an atomic recovery claim that excludes current/live registry owners;
- mandatory volatile-key-loss evidence for storage-bearing sessions;
- whole-session identity pinning before the first mutation and a second
  revalidation immediately before each operation;
- fixed dependency ordering across QEMU/process, cgroup, QMP/SPICE sockets,
  VSOCK CID, TAP/veth/netns/nftables, USB claim, outer mount, mapper, loop,
  ciphertext and runtime path;
- idempotent per-object cleanup and absence audit followed by a complete
  cross-subsystem session audit;
- an immutable-base image seal captured before and verified after recovery; and
- a closed version-1 report with aggregate counts and safe codes only.

The reconciler has no arbitrary command, path-removal or cleanup-priority API.
It runs no detached goroutine and never serializes candidate locators or exact
identity evidence.

## Reproducible local gate

Run serially on a 16 GiB host:

```text
GOMAXPROCS=2 go test -p=1 ./internal/recovery
GOMAXPROCS=2 go test -race -p=1 ./internal/recovery
GOMAXPROCS=2 go vet ./internal/recovery
python3 tools/validate_schemas.py
python3 tools/validate_examples.py
```

The tests cover success, inventory rejection, duplicate/owner conflict,
volatile key present/unknown, exact identity replacement before and after the
whole-session pin, cancellation, timeout, cleanup failure, individual and
whole-session audit failure, retry convergence, independent-session progress,
immutable-base drift, stable ordering, fixed bounds and report redaction.

## Production integration now present

`private-vmd` constructs the Linux backend, volatile-key evidence, startup-only
claim registry and immutable-cache auditor before it creates the ordinary
session manager or opens the control socket. It writes the closed report
atomically under `/run`; an incomplete recovery or report-write failure refuses
startup.

The Linux adapter uses the pinned session store and a root-owned mode-`0700`
scratch root with the required no-backup marker. It supports exact
descriptor-relative socket/runtime cleanup and typed outer mount,
`cryptsetup close`, `losetup --detach` and ciphertext unlink operations. Every
candidate is re-inventoried immediately before mutation and individually audited
afterward. External command output is discarded and never enters errors or the
report.

Source tests use only private temporary roots and fakes. They cover early-record
and ciphertext success, key-unknown retention, advanced-session refusal,
identity replacement, cancellation/timeout propagation, cleanup/audit,
immutable-cache drift, closed report publication and daemon startup refusal.

## Remaining D-005 system gates

D-005 remains open for advanced daemon-restart recovery. The current volatile
journal does not retain the exact QEMU pidfd/start-time/executable/cgroup,
network, VSOCK CID and USB claim identities. When such a journal is at
`STORAGE_READY` or later, startup stops before any mutation with a closed
identity failure. Completing this gate must reuse the verified identities
already owned by the session, QEMU, network, VSOCK and USB packages; it must not
replace them with name-only discovery.

The final acceptance run must then prove:

1. CLI `SIGKILL` does not revoke daemon-owned cleanup.
2. Daemon `SIGKILL` leaves only candidates that the restarted daemon exactly
   revalidates and removes.
3. A controlled reboot makes the process-held key source unavailable, closes
   any surviving mapper state and removes unusable ciphertext.
4. The full absence audit finds no QEMU, cgroup, socket, CID, namespace,
   interface, nftables object, loop, mapper, mount, USB claim, ciphertext or
   runtime record.
5. Immutable verified base images retain the same exact identities.

All system evidence must remain redacted. A failed or skipped check is blocking;
neither source fakes nor an empty inventory satisfy the reboot gate.
