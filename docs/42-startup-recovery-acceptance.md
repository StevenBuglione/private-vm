# Startup recovery source acceptance

This record describes the local source-only D-005 recovery evidence. It does
not claim a host reboot, a real daemon crash, or mutation of QEMU, networking,
storage, mapper, mount, USB or ciphertext resources.

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

## Remaining D-005 system gates

D-005 remains open until the concrete Linux inventories and typed cleanup
adapters are composed into `private-vmd` before session admission. That
integration must reuse the verified identities already owned by the session,
QEMU, storage, network, VSOCK and USB packages; it must not replace them with
name-only discovery.

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
