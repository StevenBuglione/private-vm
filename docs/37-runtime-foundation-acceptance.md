# Runtime foundation acceptance evidence

This record captures the local, redacted acceptance evidence for Batch 1 on
2026-07-19. It covers `D-002`, the source-level portion of `D-003`, and
`STOR-001` through `STOR-003`. The host was NixOS 26.05 with Go 1.26.5 and
QEMU 10.2.4. All heavy checks ran serially with `max-jobs = 1`, `cores = 2`,
`GOMAXPROCS=2`, and no swap.

No VPN profile, magnet, filename, file content, endpoint, or other session
secret was used by these tests or written to their output.

## Task evidence

| Task | Implemented boundary | Acceptance evidence |
| --- | --- | --- |
| `D-002` | One serialized actor per session, replayable bounded event stream, per-user quotas, daemon-owned cleanup, atomic resource registration, and strict volatile record replay | Illegal and forged transitions are rejected; concurrent transitions pass the race detector; cleanup is coalesced and retryable; caller cancellation and client disconnect do not cancel daemon-owned cleanup; restart replay rejects malformed or impossible histories |
| `D-003` | Typed role/device launch specifications, trusted executable and socket identities, QMP handshake/events, peer-credential checks, pidfd/cgroup ownership, and bounded powerdown/quit/TERM/KILL escalation | Shell/raw argument escape hatches, TCP display, shared filesystems, and unsafe socket paths are rejected; fake-QEMU success, timeout, cancellation, disconnect, process death, QMP loss, and cleanup paths pass; QMP input fuzzing does not panic |
| `STOR-001` | Read-only base validation, fresh QCOW2 overlays, strict bounded `qemu-img` JSON, image-use leases, and identity-safe deletion | Writable bases and replacement races are rejected; active images cannot be inspected or modified through the wrapper; overlay deletion is idempotent and verifies the original inode |
| `STOR-002` | Bounded memory/swap/filesystem probes, immutable capacity snapshots, atomic reservations, and exact tmpfs ownership | Disk swap blocks admission; memory overcommit is rejected before allocation; concurrent reservations cannot exceed the pool; cancellation and allocation failures retain cleanup ownership until tmpfs teardown succeeds |
| `STOR-003` | Memfd-backed random key, LUKS2 outer container, verified loop/mapper devices, opaque QEMU files, explicit backup-exclusion marker, and reverse-order cleanup | Key material is delivered by file descriptor and destroyed; partial failures at attach/format/open/mkfs/mount preserve retryable cleanup state; repeated cleanup is harmless; only the outer filesystem is host-mounted |

`D-003` also depends on `NIX-003`. The source and fake-runtime acceptance is
complete, and the common guest boot test passes, but the issue remains open
until the workstation image boot evidence is completed in Batch 2.

## Commands and results

The following commands completed successfully from the Batch 1 worktree:

```text
GOMAXPROCS=2 go test -p=1 ./...
GOMAXPROCS=2 go test -race -p=1 ./...
GOMAXPROCS=2 go vet ./...
staticcheck ./...
govulncheck ./...
buf lint
buf breaking --against the main branch
python3 tools/validate_schemas.py
python3 tools/validate_examples.py
go test ./internal/session -run '^$' -fuzz '^FuzzDecodeStoredSession$' -fuzztime=2s -parallel=1
go test ./internal/qemu -run '^$' -fuzz '^FuzzQMPInput$' -fuzztime=2s -parallel=1
nix flake check --offline --no-build
nix build .#checks.x86_64-linux.runtime-fuzz
nix build .#checks.x86_64-linux.host-module-contract
nix build .#checks.x86_64-linux.guest-common
gitleaks dir . --redact --no-banner --exit-code 1
```

The complete Go unit, race, vet, static-analysis, schema, protobuf, secret-scan,
and Nix source gates passed. The `guest-common` NixOS VM booted under QEMU and
completed its role/capability, no-SSH, volatile-journal, and guest-agent checks.
The workstation desktop boot remains a Batch 2 gate.

## Residual scope

This evidence does not claim that startup orphan reconciliation, workstation
desktop orchestration, the downloader/scanner/exporter workflows, packaging,
or release verification are complete. Those boundaries remain fail closed and
are assigned to later batches in `docs/25-implementation-roadmap.md`.
