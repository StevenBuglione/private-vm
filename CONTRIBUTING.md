# Contributing

Read `START_HERE.md`, `AGENTS.md`, the applicable ADRs and the threat model before
writing code.

## Required workflow

1. Choose one task from `project/backlog.yaml`.
2. Add or update tests before changing security behavior.
3. Keep product logic in Go or Nix; do not add lifecycle shell scripts.
4. Run `go test ./...`, `go vet ./...`, schema validation and relevant Nix checks.
5. Update documentation and the risk register when a boundary changes.
6. Keep commits narrow and include the task ID.

## Pull-request requirements

- no unresolved blocking diagnostics;
- no new third-party dependency without rationale and license review;
- no action referenced by a mutable tag in release workflows;
- generated protobuf code must match checked-in `.proto` files;
- security-invariant changes require two maintainers;
- behavior changes include upgrade and rollback notes.

## Coding rules

- pass arguments directly to executables; never invoke a shell;
- use absolute executable paths in the privileged daemon;
- bound every stream, buffer and timeout;
- treat paths, device metadata, image metadata and guest messages as untrusted;
- do not log torrent names, file names, VPN material or content hashes by default;
- cleanup must be idempotent.
