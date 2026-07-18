# Historical blueprint validation report

Generated on 2026-07-18.

> This report records the original handoff environment and is retained as
> provenance. It is superseded by the current CI results, task issue evidence,
> and executable workflows documented under `docs/`. Statements below about
> missing dependencies, unavailable Nix, or future GO-001/NIX-001 work describe
> only that historical handoff and are not current project status.

## Completed successfully

```text
gofmt over cmd/ and internal/
go test ./...
go vet ./...
go build -trimpath:
  cmd/private-vm
  cmd/private-vmd
  cmd/private-vm-guestd
python3 tools/validate_schemas.py
python3 tools/validate_examples.py
YAML parsing of machine-readable project files
ZIP integrity test
```

The Go starter compiled with the locally available Go 1.23.2 compiler. It uses no
third-party Go dependencies and remains compatible with that compiler solely so
this artifact could be validated offline. Task `GO-001` must update and pin the
public project to Go 1.26.5, regenerate dependency metadata and rerun all tests.

## Not completed in this environment

Nix was not installed, so `flake.nix`, the host module and NixOS image modules
were not evaluated. `NIX-001` is deliberately the first Nix task. It must:

1. commit `flake.lock` against NixOS 26.05;
2. validate the exact current image-build output name;
3. validate every package and module option;
4. build and TCG-boot `workstation-basic`.

No QEMU/KVM, network namespace, Proton, ClamAV, USBGuard, cryptsetup or
destructive USB integration test was performed. Those tests belong to the
implementation milestones and dedicated test environments.

## Safety status

This archive is a specification and starter scaffold, not an operational
security release. Only `version` and the starter `doctor` command are implemented.
Every other security-sensitive CLI path intentionally returns a not-implemented
failure until its backlog task and acceptance tests pass.

Do not use the starter to process sensitive or untrusted data.
