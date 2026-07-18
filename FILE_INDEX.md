# File index

This package contains 130 files before `MANIFEST.sha256`.

The controlling entry points are `HANDOFF_PROMPT.md`, `START_HERE.md`,
`DESIGN_FREEZE.md`, `docs/00-master-plan.md` and `project/backlog.yaml`.

## `.github/`

- `.github/dependabot.yml` — 259 bytes
- `.github/workflows/ci.yml` — 1,980 bytes
- `.github/workflows/image-build.yml.template` — 1,602 bytes
- `.github/workflows/release.yml.template` — 918 bytes

## `api/`

- `api/privatevm/v1/common.proto` — 1,472 bytes
- `api/privatevm/v1/daemon.proto` — 3,171 bytes
- `api/privatevm/v1/guest.proto` — 3,721 bytes

## `cmd/`

- `cmd/private-vm/main.go` — 3,673 bytes
- `cmd/private-vm/main_test.go` — 560 bytes
- `cmd/private-vm-guestd/main.go` — 913 bytes
- `cmd/private-vmd/main.go` — 662 bytes

## `docs/`

- `docs/00-master-plan.md` — 17,790 bytes
- `docs/01-requirements.md` — 6,685 bytes
- `docs/02-threat-model.md` — 6,455 bytes
- `docs/03-architecture.md` — 3,990 bytes
- `docs/04-security-boundaries.md` — 3,260 bytes
- `docs/05-state-machines.md` — 2,922 bytes
- `docs/06-user-workflows.md` — 2,835 bytes
- `docs/07-cli-reference.md` — 5,098 bytes
- `docs/08-config-policy.md` — 2,032 bytes
- `docs/09-rpc-protocol.md` — 2,914 bytes
- `docs/10-go-architecture.md` — 3,904 bytes
- `docs/11-qemu-runtime.md` — 3,711 bytes
- `docs/12-networking-vpn.md` — 3,567 bytes
- `docs/13-storage-ephemerality.md` — 3,644 bytes
- `docs/14-images-desktop.md` — 2,993 bytes
- `docs/15-torrent-workflow.md` — 2,269 bytes
- `docs/16-scanning-sanitization.md` — 3,769 bytes
- `docs/17-workspace-transfer.md` — 2,022 bytes
- `docs/18-usb-export.md` — 2,360 bytes
- `docs/19-image-build.md` — 2,586 bytes
- `docs/20-ci-cd.md` — 3,244 bytes
- `docs/21-supply-chain.md` — 3,123 bytes
- `docs/22-installation.md` — 3,008 bytes
- `docs/23-privacy-observability.md` — 1,920 bytes
- `docs/24-testing.md` — 2,896 bytes
- `docs/25-implementation-roadmap.md` — 4,177 bytes
- `docs/26-risk-register.md` — 2,559 bytes
- `docs/27-release-checklist.md` — 1,559 bytes
- `docs/28-operations-runbook.md` — 2,295 bytes
- `docs/29-open-source-governance.md` — 1,791 bytes
- `docs/30-sources.md` — 2,316 bytes
- `docs/31-agent-execution-contract.md` — 2,142 bytes
- `docs/32-data-model.md` — 2,310 bytes
- `docs/33-error-catalog.md` — 2,077 bytes
- `docs/34-security-review-checklists.md` — 2,403 bytes
- `docs/35-reproducible-build-contract.md` — 1,772 bytes
- `docs/36-local-development.md` — 1,310 bytes
- `docs/adrs/0001-nixos-canonical-images.md` — 929 bytes
- `docs/adrs/0002-direct-qemu.md` — 779 bytes
- `docs/adrs/0003-four-role-isolation.md` — 652 bytes
- `docs/adrs/0004-xfce-spice.md` — 560 bytes
- `docs/adrs/0005-grpc-unix-vsock.md` — 632 bytes
- `docs/adrs/0006-two-layer-network.md` — 622 bytes
- `docs/adrs/0007-ephemeral-luks.md` — 596 bytes
- `docs/adrs/0008-exporter-vm.md` — 594 bytes
- `docs/adrs/0009-ghcr-oci-attestations.md` — 580 bytes
- `docs/adrs/0010-no-shell-product-logic.md` — 604 bytes

## `examples/`

- `examples/config.example.toml` — 687 bytes
- `examples/image-manifest.example.json` — 1,021 bytes
- `examples/policy.quarantine.toml` — 498 bytes
- `examples/policy.safe.toml` — 480 bytes
- `examples/scan-report.example.json` — 1,082 bytes
- `examples/usb-enrollment.example.json` — 299 bytes

## `internal/`

- `internal/buildinfo/buildinfo.go` — 662 bytes
- `internal/commandexec/commandexec.go` — 1,064 bytes
- `internal/commandexec/commandexec_test.go` — 242 bytes
- `internal/exitcode/exitcode.go` — 226 bytes
- `internal/image/manifest.go` — 2,304 bytes
- `internal/image/manifest_test.go` — 887 bytes
- `internal/policy/decision.go` — 1,149 bytes
- `internal/policy/decision_test.go` — 699 bytes
- `internal/preflight/diagnostic.go` — 520 bytes
- `internal/preflight/doctor.go` — 2,526 bytes
- `internal/preflight/doctor_test.go` — 207 bytes
- `internal/qemu/spec.go` — 4,804 bytes
- `internal/qemu/spec_test.go` — 1,113 bytes
- `internal/runtime/interfaces.go` — 1,502 bytes
- `internal/secret/secret.go` — 820 bytes
- `internal/secret/secret_test.go` — 358 bytes
- `internal/session/model.go` — 2,004 bytes
- `internal/session/model_test.go` — 324 bytes
- `internal/transfer/frame.go` — 1,851 bytes
- `internal/transfer/frame_test.go` — 767 bytes
- `internal/usb/identity.go` — 1,424 bytes
- `internal/usb/identity_test.go` — 343 bytes

## `nix/`

- `nix/guests/desktop-common.nix` — 1,429 bytes
- `nix/guests/downloader.nix` — 333 bytes
- `nix/guests/exporter.nix` — 367 bytes
- `nix/guests/image-base.nix` — 1,816 bytes
- `nix/guests/scanner.nix` — 451 bytes
- `nix/guests/workstation-basic.nix` — 90 bytes
- `nix/guests/workstation-development.nix` — 228 bytes
- `nix/guests/workstation-office.nix` — 182 bytes
- `nix/modules/host.nix` — 2,912 bytes

## `packaging/`

- `packaging/default/config.toml` — 687 bytes
- `packaging/polkit/org.private-vm.policy` — 1,073 bytes
- `packaging/systemd/private-vmd.service` — 830 bytes
- `packaging/tmpfiles/private-vm.conf` — 173 bytes
- `packaging/udev/90-private-vm.rules` — 281 bytes

## `project/`

- `project/DEFINITION_OF_DONE.md` — 676 bytes
- `project/FIRST_10_COMMITS.md` — 1,331 bytes
- `project/acceptance-tests.yaml` — 7,993 bytes
- `project/backlog.yaml` — 28,689 bytes
- `project/milestones.yaml` — 1,896 bytes

## `references/`

- `references/graphical-workstation-draft.md` — 22,324 bytes
- `references/product-architecture-draft.md` — 38,198 bytes

## Top-level files

- `.gitignore` — 124 bytes
- `AGENTS.md` — 3,754 bytes
- `CODEOWNERS.example` — 312 bytes
- `CONTRIBUTING.md` — 1,265 bytes
- `DESIGN_FREEZE.md` — 2,007 bytes
- `FILE_INDEX.md` — 6,460 bytes
- `HANDOFF_PROMPT.md` — 1,936 bytes
- `LICENSE` — 11,358 bytes
- `Makefile` — 424 bytes
- `README.md` — 2,972 bytes
- `SECURITY.md` — 1,307 bytes
- `START_HERE.md` — 1,537 bytes
- `VALIDATION.md` — 1,655 bytes
- `buf.gen.yaml` — 180 bytes
- `buf.yaml` — 91 bytes
- `flake.nix` — 4,068 bytes
- `go.mod` — 53 bytes

## `schemas/`

- `schemas/config.schema.json` — 3,623 bytes
- `schemas/image-manifest.schema.json` — 2,323 bytes
- `schemas/policy.schema.json` — 2,528 bytes
- `schemas/scan-report.schema.json` — 2,995 bytes

## `tools/`

- `tools/validate_examples.py` — 629 bytes
- `tools/validate_schemas.py` — 780 bytes
