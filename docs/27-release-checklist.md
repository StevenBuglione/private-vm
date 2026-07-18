# Release checklist

## Source

- [ ] version and changelog
- [ ] clean protected tag
- [ ] CODEOWNERS approvals
- [ ] all ADRs current
- [ ] threat model reviewed
- [ ] no unresolved critical/high security issue

## Go

- [ ] format/vet/test/race
- [ ] govulncheck
- [ ] fuzz smoke
- [ ] vendored modules match go.mod
- [ ] reproducible flags
- [ ] no secret logging regression

## Nix/images

- [ ] flake locked to supported NixOS release
- [ ] all role images build
- [ ] TCG boot tests
- [ ] KVM acceptance
- [ ] role/capability manifest
- [ ] no SSH
- [ ] volatile logs
- [ ] image size budget
- [ ] base images read-only expectation

## Security workflows

- [ ] direct IPv4 leak blocked
- [ ] direct IPv6 leak blocked
- [ ] DNS leak blocked
- [ ] qBittorrent bound to proton0
- [ ] scanner offline
- [ ] quarantine read-only
- [ ] scan-limit rejection
- [ ] malicious archive corpus
- [ ] USB exporter only
- [ ] dirty-workspace stop protection
- [ ] crash cleanup matrix

## Packaging

- [ ] NixOS module
- [ ] RPM
- [ ] DEB
- [ ] generic archive
- [ ] dependency install tests
- [ ] upgrade/uninstall tests
- [ ] completions and man pages

## Supply chain

- [ ] SHA-256
- [ ] SPDX SBOM
- [ ] OCI digest
- [ ] GitHub artifact attestation
- [ ] clean-runner anonymous pull
- [ ] repository/workflow verification
- [ ] revocation list checked
- [ ] normalized reproducibility comparison

## Documentation

- [ ] install
- [ ] upgrade
- [ ] quick start
- [ ] CLI
- [ ] limitations
- [ ] privacy wording
- [ ] SECURITY.md
- [ ] source links and versions
