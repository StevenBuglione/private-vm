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
- [ ] hook-free package contract check
- [ ] generic install manifest and rollback tests
- [ ] package runbook redacted JSON/JUnit evidence

## Supply chain

- [ ] SHA-256
- [ ] SPDX SBOM
- [ ] all six fixed GHCR repositories selected by exact role/bundle mapping
- [ ] OCI digest and exact empty config/four-layer graph
- [ ] canonical SemVer or `-rc.N` tag was absent and was not overwritten
- [ ] GitHub artifact attestation binds `image.qcow2.zst` and its exact SHA-256
- [ ] saved Sigstore bundle passes local `NewOfficialVerifier` before publish
- [ ] version-1 release receipt validates and contains no credential/path/output
- [ ] protected `image-publish` environment rules verified in GitHub settings
- [ ] all six package versions are public without workflow visibility mutation
- [ ] clean fresh-runner anonymous digest pull succeeds for all six images
- [ ] exact repository/workflow/ref/numeric-ID/invocation verification succeeds
- [ ] revocation list checked
- [ ] normalized reproducibility comparison
- [ ] closed whole-release index binds three packages and six image digests
- [ ] protected `release` environment rules verified in GitHub settings
- [ ] partial-draft rollback and exact draft absence recorded
- [ ] fresh read-only runner verifies the exact 13 package-release assets anonymously

Local source and policy tests may be recorded without waiting for the remote
image workflow. Do not check any protected-environment, actual publication,
package-visibility, OIDC or anonymous-pull item until the corresponding remote
run has completed successfully and its immutable run URL and commit are saved
in the release record.

Run the fixed source evidence producer inside the pinned development shell:

```bash
private-vm-release-acceptance \
  --workdir "$PWD" \
  --json /tmp/private-vm-release-source.json \
  --junit /tmp/private-vm-release-source.junit.xml
```

Its expected source-only terminal result is `RELEASE_GATES_INCOMPLETE`; the
JSON/JUnit files distinguish passed source checks from unavailable live gates.

## Documentation

- [ ] install
- [ ] upgrade
- [ ] quick start
- [ ] CLI
- [ ] limitations
- [ ] privacy wording
- [ ] SECURITY.md
- [ ] source links and versions
