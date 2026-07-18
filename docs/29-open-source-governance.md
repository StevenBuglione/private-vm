# Open-source governance

## Repository

Recommended:

```text
github.com/StevenBuglione/private-vm
```

## Branch protection

- pull request required
- two approvals for security-sensitive paths when maintainers allow
- CODEOWNERS
- dismiss stale approvals
- signed commits/tags recommended
- required CI
- no force push
- protected release environment
- tag creation restricted

## CODEOWNERS areas

```text
/api/                 protocol owners
/internal/network/    security/network owners
/internal/storage/    security/storage owners
/internal/qemu/       virtualization owners
/internal/scan/       scanner owners
/nix/                 Nix/image owners
/.github/workflows/   release owners
/docs/adrs/           architecture owners
```

## Contribution policy

Contributors must:

- add tests
- update docs/schema
- avoid new host/guest sharing
- avoid shell product logic
- avoid unbounded parsers
- declare new dependencies
- add ADR for boundary changes

## Security reports

Use private GitHub security advisories. `SECURITY.md` defines supported versions
and expected acknowledgement.

## Releases

Semantic versioning:

- protocol/image compatibility follows explicit major/minor fields
- pre-1.0 may change CLI with changelog
- release artifacts immutable
- compromised digest added to revocation list

## Licensing

Apache-2.0 is recommended for original code. Before first public image:

- generate full license inventory
- verify qBittorrent, Firefox, LibreOffice, ClamAV, VSCodium, codecs, fonts, and
  reconstruction tools may be redistributed in the chosen form
- do not include unfree packages in official image without explicit decision
- publish notices/SBOM

## Security claims review

README and release notes must be reviewed for accurate claims before publishing.
