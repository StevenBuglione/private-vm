# Configuration and policy

## Configuration precedence

Lowest to highest:

1. built-in safe defaults
2. `/etc/private-vm/config.toml`
3. `$XDG_CONFIG_HOME/private-vm/config.toml`
4. command-line non-secret flags

Secrets are never allowed in TOML.

## Example

See `examples/config.example.toml`.

## Policy separation

Configuration answers how the system runs. Policy answers what content can move
between trust boundaries.

Built-in policies:

- `safe`: reconstructed documents/media only
- `quarantine`: original content only to dedicated encrypted quarantine output
- no `raw` policy in v1

## Safe policy rules

- malware detection rejects
- scan error rejects
- scan skip rejects
- uninspectable encryption rejects
- executable formats reject
- scripts reject
- packages reject
- disk/VM images reject
- PDF/Office must be reconstructed
- images must be metadata-stripped and re-encoded
- media must be decoded/re-encoded
- archives must be bounded, extracted, rescanned, and exported as approved members
- scanner report and output hashes must be complete

## Configuration validation

The CLI loads TOML into immutable typed structs and then validates against both
the JSON schema and semantic rules.

Semantic examples:

- `runtime.session_mode=tmpfs` cannot request more than configured RAM budget.
- `desktop.audio=true` is invalid under a policy that forbids audio devices.
- `network.ipv6=allow` requires `::/0` in Proton AllowedIPs and successful leak test.
- `usb.required=true` requires an enrolled device.
- `privacy.persistent_reports=false` forbids a persistent report path.

## Changes requiring restart

Daemon-level:

- image registry trust roots
- runtime binary paths
- private-vm group/socket
- host networking ranges
- USBGuard integration

Per-session:

- bundle
- resource sizes
- audio
- policy
- destination
- VPN profile

## Schema versioning

Every config, policy, manifest, and report includes `schema_version`. Major schema
changes require migration tooling or a clear refusal with remediation.
