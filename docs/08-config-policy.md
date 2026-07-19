# Configuration and policy

## Effective configuration

The CLI resolves one immutable, typed snapshot before dispatching an operational
command. Precedence from lowest to highest is:

1. built-in fail-closed defaults;
2. optional root-owned `/etc/private-vm/config.toml`;
3. optional user-owned `$XDG_CONFIG_HOME/private-vm/config.toml`;
4. explicitly supplied non-secret command flags.

`--config PATH` selects one required user layer in place of the default user
path; it does not add a fifth layer. `version`, root help and shell completion do
not load configuration. An absent boolean command flag is distinct from an
explicit `--flag=false`, so an absent flag cannot accidentally replace a file
setting. Configuration failures use exit 11 and a stable redacted `CONFIG_*`
code before any semantic operation is dispatched.

The root daemon has a separate trust scope. It loads exactly one required,
root-owned system file and never loads a root user's XDG file or CLI preference
overrides. A CLI snapshot describes a requested operation; it is not authority
for the daemon. Each privileged API implementation must validate the request
again against the daemon snapshot. This preserves user preference precedence
without permitting a user file to weaken host enforcement.

## File and data contract

Every TOML layer must contain integer `schema_version = 1`. Partial layers are
allowed and inherit omitted values. Unknown fields, invalid types, future
versions and all keys suggestive of credentials, passwords, passphrases,
secrets, tokens, private keys or magnets are rejected. Values from a rejected
document, its path and raw parser/read errors never enter the returned error.

On Linux, configuration and policy inputs are opened nonblocking with
`openat2`, magic links are rejected, and the resulting descriptor must identify
a bounded regular file on an explicit local-filesystem allowlist (ext-family,
XFS, Btrfs, F2FS, ZFS, tmpfs/ramfs, eCryptfs, OverlayFS, SquashFS and EROFS).
Every unrecognized filesystem, including FUSE, NFS, SMB, 9P, AFS and Ceph,
fails closed, as do group/world-writable and executable files. System
configuration is root-owned; user configuration is owned by the effective user.
Ordinary symlinks remain supported for NixOS `/etc` links and user dotfile
managers. CLI-selected configuration and policy links are unprivileged input,
not daemon-created paths; their opened targets must still be owned by root or
the effective user as appropriate. All ownership, mode, type and filesystem
checks are performed on the opened target descriptor, so a link cannot bypass
the trust policy. Magic links are never accepted.

The implemented configuration surface is exactly the one in
`examples/config.example.toml` and `schemas/config.schema.json`:

| Section | Fields | Enforced semantics |
|---|---|---|
| root | `schema_version`, `strict` | schema is 1; strict is a preference consumed by preflight |
| `image_source` | `registry`, `repository`, `channel`, `require_attestation` | bounded registry and source identity; `stable` or `edge`; attestations mandatory for every source |
| `runtime` | `directory`, `image_cache`, `scratch_directory`, `small_scratch_max_bytes`, `cleanup_timeout_seconds` | runtime, image cache and encrypted scratch roots are fixed v1 paths; scratch at most 1 TiB; cleanup 5–300 seconds |
| `desktop` | `bundle`, `viewer`, `audio`, `memory_bytes`, `vcpus` | fixed bundles; `remote-viewer`; 2–256 GiB and 1–64 vCPUs |
| `vpn` | `profile_name`, `disable_ipv6_if_not_tunneled` | bounded non-secret label; IPv6 fail-closed is mandatory |
| `usb` | `require_usbguard`, `default_filesystem` | USBGuard mandatory; `luks2-ext4` only |
| `logging` | `persistent_lifecycle_metadata`, `telemetry` | lifecycle metadata contains no session data; telemetry is always disabled |

The Go loader performs strict TOML type/unknown-field checks and semantic
validation. Repository tooling validates complete effective examples against
the JSON Schema. Go boundary tests mirror every numeric, enum, conditional and
fail-closed rule. The schema describes effective snapshots; partial TOML layers
are intentionally not schema documents until they have been merged.

Migration registries are copied at loader construction. Each registered hook
must advance exactly one version, cannot introduce a secret or unknown field,
and cannot produce a document larger than 1 MiB. No v0 migration ships in v1;
the hook contract exists so a future release can add an explicit reviewed
migration without silently accepting old data.

## Policy separation

Configuration answers how the system runs. Policy answers what content may move
between trust boundaries. The only v1 policy identities and modes are:

- `safe`: reconstructed documents/media and approved archive members only;
- `quarantine`: original content only to dedicated encrypted quarantine output.

There is no `raw` policy. Both policies always reject malware, scan errors,
skipped files and uninspectable encrypted content. `safe` must enable executable,
script and disk-image blocking plus document sanitization, media re-encoding and
metadata stripping. `quarantine` must disable those reconstruction switches so
it cannot be confused with a sanitized result; the isolation and destination
rules enforce its safety boundary.

Policy files are immutable typed snapshots described by
`schemas/policy.schema.json`. They use the same 1 MiB, schema-version, strict
unknown-field, secret-field, migration-output, local-file and redacted-error
rules as configuration. Limits are finite: input at most 1 TiB, at most one
million files, archive depth at most 10, expansion ratio at most 1000, expanded
content at most 4 TiB and scan timeout from 30 seconds through 24 hours. A
zero-value or unvalidated Go `Rules` value always denies approval.

## Applying changes

The daemon system file is read once at daemon startup. Changing its runtime,
image, cleanup, VPN or USB enforcement values therefore requires a daemon
restart. CLI user/session preferences are resolved for each invocation. A
running session remains bound to the validated snapshot recorded at creation;
editing a file never mutates that session.

See `examples/config.example.toml`, `examples/policy.safe.toml` and
`examples/policy.quarantine.toml` for the canonical v1 documents.
