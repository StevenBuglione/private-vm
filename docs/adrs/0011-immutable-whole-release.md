# ADR 0011: Immutable whole-release transaction

## Status

Accepted for v1.

## Decision

REL-004 uses a separate bounded Go coordinator after REL-003 image publication.
It accepts exactly DEB, RPM and generic-archive package subjects, anonymously
verifies the six fixed OCI image identities, and writes one closed release
index. Package attestations reuse the embedded-root GitHub/Sigstore verifier;
no caller-selectable trust root, repository, workflow, upload URL or command is
exposed.

Publication creates a draft GitHub Release, uploads the exact indexed asset set
and makes it public only after every upload succeeds. Failure, cancellation or
timeout deletes the draft with an independent bounded cleanup owner. The Git
tag is never deleted or moved; a failed attempt is retried only after absence is
proved. Anonymous verification runs in a fresh read-only job and has no token or
authenticated fallback.

## Consequences

The `release` GitHub environment must be protected in repository settings;
workflow YAML cannot prove that server-side fact. DEB/RPM/generic installation
tests, public release publication and all anonymous downloads remain live gates.
Source tests deliberately do not claim them.
