# ADR 0009: Publish images as attested OCI artifacts in GHCR

- Status: Accepted
- Date: 2026-07-18

## Decision

QCOW2 images, manifests and SPDX SBOMs are published to public GHCR repositories
using OCI media types. Releases produce GitHub artifact attestations. The Go CLI
uses ORAS libraries to pull by digest and Sigstore/GitHub provenance verification
to enforce repository, workflow, tag, role and architecture identity.

## Consequences

Tags are discovery aliases; digests are execution identities. Missing or invalid
provenance is never overridable for official images.
