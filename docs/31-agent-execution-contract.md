# Coding-agent execution contract

## Objective

Implement the public `private-vm` repository from this specification without
silently changing its security model. The coding agent owns research needed to
validate exact library and Nix APIs, but it must preserve the decisions in
`DESIGN_FREEZE.md`.

## Required behavior before editing

1. Read `AGENTS.md`, `DESIGN_FREEZE.md` and the task's linked documents.
2. Locate the task in `project/backlog.yaml`.
3. Identify affected security invariants and acceptance tests.
4. Inspect current upstream APIs rather than copying stale examples.
5. State assumptions in the pull-request description.

## Work-unit rule

Implement one backlog task per branch unless two tasks are explicitly inseparable.
Do not generate a broad unreviewable implementation in one commit.

## Research rule

Current interfaces for NixOS, GitHub Actions, QEMU, Proton, ClamAV, USBGuard and
Sigstore can change. Use their primary documentation and pin exact versions.
Record material findings in `docs/30-sources.md` and an ADR when they alter a
decision.

## Safety rule

Prototype code must default to refusal. A placeholder that has not implemented a
security check returns a blocking `NOT_IMPLEMENTED` diagnostic. It must never
return success or quietly skip the check.

## Generated-code rule

Protobuf output may be generated and committed. It must be reproducible from the
checked-in schema and Buf configuration. Generated code is not edited manually.

## Completion report

For each task, report:

- files changed;
- commands run;
- tests added;
- acceptance criteria demonstrated;
- security invariants touched;
- known limitations;
- next unblocked task.

## Prohibited shortcuts

- mounting a guest image on the host;
- using a shared host directory;
- disabling provenance verification for convenience;
- using NAT without the endpoint allowlist;
- scanning while the quarantine guest has a NIC;
- attaching USB to the scanner;
- accepting ClamAV's clean count without checking errors and skipped files;
- logging sensitive input to make debugging easier;
- implementing lifecycle actions as shell scripts.
