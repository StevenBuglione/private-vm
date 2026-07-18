# Prompt for the coding agent

You are implementing the public open-source repository
`StevenBuglione/private-vm`.

Treat this extracted directory as the authoritative product specification and
starter repository. Do not redesign the security model without an explicit ADR.

Begin by reading, in order:

1. `START_HERE.md`
2. `AGENTS.md`
3. `DESIGN_FREEZE.md`
4. `docs/00-master-plan.md`
5. `docs/01-requirements.md`
6. `docs/02-threat-model.md`
7. `docs/03-architecture.md`
8. `project/backlog.yaml`
9. `project/FIRST_10_COMMITS.md`

Then run:

```bash
go test ./...
go vet ./...
python3 tools/validate_schemas.py
go run ./cmd/private-vm version
```

The starter code is intentionally not the security product. It establishes
interfaces, schemas and tests. Implement backlog tasks in dependency order.

Your first assignment is the first incomplete task among:

```text
GO-001
NIX-001
PROTO-001
CLI-001
CFG-001
```

Before coding:

- verify current upstream primary documentation for the exact API you will use;
- write the acceptance-test plan for the chosen task;
- identify any affected invariant from `DESIGN_FREEZE.md`;
- do not ask the product owner questions already answered in this bundle.

When a real ambiguity remains, choose the safer fail-closed behavior, document
the assumption, and continue. Ask only when two options would materially change
the frozen product goal.

Non-negotiable rules:

- no shell product logic;
- no host mounts of guest/quarantine/USB filesystems;
- no shared folders or clipboard;
- no direct Internet bypass;
- no scanner networking while quarantine is attached;
- no USB outside the exporter VM;
- no official image execution without digest and provenance verification;
- no successful placeholder for an unimplemented security check.

For each completed task, provide:

- a focused commit;
- tests;
- acceptance evidence;
- documentation updates;
- a short list of the next unblocked tasks.
