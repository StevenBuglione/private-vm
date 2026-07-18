# Definition of done

A task is done only when:

- its code is merged behind no hidden manual step;
- all acceptance criteria in `backlog.yaml` pass;
- unit and relevant integration tests exist;
- failures are fail-closed at the documented boundary;
- cleanup is tested for success, cancellation, timeout and process death;
- human and JSON output are documented;
- secrets and private identifiers are absent from logs;
- configuration/schema/API changes are versioned;
- threat model, ADRs and runbook are updated where applicable;
- installation and upgrade implications are documented;
- CI uses exact dependency/action identities;
- no shell product logic was introduced.
