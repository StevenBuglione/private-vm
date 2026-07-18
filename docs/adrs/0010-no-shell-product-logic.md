# ADR 0010: No shell-based security or lifecycle logic

- Status: Accepted
- Date: 2026-07-18

## Decision

Security decisions, process orchestration, cleanup, network rules, storage
management, installation and scanning policy are implemented in typed Go or
declarative Nix. CI may run simple compiler or test commands but no product
workflow may depend on shell scripts.

## Consequences

External programs are invoked by absolute path with argument slices. Command
construction, error handling and cleanup are testable. Packaging templates may
contain data files but not imperative installer scripts.
