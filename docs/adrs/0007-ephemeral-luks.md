# ADR 0007: Use volatile roots and ephemeral-key LUKS scratch

- Status: Accepted
- Date: 2026-07-18

## Decision

Root overlays and small scratch volumes live under tmpfs. Large scratch uses a
per-session LUKS2 container whose random key exists only in protected volatile
runtime state. On teardown the mapping closes, the key is destroyed and the
ciphertext container is removed.

## Non-claim

The project promises no intentional persistent plaintext session state. It does
not claim physical flash cells were overwritten or that a compromised host,
firmware or hypervisor leaves no evidence.
