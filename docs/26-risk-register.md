# Risk register

| ID | Risk | Likelihood | Impact | Mitigation |
|---|---|---:|---:|---|
| R-001 | QEMU escape | low | critical | rapid patching, minimal devices, role isolation |
| R-002 | Free runner disk insufficient | medium | medium | one image/job, size budgets, split OCI stages |
| R-003 | Nix image API changes | medium | medium | pin 26.05, wrapper module, CI evaluation |
| R-004 | ClamAV miss/false positive | high | high | reconstruction, policy, clear wording |
| R-005 | Parser exploit in scanner | medium | high | offline disposable role, read-only input |
| R-006 | Proton profile stale | medium | medium | bounded trusted-host resolution, redacted `rotation_required` status, atomic import of a newly generated profile |
| R-007 | VPN leak due routing | medium | high | independent host+guest enforcement, active tests |
| R-008 | Host disk swap leaks memory | medium | high | strict preflight, zram only |
| R-009 | Secret copies or unlocked pages outside the owned mapping | medium | medium | short lifetime; sealed/dump-excluded memfd; best-effort mlock; read-only inherited FDs; no mutable backing view; constant-time comparison; explicit overwrite; document unavoidable Go/gRPC/kernel/hardware copies and make no perfect-erasure claim |
| R-010 | USB composite attack | low/medium | high | USBGuard exact interface set and identity |
| R-011 | USB filesystem exploit | medium | high | exporter guest only; host never mounts |
| R-012 | Cleanup leaves recoverable ciphertext | low | high | volatile random key, startup deletion |
| R-013 | Dirty work destroyed | medium | high | workspace state and stop block |
| R-014 | Supply-chain substitution | medium | critical | digest, provenance, repo/workflow identity |
| R-015 | Malicious PR exfiltrates CI token | medium | high | no secrets/write perms on PR, pinned actions |
| R-016 | Public users misunderstand anonymity | high | medium | explicit UI/docs wording |
| R-017 | qBittorrent API/version drift | medium | medium | pin package, contract tests |
| R-018 | Scanner large-file denial of service | high | medium | planning, limits, timeouts, resource scopes |
| R-019 | Encrypted archive uninspectable | high | medium | reject until decrypted/rescanned |
| R-020 | Nix image contains mutable identifiers | medium | medium | sealing checks and image tests |
| R-021 | Multiple sessions increase attack surface | medium | medium | default one active session; explicit concurrency |
| R-022 | Host cannot verify root encryption | medium | medium | warning/strict manual attestation |
| R-023 | GHCR custom artifact incompatibility | low/medium | medium | ORAS integration test and release fallback |
| R-024 | Attestation library/API drift | medium | high | pin dependency, golden bundles, fallback verifier |
| R-025 | Legal redistribution issue | low/medium | high | license inventory before release |
| R-026 | A malicious kernel-backed userspace filesystem blocks while resolving a selected config/policy path | low | medium | accept only trusted local paths in operations; use nonblocking `openat2`; accept only explicitly allowlisted local filesystem descriptors; packaging installs system files locally; move arbitrary external file acquisition behind an owned killable worker before v1 release |
