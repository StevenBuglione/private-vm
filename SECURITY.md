# Security policy

## Status

This repository is initially a security-sensitive prototype. Until a tagged
release explicitly states otherwise, do not use it to protect data against a
targeted adversary.

## Reporting

Do not open public issues for suspected vulnerabilities. Use GitHub private
vulnerability reporting for the repository. Include:

- affected commit or release;
- complete reproduction;
- expected and observed trust boundary;
- whether secrets, host access or arbitrary code execution are involved;
- logs with all private data removed.

## Supported releases

Only the latest stable minor release receives security fixes before v1.0. After
v1.0, the latest two minor releases are supported for 90 days.

## Security invariants

Changes that affect any item below require security-owner review:

- QEMU arguments;
- network namespace or nftables rules;
- VPN configuration handling;
- image provenance;
- guest capability authorization;
- LUKS key lifecycle;
- quarantine attachment modes;
- file relay framing;
- USB identity or passthrough;
- scanner approval policy;
- cleanup and crash recovery.

## Disclosure targets

- acknowledgement within 3 business days;
- initial assessment within 7 business days;
- coordinated disclosure after a fix is available;
- no guarantee of a bounty.
