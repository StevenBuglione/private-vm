# ADR 0003: Separate workstation, downloader, scanner and exporter roles

- Status: Accepted
- Date: 2026-07-18

## Decision

Use four immutable image roles:

1. graphical workstation for trusted work;
2. graphical downloader for torrent acquisition;
3. graphical scanner for inspection and reconstruction;
4. headless exporter for USB writes.

A role manifest and guest capability token prevent a guest from invoking another
role's operations.

## Rationale

Combining these functions would let hostile torrent content share credentials,
browser sessions or USB access. The extra VMs are operationally more complex but
materially reduce blast radius.
