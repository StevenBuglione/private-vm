# ADR 0023: Sixteen GiB role defaults

## Status

Accepted for frozen v1.

## Context

The supported maintainer and public-runner baseline has 16 GiB of physical RAM
and no disk-backed swap. The strict capacity planner must preserve the larger
of 4 GiB or 20 percent of physical RAM for the host. Earlier runtime prose
listed 6 GiB for the downloader and 12 GiB for the scanner, while production
composition selected 6 GiB and 8 GiB respectively. On the supported host those
implicit choices cannot pass a truthful capacity check once the desktop and
daemon are running. Trying to bypass that check would expose the host to an
out-of-memory failure.

The roles run serially. Scanner reconstruction and transfer code is bounded and
streaming; quarantine, reconstruction and root-overlay capacity is planned
separately from guest RAM. No requirement depends on an implicit RAM allocation
larger than 4 GiB.

## Decision

Packaged workstation, downloader and scanner launches default to 4 GiB. The
exporter defaults to 1 GiB. Workstation remains explicitly configurable within
the documented bounds; the downloader and scanner defaults remain closed,
daemon-owned plans. Every launch still passes the immutable host-capacity
snapshot through the no-overcommit planner and retains the 4 GiB/20 percent
host reserve. The implementation does not use swap, ballooning, memory hotplug
or a direct launch fallback when capacity is insufficient.

Development and acceptance commands run one memory-heavy lane at a time under
an outer cgroup memory limit. This operational limit does not weaken the
per-session production capacity check.

## Consequences

- All four packaged role defaults are runnable in principle on the supported
  16 GiB baseline without promising unavailable memory.
- A user can explicitly raise workstation memory, but the planner may reject it
  before QEMU starts.
- Large scan inputs remain governed by file, expansion, disk-capacity and
  timeout bounds; the scanner may fail closed if its bounded tools cannot
  process an input within the selected resources.
- Future default increases require capacity evidence on the minimum supported
  host and an ADR update.
