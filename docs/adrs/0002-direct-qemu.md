# ADR 0002: Run sessions with direct QEMU/KVM

- Status: Accepted
- Date: 2026-07-18

## Context

Persistent libvirt domains, storage pools and logs complicate guarantees about
session teardown. The product needs a one-process-per-VM lifecycle, session-owned
sockets and generated arguments that can be validated before execution.

## Decision

`private-vmd` launches QEMU directly with KVM acceleration, controls it through a
private QMP Unix socket, and never registers a persistent libvirt domain.

## Consequences

- The daemon owns process supervision and cleanup.
- QEMU arguments are modeled as typed Go structures and executed without a shell.
- virt-manager is not part of the product runtime.
- We must implement display client launching, QMP handling and USB hotplug.
