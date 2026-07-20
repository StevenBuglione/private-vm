# ADR 0025: Production exporter runtime and semantic source registry

## Status

Accepted

## Context

USB preparation and export require a physical device in one networkless,
headless exporter guest. The host must not mount the device or an approved
source filesystem, and an ambiguous QMP response must not lose ownership of a
possibly attached USB device. Approved content can originate from scanner
reconstruction or workstation Export, but a common abstraction must not become
a generic path or command API.

## Decision

The daemon composes a dedicated exporter runtime coordinator from the verified
role image/storage selector, CID allocator, private QMP directory owner, direct
QEMU launcher and authenticated AF_VSOCK guest client. The QEMU specification
has `-nic none`, no SPICE and one fixed xHCI controller. The only USB QMP
operations use fixed command, driver, object and controller identifiers; their
typed input is the bus/address from a freshly revalidated daemon claim.

The runtime marks USB ownership before `device_add`. It retains ownership and
the concrete cleanup handle after every failed detach, VSOCK close, process
stop, image destroy, CID release or directory cleanup. A retry clears only the
step it proves complete. QEMU process absence proves its device attachment is
absent. No-network verification requires both the typed QEMU shape and the
authenticated guest `InspectUSB` response.

Approved input is opened once from a volatile registry keyed by source role,
session ID and opaque output ID. Scanner entries require authenticated complete
policy-approved reconstruction. Workstation entries require authenticated
ready Export state. The interface cannot represent a path, mount, device,
command or QEMU argument.

The semantic workstation-to-USB command is a distinct one-shot authorization:
it is accepted only by the prepared exporter selected by ADR 0022 and is bridged
directly into the same `ExportOperation`. That operation exposes its actual
post-write guest re-read digest only as a non-serializable in-process value and
only after fsync, unmount, detach, exporter stop, claim release, and absence
audit all succeed. Any later mismatch or failure destroys the exporter while
leaving the workstation output unverified and therefore dirty.

The scanner adapter is registered only from the MAC-verified report promotion
path and permits exactly one report-listed reconstructed output. Its offline VM
remains actor-owned until the factory is consumed or cleanup invalidates every
entry for that scanner. The workstation adapter is registered only after the
guest rehashes and marks one export current; it rechecks exported/unchanged
inventory and pins the new stream descriptor to that verified digest. A common
bounded frame validator requires begin, monotonic chunks, exact end and clean
EOF before either adapter can close successfully.

## Consequences

Preparation/export and their cleanup remain owned by the serialized exporter
session actor. Caller cancellation cannot discard resource ownership. Adding a
new source role requires a typed policy and authenticated adapter rather than a
path-based escape hatch. Live physical-device, KVM and reboot evidence remains
a separate destructive acceptance gate.
