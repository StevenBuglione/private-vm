# ADR 0004: XFCE over SPICE Unix sockets

- Status: Accepted
- Date: 2026-07-18

## Decision

Official graphical images use XFCE and LightDM. QEMU exposes SPICE only through a
session-owned Unix socket. `remote-viewer` is the initial host client.

Clipboard and agent file transfer remain disabled. `spice-vdagent` is retained
only for pointer integration and dynamic display resize.

## Consequences

- No graphical listener binds TCP.
- Plasma may be an unsupported local flavor later.
- Audio is opt-in and no webcam or microphone passthrough exists in v1.
