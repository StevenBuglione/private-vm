# System architecture

## Component diagram

```mermaid
flowchart TB
    User --> CLI[private-vm CLI]
    CLI -->|gRPC Unix socket| D[private-vmd]
    D --> IMG[Verified image cache]
    D --> SESS[Encrypted session store]
    D --> NET[Network namespace + nftables]
    D --> Q1[QEMU workstation/downloader/scanner]
    D --> Q2[QEMU exporter]
    D -->|QMP Unix socket| Q1
    D -->|QMP Unix socket| Q2
    Q1 -->|AF_VSOCK gRPC| GD1[private-vm-guestd]
    Q2 -->|AF_VSOCK gRPC| GD2[private-vm-guestd]
    Q1 -->|SPICE Unix socket| Viewer[remote-viewer]
    GD1 --> WG[Proton WireGuard]
    GD1 --> QB[qBittorrent]
    GD1 --> AV[ClamAV + reconstruction]
    GD2 --> USB[Enrolled USB]
    CLI --> Viewer
```

## Trust boundaries

```mermaid
flowchart LR
    subgraph HostTrusted[Trusted host boundary]
      CLI
      D[private-vmd]
      QEMU
      Kernel
    end
    subgraph Work[Disposable workstation]
      W[XFCE + applications]
      WG1[guestd]
    end
    subgraph Download[Hostile downloader boundary]
      QB[qBittorrent]
      G1[guestd]
    end
    subgraph Scan[Hostile parser boundary]
      AV[ClamAV/parsers]
      G2[guestd]
    end
    subgraph Export[Minimal exporter boundary]
      E[guestd]
    end
    Internet((Internet))
    USB[(USB)]

    HostTrusted <-->|VSOCK| Work
    HostTrusted <-->|VSOCK| Download
    HostTrusted <-->|VSOCK| Scan
    HostTrusted <-->|VSOCK| Export
    Download -->|Proton tunnel| Internet
    Work -->|Proton tunnel| Internet
    Export --> USB
```

## Runtime resource ownership

One `Session` object owns:

- session ID and invoking UID
- role workflow and state
- session token
- VSOCK CIDs
- QEMU PIDs and pidfds
- QMP sockets
- SPICE sockets
- network namespaces
- TAP/veth names
- nftables table/chain handles
- outer LUKS container and device mapping
- root overlays
- quarantine image
- USB claim
- cancellation context
- ephemeral event/report store

No resource may exist without a parent session record. Cleanup is idempotent and
walks this ownership graph in reverse creation order.

## Daemon boundary

The daemon is not a generic root command runner. Its APIs are semantic:

- create a planned session
- allocate a bounded encrypted store
- launch a verified role image
- attach an allowed block image read-only/writable according to state
- create a Proton endpoint-restricted network
- claim an enrolled USB for exporter
- relay a bounded verified stream
- destroy session

There is no API such as `RunCommand`, `MountPath`, `AttachArbitraryDevice`, or
`LaunchCustomQEMUArgs`.

## Guest capability negotiation

At boot, guestd returns:

```text
role
image digest
build source commit
guest protocol major/minor
capability list
boot nonce
OS release
guestd version
```

The daemon checks these values against the verified manifest and requested role.
A mismatch destroys the guest.

## Process supervision

Use Linux pidfds where available. QEMU processes run in systemd transient scopes
with:

- no core dumps
- bounded memory/CPU
- explicit device access
- stdout/stderr directed to volatile files or `/dev/null`
- kill mode control-group
- no restart
- session-specific slice name

The daemon subscribes to QMP events and process exit. Either signal triggers the
same idempotent state transition.

## Why direct QEMU instead of libvirt

Direct QEMU is selected for the privacy workflow because:

- the daemon controls exact sockets and paths
- no persistent libvirt domain definition
- no default libvirt log location
- no storage pool metadata
- no broad libvirt API exposure
- deterministic argument allowlist
- simpler one-session ownership

Libvirt remains compatible with the host for unrelated user VMs.

## Why VSOCK

AF_VSOCK provides host/guest communication without:

- guest IP networking
- listening TCP ports
- shared filesystems
- serial framing implementation

The Go VSOCK listener and dialer satisfy `net.Listener` and `net.Conn`, allowing
the same gRPC stack to be used over Unix sockets and VSOCK.
