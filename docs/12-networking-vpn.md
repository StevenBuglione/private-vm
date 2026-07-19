# Networking and Proton VPN

## VPN input

The user supplies a Proton WireGuard configuration generated through Proton's
account interface. `private-vm` does not authenticate to Proton's account API and
does not store the user's Proton account password.

The parser accepts only the required WireGuard fields and rejects:

- hooks such as `PreUp`, `PostUp`, `PreDown`, `PostDown`
- multiple peers
- non-default routes that weaken policy
- missing IPv4 default route
- IPv6 enabled without `::/0`
- endpoint without a concrete port
- invalid keys or addresses
- unsafe DNS values
- duplicate fields

The endpoint hostname is resolved on the trusted host before creating the guest.
The ephemeral guest copy uses an IP address to avoid pre-tunnel DNS.

## Host namespace topology

```mermaid
flowchart LR
    Q[QEMU virtio-net] --> TAP[tap-pvm]
    TAP --> NS[session netns]
    NS --> VETH[veth pair]
    VETH --> HOST[host]
    HOST --> WAN[physical uplink]
    NS -. nft allow only Proton endpoint .-> WAN
```

Use static guest addressing. Do not run a broad DNS/DHCP service.

The namespace owns an nftables table whose policy:

- default drop
- permit established/related
- permit required link-local/ARP
- permit guest UDP only to resolved Proton endpoint and port
- deny host LAN/private ranges
- deny all other IPv4/IPv6
- no inbound forwarding

## Guest policy

The guest has two zones:

### Underlay `eth0`

Allowed:

- ARP/neighbor discovery for gateway
- UDP to exact Proton endpoint

Denied:

- DNS
- HTTP/HTTPS
- LAN
- all other addresses and ports

### Tunnel `proton0`

Allowed according to role:

- workstation: normal outbound traffic
- downloader: normal outbound traffic, with qBittorrent bound to `proton0`
- scanner update: ClamAV update endpoints only if endpoint allowlisting is
  practical; otherwise general tunnel egress during update boot
- scan/exporter: interface absent

## qBittorrent

Use qBittorrent Web API controlled locally by guestd. The graphical client may
be present, but guestd is authoritative for:

- add paused
- metadata status
- file selection
- save path
- start/pause
- progress
- completion
- interface binding verification

Required settings:

- network interface `proton0`
- anonymous mode where supported
- DHT/PEX/LSD policy configurable
- UPnP disabled
- NAT-PMP disabled by default
- no automatic execution
- no watched folders
- no external program hooks
- no alternate upload directory outside quarantine
- no web API listener beyond localhost

Port forwarding is not part of v1. Download functionality does not require it,
and it adds state and inbound exposure.

The downloader image boots with a default-drop `inet` table. It contains
separate IPv4 and IPv6 runtime templates whose only underlay egress is UDP to a
typed, validated Proton endpoint; NET-003 renders and applies one complete
transaction after profile validation. qBittorrent runs as a hardened user
service only when both the root-owned `/run/private-vm-vpn/ready` marker and the
quarantine mount exist. Its profile and logs are volatile, its Web API binds to
`127.0.0.1`, and the immutable image contains no reusable API credential.
TOR-002 must provision and verify local authentication with a per-boot
credential before guestd uses the API.

NIX-004 establishes only the fail-closed image defaults and service sandbox. It
does not claim that the current immutable `ExecStartPre` profile copy provisions
an authenticated Web API session. TOR-002 must replace that bootstrap path with
a bounded per-boot credential flow, keep the credential in volatile memory,
prove an authenticated API request succeeds, and prove the credential is absent
from argv, the environment, the immutable profile and the journal.

## Leak tests

Before role readiness:

1. WireGuard handshake timestamp is recent.
2. `proton0` exists and has expected routes.
3. tunnel DNS resolves.
4. public IPv4 through tunnel is reachable.
5. public IPv6 through tunnel is reachable when enabled.
6. a direct socket bound to `eth0` cannot reach a public test endpoint.
7. DNS bound to `eth0` fails.
8. qBittorrent reports `proton0` as bound interface.
9. host namespace counters show no forbidden egress.

Tests must avoid sending secrets or torrent metadata to third-party leak-test
sites. Use minimal controlled endpoints or Proton-provided IP checks.

## VPN loss

guestd continuously monitors:

- interface existence
- latest handshake
- default route
- DNS route

On failure:

- guest nftables already blocks fallback
- qBittorrent is paused
- workstation shows a blocking warning
- daemon emits `VPN_DEGRADED`
- session remains available for local save/export
- user may retry or stop
