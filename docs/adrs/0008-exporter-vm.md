# ADR 0008: Only the exporter VM may access transfer USB devices

- Status: Accepted
- Date: 2026-07-18

## Decision

The scanner emits approved bytes through a bounded framed stream. The host relays
without interpreting or storing the content. A fresh, networkless exporter VM
receives the stream and writes an exactly enrolled USB device.

The host, workstation, downloader and scanner never mount or receive the USB.

## Consequences

USB identity, interface class, capacity and mount state are hard preflight gates.
A write is committed only after scanner, relay and exporter hashes agree.
