# Security review checklists

## QEMU launch review

- [ ] executable path is absolute and package-controlled;
- [ ] `-nodefaults` and `-no-user-config` are present;
- [ ] image formats are explicit;
- [ ] base image is never attached writable;
- [ ] no 9p, virtiofs or host directory device exists;
- [ ] SPICE uses only a mode-0600 Unix socket;
- [ ] clipboard and agent file transfer are disabled;
- [ ] offline roles have `-nic none`;
- [ ] role-appropriate disks have correct read-only modes;
- [ ] unique VSOCK CID and capability are present;
- [ ] QMP is private and supervised;
- [ ] core dumps and snapshots are disabled.

## Network review

- [ ] profile grammar admits exactly one peer, fixed fields and complete default routes;
- [ ] private key remains byte-backed and profile/endpoint serialization is rejected;
- [ ] profile names, bytes, lines, addresses, DNS entries and resolution results are bounded;
- [ ] endpoint resolution is host-side, context-bounded and rejects any unsafe answer;
- [ ] profile replacement/remove/shutdown destroys every daemon-owned key;
- [ ] inspection and errors exclude keys, endpoints, addresses, DNS answers and source paths;
- [ ] namespace and interface names derive from internal session IDs;
- [ ] nftables rules are installed atomically before VM start;
- [ ] default forward/output policy is drop;
- [ ] clear-interface destination is limited to Proton endpoint;
- [ ] host/LAN/link-local/metadata ranges are blocked;
- [ ] guest kill switch is active before applications;
- [ ] DNS and IPv6 behavior is tested;
- [ ] teardown removes rules and interfaces by stored handles;
- [ ] endpoint changes force re-plan.

## Storage review

- [ ] runtime directory is verified tmpfs;
- [ ] scratch mode selected before creating resources;
- [ ] key is not in argv, environment, journal or normal file;
- [ ] outer persistent volume contains only opaque guest files;
- [ ] host never mounts inner filesystem;
- [ ] cleanup ordering closes QEMU, mapper, key and ciphertext;
- [ ] crash-recovery path is tested;
- [ ] backup and snapshot exclusion is documented.

## Volatile secret review

- [ ] nil, zero and copied handles cannot close or duplicate unrelated FDs;
- [ ] supported Linux uses a mode-0600 memfd with dump and size protections;
- [ ] exported descriptors are read-only, CLOEXEC, offset-zero and independent;
- [ ] raw secret backing is not exposed as a mutable slice;
- [ ] serialization and formatting cannot disclose the value;
- [ ] argv and environment absence is inspected on a live helper process;
- [ ] destroy zeroes the live mapping before unmap and close;
- [ ] `mlock`, Go-copy and transient metadata limitations are documented.

## Scan review

- [ ] scanner definitions updated before quarantine attachment;
- [ ] offline boot has no NIC device;
- [ ] quarantine is block- and filesystem-read-only;
- [ ] true MIME/type inspected;
- [ ] scanner limits cover maximum supported input;
- [ ] stderr, exit status, skipped and timeout states are parsed;
- [ ] archives are bounded and path-safe;
- [ ] sanitizer output is rescanned;
- [ ] approval requires complete signed report.

## USB review

- [ ] VID, PID, serial, port, interfaces and capacity match;
- [ ] only exact mass-storage interfaces exist;
- [ ] device is not mounted or host-critical;
- [ ] exporter has no NIC and no quarantine disk;
- [ ] host relay is bounded and non-persistent;
- [ ] hashes agree at all three stages;
- [ ] flush, unmount and QEMU detach complete before success.
