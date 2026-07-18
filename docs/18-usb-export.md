# USB enrollment and export

## Enrollment

`private-vm usb enroll` shows:

- kernel device path
- vendor/product ID
- serial
- USBGuard hash
- physical port
- interface classes
- capacity
- current mount state
- model string

It refuses:

- system/root/boot device
- mounted device
- multiple matching devices
- no stable identity unless port binding is accepted
- composite interfaces other than exactly mass storage
- read-only device
- insufficient capacity

Enrollment stores identity only, never filesystem content.

## USBGuard

NixOS integration enables USBGuard with implicit block. The enrolled transfer
device rule should require its exact identity and:

```text
with-interface equals { 08:*:* }
```

Existing keyboard/mouse policies must be preserved. Installation must not
blindly replace USBGuard rules.

## Host automount

The module/package disables or documents disabling desktop automount for the
transfer device. `doctor` fails if the enrolled device is mounted.

## Passthrough

The daemon claims the physical device and passes exact bus/address or
vendor/product/serial association to QEMU exporter. It re-verifies identity
immediately before launch.

No generic `--usb` raw argument exists.

## Export formats

### Default: `luks2-ext4`

- entire device or one GPT data partition
- LUKS2
- ext4
- user enters passphrase directly through secure CLI/guest path
- no passphrase in daemon persistent config
- exporter mounts, writes, syncs, rereads, hashes, unmounts, closes

### Future compatibility format

exFAT may be added only under a separate weaker policy with a warning that it
provides no block encryption and expands host/destination parser exposure.

## Write procedure

1. verify enrolled identity
2. verify destination capacity
3. start exporter with no NIC
4. authenticate guest
5. attach USB
6. guest verifies identity/capacity
7. explicit destructive format confirmation if needed
8. mount destination
9. receive one approved stream
10. write temporary name
11. fsync file and filesystem
12. atomic rename
13. reread and hash
14. compare sender, relay, and USB hash
15. write manifest
16. unmount
17. close LUKS
18. detach USB
19. stop exporter
20. release host claim

## Interrupted export

The report is `INCOMPLETE`. The USB must be reverified in exporter before use.
The host must not mount it to inspect partial output.
