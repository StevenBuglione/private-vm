# Refined product plan: `private-vm`

The previous plan needs one major architectural correction:

> **Packer should not be the canonical image builder. Nix should be.**

The guest images should be minimal, declaratively built **NixOS QCOW2 images**, even when `private-vm` runs on Fedora, Ubuntu, Debian, or another supported Linux host.

That gives us:

* Pinned guest packages through `flake.lock`
* Declarative image configuration
* Smaller images without a desktop environment
* No image-provisioning shell scripts
* Better public CI compatibility
* The same guest images on every supported host
* Rebuildable and auditable public artifacts

Proton supports standard WireGuard configurations on any conforming WireGuard client, so the guest does not need Fedora or Proton’s native application. A minimal NixOS guest can use `wg-quick` directly. ([Proton VPN][1])

NixOS image generation was upstreamed into Nixpkgs beginning with NixOS 25.05. The old `nixos-generators` repository was archived in January 2026, and QCOW2 images are now available through `nixos-rebuild build-image` and `config.system.build.images.qcow`. ([GitHub][2])

## 1. Final system architecture

```text
┌──────────────────────────────────────────────────────────────┐
│                      Public GitHub Repo                      │
│                                                              │
│  Go sources      Nix guest definitions      GitHub Actions  │
│      │                    │                         │         │
│      ├─ private-vm       ├─ downloader image      │         │
│      ├─ private-vmd      ├─ scanner image         │         │
│      └─ guestd           └─ exporter image        │         │
│                                                    │         │
│                      Signed + attested release ─────┘         │
└──────────────────────────────┬───────────────────────────────┘
                               │
                   Public GHCR OCI artifacts
                               │
                               ▼
┌──────────────────────────────────────────────────────────────┐
│                         Linux Host                           │
│                                                              │
│  private-vm CLI ─────────────── private-vmd root service     │
│          │                              │                    │
│          │                       QEMU/KVM lifecycle           │
│          │                       encrypted scratch           │
│          │                       network namespaces          │
│          │                       USB passthrough              │
│          ▼                              ▼                    │
│                                                              │
│   ┌────────────┐   ┌────────────┐   ┌────────────┐           │
│   │ Downloader │   │  Scanner   │   │  Exporter  │           │
│   │    VM      │   │    VM      │   │    VM      │           │
│   │            │   │            │   │            │           │
│   │ Proton WG  │   │ ClamAV     │   │ USB only   │           │
│   │ qBittorrent│   │ sanitizers │   │ no network │           │
│   └─────┬──────┘   └─────┬──────┘   └─────┬──────┘           │
│         │                │                │                  │
│         └ encrypted ─────┘                ▼                  │
│             scratch                  Dedicated USB           │
└──────────────────────────────────────────────────────────────┘
```

There are **three disposable guest roles**:

| Guest      |                               Network | Input                        | Output                       | Purpose                                      |
| ---------- | ------------------------------------: | ---------------------------- | ---------------------------- | -------------------------------------------- |
| Downloader |                           Proton-only | Magnet or torrent metadata   | Encrypted quarantine storage | Download without opening files               |
| Scanner    | Update phase only; no NIC during scan | Quarantine read-only         | Approved stream              | Scan, inspect and sanitize                   |
| Exporter   |                                  None | Approved one-way byte stream | Dedicated USB                | Write output without exposing USB to scanner |

The USB is never connected to the downloader or scanner. That is important because both guests process hostile input.

## 2. Components written in Go

The project produces three Go binaries from one repository.

### `private-vm`

The user-facing CLI. It:

* Runs preflight checks
* Downloads and verifies guest images
* Accepts torrent input securely
* Displays the workflow state
* Requests privileged operations from `private-vmd`
* Shows scan reports
* Handles explicit approval and rejection
* Never directly opens or mounts downloaded content

### `private-vmd`

A narrowly privileged system service. It:

* Creates network namespaces
* Configures host-side egress restrictions
* Creates ephemeral encrypted scratch devices
* Launches QEMU
* Controls QEMU through QMP
* Passes USB devices to the exporter
* Cleans up sessions after success, failure or reboot
* Never parses torrent content or guest filesystems

Communication uses a Unix-domain socket under:

```text
/run/private-vm/control.sock
```

The daemon validates callers using Unix peer credentials and a Polkit policy. Do not use a setuid binary.

### `private-vm-guestd`

A small static binary included in each guest image. Its behavior depends on the guest role.

Downloader mode:

* Receives the WireGuard configuration through an ephemeral channel
* Configures `proton0`
* Applies the guest kill switch
* Controls `qbittorrent-nox`
* Fetches torrent metadata before downloading
* Reports file names and exact sizes
* Refuses downloads until host capacity approval

Scanner mode:

* Updates ClamAV before quarantine storage exists
* Verifies signature database age
* Scans read-only quarantine storage
* Detects file type independently of the extension
* Reports skipped files, encrypted archives and scan limits
* Performs supported sanitization
* Streams approved output

Exporter mode:

* Has no network interface
* Receives a bounded byte stream
* Verifies expected size and hash
* Writes to the enrolled USB
* Flushes and unmounts the USB
* Reports a final post-write checksum

## 3. Do not use shell scripts for product logic

The repository should establish this rule:

> Shell may invoke a compiler or test command in CI, but no security decision, orchestration logic or lifecycle management may exist in shell.

That means:

* No `launch-vm.sh`
* No `cleanup.sh`
* No `scan.sh`
* No `prepare-usb.sh`
* No `install-guest.sh`
* No provisioning scripts inside Packer

All decisions are implemented in typed Go or declarative Nix.

The GitHub workflow can contain simple commands such as:

```yaml
run: nix build .#checks.x86_64-linux.default
```

But multi-step behavior belongs in:

```text
private-vm image build
private-vm image test
private-vm release prepare
```

## 4. Why Packer becomes secondary

GitHub’s standard public Linux runners currently provide four CPUs, 16 GB RAM and 14 GB SSD, and their use is free and unlimited for public repositories. However, nested virtualization is explicitly experimental and unsupported. ([GitHub Docs][3])

A Packer QEMU build normally boots a VM, installs the operating system and provisions it. That makes it dependent on nested virtualization or slow QEMU software emulation. ([HashiCorp Developer][4])

Therefore:

### Canonical image build

```text
NixOS configuration
        ↓
nix build
        ↓
config.system.build.images.qcow
        ↓
QCOW2 image
```

### Secondary Packer use

Keep a small `packer/` directory only for optional compatibility and acceptance tests:

```text
private-vm image test --backend packer
```

It can:

* Boot the released QCOW2
* Wait for `guestd`
* Exercise a clean lifecycle
* Confirm shutdown and cleanup behavior

It should not independently install or configure the operating system.

This prevents Packer and Nix from becoming two competing sources of truth.

## 5. Public repository layout

```text
private-vm/
├── cmd/
│   ├── private-vm/
│   │   └── main.go
│   ├── private-vmd/
│   │   └── main.go
│   └── private-vm-guestd/
│       └── main.go
│
├── internal/
│   ├── attestation/
│   ├── config/
│   ├── daemon/
│   ├── guest/
│   ├── image/
│   ├── network/
│   ├── orchestrator/
│   ├── policy/
│   ├── preflight/
│   ├── qemu/
│   ├── qmp/
│   ├── scan/
│   ├── secret/
│   ├── session/
│   ├── storage/
│   ├── torrent/
│   ├── usb/
│   └── vpn/
│
├── api/
│   ├── daemon.proto
│   └── guest.proto
│
├── nix/
│   ├── host-module.nix
│   ├── packages.nix
│   └── guests/
│       ├── common.nix
│       ├── downloader.nix
│       ├── scanner.nix
│       └── exporter.nix
│
├── packer/
│   └── acceptance.pkr.hcl
│
├── packaging/
│   ├── deb/
│   ├── rpm/
│   ├── systemd/
│   ├── polkit/
│   ├── tmpfiles/
│   └── udev/
│
├── policies/
│   ├── safe.toml
│   ├── quarantine.toml
│   └── file-types.toml
│
├── .github/
│   ├── CODEOWNERS
│   ├── dependabot.yml
│   └── workflows/
│       ├── ci.yml
│       ├── image-build.yml
│       ├── nightly.yml
│       ├── release.yml
│       └── reproducibility.yml
│
├── docs/
│   ├── architecture.md
│   ├── threat-model.md
│   ├── security-boundaries.md
│   ├── image-builds.md
│   ├── installation.md
│   └── recovery.md
│
├── flake.nix
├── flake.lock
├── go.mod
├── go.sum
├── SECURITY.md
├── REPRODUCIBILITY.md
├── CONTRIBUTING.md
└── LICENSE
```

Use Apache-2.0 for original project code unless there is a specific reason to choose another license. Generate an SBOM and third-party license report for each distributed guest image.

## 6. Nix image outputs

The root flake should expose:

```text
packages.x86_64-linux.private-vm
packages.x86_64-linux.private-vmd
packages.x86_64-linux.private-vm-guestd

packages.x86_64-linux.downloader-image
packages.x86_64-linux.scanner-image
packages.x86_64-linux.exporter-image

apps.x86_64-linux.private-vm

nixosModules.default
checks.x86_64-linux.default
devShells.x86_64-linux.default
```

Conceptually:

```nix
packages.x86_64-linux.downloader-image =
  self.nixosConfigurations.downloader.config.system.build.images.qcow;
```

The images should use a pinned stable Nixpkgs revision in `flake.lock`, not a floating branch during releases.

### Common guest configuration

Every image should have:

* No SSH server
* No normal login account
* No password
* No desktop environment
* No shared folders
* No clipboard
* No host filesystem integration
* Read-only Nix store
* `private-vm-guestd` as the control plane
* Locked serial console
* Predictable VirtIO devices
* No persistent journald
* Volatile `/var/log`
* Volatile `/tmp`
* Automatic poweroff when the guest workflow completes

## 7. Image distribution through GHCR

Publish the guest images as OCI artifacts:

```text
ghcr.io/OWNER/private-vm-downloader:v0.1.0-amd64
ghcr.io/OWNER/private-vm-scanner:v0.1.0-amd64
ghcr.io/OWNER/private-vm-exporter:v0.1.0-amd64
```

Use custom OCI media types:

```text
application/vnd.private-vm.qcow2+zstd
application/vnd.private-vm.manifest.v1+json
application/spdx+json
```

GitHub Container Registry supports OCI images, public packages can be pulled anonymously, and container storage and bandwidth are currently free. ([GitHub Docs][5])

That is better than putting images in GitHub Actions artifacts or release assets. GitHub release assets are limited to less than 2 GiB per individual file, while Actions artifact storage is much smaller. ([GitHub Docs][6])

The CLI should use the ORAS Go libraries directly to pull OCI artifacts. It should not require the external `oras` or Docker CLI.

## 8. Supply-chain verification

Every CLI binary, package and guest image must have:

* SHA-256 digest
* SPDX SBOM
* GitHub artifact attestation
* Build manifest
* Source commit
* Flake lock digest
* Go module digest
* Guest role
* Architecture
* Required minimum QEMU version
* Image compatibility version

GitHub artifact attestations establish signed build provenance and can be verified for binaries and OCI images. ([GitHub Docs][7])

`private-vm images pull` must fail unless all of these match:

```text
Expected repository: OWNER/private-vm
Expected workflow:   .github/workflows/release.yml
Expected tag:        vX.Y.Z
Expected subject:    downloaded OCI digest
Expected arch:       host architecture
Expected role:       requested image role
```

Use `sigstore-go` inside `private-vm` so users do not need `gh attestation verify`.

An explicit custom source should require:

```bash
private-vm images source add \
  --unsafe-custom-source \
  --repository example/custom-private-vm
```

Custom sources must never silently inherit trust from the official source.

## 9. GitHub Actions design

### `ci.yml`

Runs for every pull request and push:

```text
gofmt check
go vet
go test
go test -race
govulncheck
static analysis
RPC fuzz tests
QMP parser fuzz tests
config schema tests
policy tests
Nix flake check
NixOS module evaluation
CLI builds for amd64 and arm64
```

Fork pull requests receive:

```text
contents: read
packages: none
id-token: none
attestations: none
```

Never use `pull_request_target` to build untrusted changes.

### `image-build.yml`

Runs on changes to:

```text
nix/**
flake.nix
flake.lock
cmd/private-vm-guestd/**
policies/**
```

Each role builds in a separate job so every role gets a fresh runner and its own 14 GB workspace.

```text
matrix:
  downloader
  scanner
  exporter
```

On pull requests:

* Build images
* Run static inspection
* Run TCG boot smoke test
* Do not publish

On `main`:

* Build
* Test
* Publish an `edge-<commit>` OCI artifact
* Attest it

### `nightly.yml`

Nightly should:

* Rebuild the exact locked inputs
* Confirm images still build
* Boot each image under QEMU TCG
* Test guest daemon readiness
* Test scanner definition update
* Test downloader VPN firewall logic with a mock WireGuard peer
* Test teardown and orphan cleanup

Dependency updates should arrive through reviewed Dependabot or Renovate pull requests. A nightly job should not silently rewrite `flake.lock`.

### `release.yml`

Triggered only by protected version tags:

```text
v0.1.0
v0.2.0
v1.0.0
```

Release process:

1. Rebuild Go binaries.
2. Build `.deb`, `.rpm` and tar archives.
3. Build all guest images.
4. Run boot and workflow tests.
5. Generate SBOMs.
6. Publish images to GHCR by digest.
7. Create GitHub artifact attestations.
8. Publish CLI packages to GitHub Releases.
9. Run a clean verification job.
10. Pull every artifact anonymously.
11. Verify every attestation.
12. Mark the release immutable.

All third-party GitHub Actions must be pinned to full commit SHAs. GitHub states that a full commit SHA is the only immutable way to reference an action. ([GitHub Docs][8])

## 10. User-facing CLI design

### Initial setup

```bash
private-vm init
private-vm doctor --strict
private-vm images sync
private-vm vpn import
private-vm usb enroll
```

### Normal use

```bash
private-vm plan
private-vm run
private-vm status
private-vm report
```

### Recovery and maintenance

```bash
private-vm abort
private-vm cleanup
private-vm images verify
private-vm images prune
```

## 11. Complete command hierarchy

```text
private-vm
├── version
├── init
├── doctor
├── config
│   ├── show
│   ├── get
│   ├── set
│   └── validate
├── images
│   ├── list
│   ├── sync
│   ├── pull
│   ├── verify
│   ├── inspect
│   ├── build
│   ├── test
│   └── prune
├── vpn
│   ├── import
│   ├── inspect
│   ├── test
│   ├── rotate
│   └── remove
├── usb
│   ├── list
│   ├── inspect
│   ├── enroll
│   ├── prepare
│   ├── verify
│   └── forget
├── plan
├── run
├── session
│   ├── status
│   ├── report
│   ├── abort
│   └── cleanup
├── policy
│   ├── list
│   ├── show
│   └── validate
├── system
│   ├── status
│   ├── install
│   └── uninstall
└── completion
    ├── bash
    ├── zsh
    └── fish
```

## 12. Secure input handling

A magnet link must not normally be accepted as a command-line argument because it can be recorded in:

* Shell history
* Process listings
* Terminal logs
* Desktop launch history

The default interaction should be:

```bash
private-vm run
```

Then:

```text
Input type:
  1. Magnet link
  2. Torrent file
  3. Resume current in-memory session

Paste magnet link:
```

The CLI reads it from the terminal without echo and sends it through the daemon’s ephemeral guest channel.

For automation:

```bash
printf '%s' "$MAGNET" | private-vm run --magnet-stdin
```

An argv form can exist only behind:

```bash
private-vm run \
  --allow-sensitive-argv \
  --magnet 'magnet:?xt=...'
```

## 13. Metadata-first planning

The run must not begin downloading immediately.

Workflow:

```text
1. Start downloader.
2. Establish Proton WireGuard.
3. Verify host and guest kill switches.
4. Add magnet in metadata-only mode.
5. Fetch torrent metadata.
6. Pause all file downloading.
7. Return exact file list and sizes.
8. Recalculate storage requirements.
9. Confirm USB capacity.
10. Ask the user which files to download.
11. Begin downloading only after checks pass.
```

This prevents discovering halfway through the download that:

* The scratch disk is too small
* The USB is too small
* The torrent contains unexpected files
* Extraction would exceed available capacity
* The torrent contains only blocked file types

## 14. Runtime state machine

```text
CREATED
   ↓
HOST_PREFLIGHTED
   ↓
IMAGES_VERIFIED
   ↓
SCANNER_UPDATED
   ↓
DOWNLOADER_BOOTED
   ↓
VPN_ESTABLISHED
   ↓
VPN_LEAK_TESTED
   ↓
TORRENT_METADATA_READY
   ↓
CAPACITY_CONFIRMED
   ↓
DOWNLOADING
   ↓
DOWNLOAD_COMPLETE
   ↓
DOWNLOADER_DESTROYED
   ↓
SCANNER_BOOTED_OFFLINE
   ↓
SCAN_COMPLETE
   ↓
POLICY_APPROVED or POLICY_REJECTED
   ↓
EXPORTER_BOOTED
   ↓
EXPORT_COMPLETE
   ↓
USB_CHECKSUM_VERIFIED
   ↓
ALL_GUESTS_DESTROYED
   ↓
SCRATCH_KEY_DESTROYED
   ↓
SESSION_DESTROYED
```

Any error moves immediately to:

```text
ABORTING
   ↓
ALL_GUESTS_STOPPED
   ↓
ENCRYPTED_DEVICES_CLOSED
   ↓
KEYS_DESTROYED
   ↓
SESSION_DESTROYED
```

Session state exists only under:

```text
/run/private-vm/<session-id>/
```

There is intentionally no session resume after a host reboot.

## 15. Mandatory preflight checks

`private-vm run` automatically performs `doctor` and `plan`. The user should never be expected to remember them.

### Host checks

| Check                                 | Failure behavior                   |
| ------------------------------------- | ---------------------------------- |
| Linux and systemd available           | Block                              |
| Supported CPU architecture            | Block                              |
| `/dev/kvm` exists and is usable       | Block                              |
| QEMU version satisfies image manifest | Block                              |
| Required kernel modules loaded        | Block                              |
| Unencrypted disk swap detected        | Block by default                   |
| Hibernation enabled                   | Block by default                   |
| Runtime directory not tmpfs           | Block                              |
| Root image directory writable by user | Block                              |
| Existing private-vm session active    | Block                              |
| Orphan device mapper found            | Clean, then recheck                |
| Insufficient RAM                      | Choose encrypted scratch or block  |
| Insufficient encrypted scratch space  | Block                              |
| Host root not encrypted               | Strong warning; strict mode blocks |
| USBGuard unavailable                  | Warning; strict mode blocks        |

### Image checks

| Check                              | Failure behavior         |
| ---------------------------------- | ------------------------ |
| OCI digest mismatch                | Never overridable        |
| Missing provenance attestation     | Never overridable        |
| Wrong repository identity          | Never overridable        |
| Wrong workflow identity            | Never overridable        |
| Wrong architecture                 | Block                    |
| Unsupported guest protocol version | Block                    |
| Base image writable                | Block                    |
| Image SBOM missing                 | Block in strict mode     |
| Scanner definitions too old        | Update before proceeding |

### VPN checks

| Check                                | Failure behavior  |
| ------------------------------------ | ----------------- |
| Invalid WireGuard syntax             | Block             |
| Missing private key                  | Block             |
| Missing endpoint                     | Block             |
| Endpoint cannot resolve              | Block             |
| Host egress namespace not restricted | Never overridable |
| Guest WireGuard handshake absent     | Block             |
| qBittorrent not bound to `proton0`   | Never overridable |
| Non-VPN public egress succeeds       | Never overridable |
| DNS bypass detected                  | Block             |
| IPv6 bypass detected                 | Block             |

Proton WireGuard configurations may eventually stop working if Proton retires a server, so `vpn test` must detect stale profiles and tell the user to generate a new one. ([Proton VPN][9])

### USB checks

| Check                                        | Failure behavior                    |
| -------------------------------------------- | ----------------------------------- |
| VID/PID/serial mismatch                      | Never overridable                   |
| More than one matching device                | Block                               |
| USB currently mounted                        | Block                               |
| USB contains host root or boot filesystem    | Never overridable                   |
| Composite keyboard/network interface present | Block                               |
| Device capacity too small                    | Block                               |
| Device is read-only                          | Block                               |
| Existing filesystem not expected             | Require explicit prepare            |
| USB disappears during export                 | Abort and preserve no session state |

### Scan checks

| Check                            | Failure behavior                      |
| -------------------------------- | ------------------------------------- |
| Scanner VM has a network device  | Never overridable                     |
| Quarantine disk writable         | Never overridable                     |
| ClamAV reports malware           | Reject                                |
| Relevant file skipped            | Reject                                |
| Scan limit reached               | Reject                                |
| Archive encrypted                | Reject unless decrypted and rescanned |
| Archive expansion exceeds policy | Reject                                |
| File extension/type mismatch     | Reject or manual quarantine           |
| Unexpected executable present    | Reject under safe policy              |
| Scanner process crashes          | Reject                                |
| Report incomplete                | Reject                                |

## 16. Policy modes

### `safe`

Default and recommended.

* Documents must be sanitized.
* Media must be fully decoded and re-encoded when supported.
* Archives are extracted and individually scanned.
* Executables are not exported.
* ISOs and VM images are not exported.
* Original hostile input is never placed on the USB.

```bash
private-vm run --policy safe
```

### `quarantine`

Allows the original file onto a dedicated encrypted quarantine USB.

* The USB is clearly labeled as untrusted.
* The output must be opened only in another disposable VM.
* Executables remain blocked from normal host use.
* The CLI prints an explicit destination warning.

```bash
private-vm run \
  --policy quarantine \
  --output usb:quarantine
```

### `raw`

Do not provide this in the first stable release.

A raw export mode undermines too many guarantees and will be used incorrectly. Add it only after the threat model and UX have been independently reviewed.

## 17. Networking design

The downloader has two kill-switch layers.

### Host-side restriction

The daemon:

1. Parses the WireGuard endpoint.
2. Resolves the endpoint before starting the VM.
3. Creates a dedicated network namespace.
4. Allows guest egress only to the Proton endpoint and port.
5. Drops all other direct guest traffic.

Therefore, even if the guest firewall fails, the downloader cannot send ordinary traffic directly through the host connection.

### Guest-side restriction

Inside the guest:

* `proton0` must be established.
* nftables permits qBittorrent traffic only through `proton0`.
* qBittorrent is explicitly bound to `proton0`.
* DNS uses only the tunnel-provided resolver.
* IPv6 is either tunneled correctly or disabled.
* Downloading remains paused until all checks succeed.

## 18. Ephemeral storage

### VM roots

The immutable downloaded base images remain:

```text
/var/lib/private-vm/images/
```

Each session receives temporary copy-on-write overlays under:

```text
/run/private-vm/<session-id>/disks/
```

### Torrent storage

Small download:

```text
RAM-backed sparse disk under /run
```

Large download:

```text
Encrypted sparse file on disk
+ random LUKS key held only in volatile runtime memory
```

The Go daemon should use:

* `memfd_create` for temporary secret material
* `mlock` where possible
* short secret lifetimes
* no conversion of secrets into Go strings
* redacted logging
* no environment variables for secrets

Go cannot offer a perfect guarantee that every historical memory copy has been erased because of garbage collection and runtime behavior. The project documentation must say that plainly rather than claiming perfect memory erasure.

## 19. One-way scanner-to-exporter transfer

Do not use a shared staging filesystem.

Instead:

```text
Scanner guestd
    ↓ framed stream
Host byte relay
    ↓ framed stream
Exporter guestd
    ↓
USB filesystem
```

The host relay:

* Does not interpret file contents
* Enforces maximum size
* Enforces one file at a time
* Validates frame lengths
* Computes an independent SHA-256
* Never stores the bytes on disk
* Does not allow exporter-to-scanner traffic

This avoids mounting a scanner-controlled filesystem in another trusted environment.

## 20. Installation methods

### NixOS module: primary method

```nix
{
  inputs.private-vm.url = "github:OWNER/private-vm";

  outputs = { nixpkgs, private-vm, ... }: {
    nixosConfigurations.my-laptop =
      nixpkgs.lib.nixosSystem {
        system = "x86_64-linux";

        modules = [
          private-vm.nixosModules.default

          {
            services.private-vm.enable = true;
          }
        ];
      };
  };
}
```

Then:

```bash
sudo nixos-rebuild switch --flake .#my-laptop
```

### Nix profile: CLI-only evaluation

```bash
nix run github:OWNER/private-vm#private-vm -- doctor
```

or:

```bash
nix profile install github:OWNER/private-vm#private-vm
```

Nix supports GitHub flake references and profile installation of flake outputs. ([Nix][10])

The profile installation alone does not configure the privileged daemon. On NixOS, the module is the supported full installation.

### Debian and Ubuntu

Release assets:

```text
private-vm_VERSION_amd64.deb
private-vm_VERSION_arm64.deb
```

The package installs:

* `/usr/bin/private-vm`
* `/usr/libexec/private-vmd`
* systemd unit
* Polkit policy
* tmpfiles rule
* udev rule
* manual pages
* completions

### Fedora and RHEL-compatible systems

Release assets:

```text
private-vm-VERSION-1.x86_64.rpm
private-vm-VERSION-1.aarch64.rpm
```

### Generic Linux

Provide:

```text
private-vm_VERSION_linux_amd64.tar.zst
private-vm_VERSION_linux_arm64.tar.zst
```

After verification:

```bash
sudo ./private-vm system install
```

This command installs the daemon, units and policies using typed Go code. It should display every filesystem change before proceeding.

Initial officially supported hosts should be:

```text
NixOS
Fedora
Ubuntu
Debian
```

Do not claim universal Linux support in v1. The daemon depends on:

* Linux
* systemd
* cgroups v2
* KVM
* nftables
* Polkit
* udev
* cryptsetup

## 21. Configuration locations

```text
/etc/private-vm/config.toml
/etc/private-vm/policies/
/etc/private-vm/devices.json

/var/lib/private-vm/images/
/var/lib/private-vm/scratch/

/run/private-vm/
/run/user/<uid>/private-vm/

~/.config/private-vm/config.toml
```

No secrets belong in `/etc/private-vm/config.toml`.

VPN storage modes:

```text
none                 Prompt every run; strongest privacy
desktop-keyring      Secret Service or KWallet
systemd-credential   TPM/passphrase-backed where available
```

The default should be `none`.

## 22. Logging and privacy

Default behavior:

* No telemetry
* No crash uploads
* No persistent session logs
* No persistent torrent names
* No persistent magnet links
* No persistent file names
* No QEMU stdout in journald
* No VPN keys in argv or environment
* No secret values in errors
* Redacted daemon lifecycle metadata only

Reports remain in `/run` unless the user explicitly runs:

```bash
private-vm session report --export ./scan-report.json
```

The tool should promise:

> No intentional persistent plaintext session state.

It should **not** promise:

> No trace can exist anywhere.

The host kernel, firmware, hardware, VPN provider and storage controller remain outside the tool’s complete control.

## 23. Implementation milestones

### Phase 1: Repository and CLI foundation

Deliver:

* Go module
* Flake
* CLI command tree
* Config parser
* Structured exit codes
* `doctor`
* `plan`
* Unit tests
* GitHub CI

Exit criteria:

```text
private-vm doctor --json
private-vm config validate
nix flake check
```

all work.

### Phase 2: Public guest images

Deliver:

* Downloader image
* Scanner image
* Exporter image
* Guest daemon
* TCG boot tests
* GHCR publication
* SBOMs
* Attestations

Exit criteria:

* Every image boots.
* Every image reports the correct role.
* No image accepts an interactive login.
* Images can be independently pulled and verified.

### Phase 3: Runtime daemon

Deliver:

* Unix RPC
* Polkit
* QEMU lifecycle
* QMP
* temporary overlays
* encrypted scratch
* cleanup watchdog
* startup orphan cleanup

Exit criteria:

* Killing the CLI destroys the VM.
* Killing QEMU triggers cleanup.
* Rebooting leaves only unrecoverable ciphertext.
* Base images never change.

### Phase 4: Torrent and VPN workflow

Deliver:

* WireGuard injection
* Host egress allowlist
* Guest kill switch
* qBittorrent binding
* metadata-only stage
* capacity recalculation
* download monitoring

Exit criteria:

* Torrent traffic stops immediately when WireGuard is removed.
* No direct guest traffic can bypass the endpoint allowlist.
* Insufficient space is detected before payload download begins.

### Phase 5: Scanner and policy engine

Deliver:

* ClamAV update phase
* offline scan phase
* file-type inspection
* archive policy
* scan reports
* safe/quarantine decisions

Exit criteria:

* Any skipped file rejects export.
* Any scanner error rejects export.
* Scanner phase contains no virtual NIC.
* Quarantine storage is read-only.

### Phase 6: USB exporter

Deliver:

* USB enrollment
* exact identity matching
* USBGuard integration
* exporter guest
* one-way stream
* post-write verification

Exit criteria:

* USB is never mounted by the host.
* USB is never exposed to downloader or scanner.
* Written hash matches the scanner and host relay hashes.

### Phase 7: Packaging and stable release

Deliver:

* NixOS module
* `.deb`
* `.rpm`
* generic archive
* installation documentation
* signed release
* immutable release process

## Final technology choices

```text
Project name:          private-vm
Language:              Go
Canonical guest OS:    Minimal NixOS
Canonical image build: Nixpkgs build-image / system.build.images.qcow
Optional acceptance:   Packer + QEMU
Virtualization:        QEMU/KVM
Runtime control:       private-vmd + QMP
Guest control:         private-vm-guestd over VirtIO serial
VPN:                   Proton WireGuard configuration
Torrent client:        qBittorrent-nox
Scanning:              ClamAV + role-specific sanitizers
Scratch storage:       tmpfs or ephemeral-key LUKS
USB isolation:         Dedicated exporter VM
Image distribution:    Public GHCR OCI artifacts
Provenance:            GitHub artifact attestations
Host installations:    NixOS module, deb, rpm, tar.zst
CI:                    Public GitHub Actions standard runners
```

The most important correction is this: **do not build Fedora desktop images with Packer as the core system. Build three minimal NixOS images declaratively, use Packer only for optional boot acceptance, and put all runtime orchestration into the `private-vm` Go application and its narrowly privileged daemon.**

[1]: https://protonvpn.com/support/wireguard-linux?srsltid=AfmBOooDdb6hpsHsvoDWL0A30V2n4k8TJ5UlOhKI7-m6fu_XJGJNbHQk&utm_source=chatgpt.com "How to manually configure WireGuard on Linux"
[2]: https://github.com/nix-community/nixos-generators "GitHub - nix-community/nixos-generators: Collection of image builders [maintainer=@Lassulus] · GitHub"
[3]: https://docs.github.com/en/actions/reference/runners/github-hosted-runners?utm_source=chatgpt.com "GitHub-hosted runners reference"
[4]: https://developer.hashicorp.com/packer/integrations/hashicorp/qemu/latest/components/builder/qemu?utm_source=chatgpt.com "QEMU Builder | Integrations | Packer"
[5]: https://docs.github.com/packages/working-with-a-github-packages-registry/working-with-the-container-registry?utm_source=chatgpt.com "Working with the Container registry - GitHub Docs"
[6]: https://docs.github.com/en/repositories/releasing-projects-on-github/about-releases?utm_source=chatgpt.com "About releases"
[7]: https://docs.github.com/actions/security-for-github-actions/using-artifact-attestations/using-artifact-attestations-to-establish-provenance-for-builds?utm_source=chatgpt.com "Using artifact attestations to establish provenance for builds"
[8]: https://docs.github.com/en/actions/reference/security/secure-use?utm_source=chatgpt.com "Secure use reference - GitHub Docs"
[9]: https://protonvpn.com/support/linux-vpn-setup?srsltid=AfmBOopY3DF231Xy9d5vrp856VZYh-9Q7L1qteEZgSqF42BHA5n9xgTc&utm_source=chatgpt.com "How to install Proton VPN on Linux"
[10]: https://nix.dev/manual/nix/2.18/command-ref/new-cli/nix3-profile-install?utm_source=chatgpt.com "nix profile install - Nix Reference Manual"
