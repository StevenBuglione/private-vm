The desktop requirement changes the image model. The correct design is a **full disposable graphical workstation**, while torrent downloading, scanning, and USB export remain separate security compartments.

# `private-vm`: graphical disposable-workstation architecture

## 1. Revised image set

The project should publish four immutable NixOS images:

| Image         | Desktop |                   Network | Purpose                                                       |
| ------------- | ------- | ------------------------: | ------------------------------------------------------------- |
| `workstation` | XFCE    |               Proton-only | Browser, office work, development and normal private activity |
| `downloader`  | XFCE    |               Proton-only | qBittorrent and torrent inspection                            |
| `scanner`     | XFCE    | Update-only, then offline | Malware scanning, manual inspection and sanitization          |
| `exporter`    | None    |                      None | Write approved output to an enrolled USB device               |

The workstation, downloader and scanner need graphical interfaces. The exporter should remain headless because its job is narrow and fully automated.

A single all-purpose desktop VM would be easier, but it would weaken the system substantially. A malicious torrent or document could then access browser sessions, work files, credentials and anything else created during the session.

## 2. Desktop choice

Use **XFCE as the default desktop environment**.

NixOS supports XFCE declaratively through its desktop-manager configuration, and XFCE provides a complete window manager, panel, desktop and file manager while remaining comparatively lightweight. ([NixOS Wiki][1])

XFCE is preferable here to GNOME or KDE Plasma because:

* Guest images and Nix closures are smaller.
* It consumes less guest memory.
* Software-rendered or virtual GPU operation is predictable.
* It is easier to build within the storage limits of free GitHub-hosted runners.
* It still provides a complete graphical environment.
* It works well for disposable VMs where visual effects are unimportant.

GitHub’s standard public Linux runners currently provide four CPUs, 16 GB of RAM and 14 GB of SSD storage, with free and unlimited use for public repositories. Each desktop image should therefore be built in a separate job so every build receives a clean 14 GB workspace. ([GitHub Docs][2])

KDE Plasma can later be offered as an optional locally built workstation flavor:

```text
workstation-xfce       Official and CI-built
workstation-plasma     Optional, locally built
```

Do not make Plasma part of the first release.

## 3. Workstation contents

The default `workstation` image should include:

```text
XFCE desktop
LightDM with local autologin
Firefox
VSCodium
LibreOffice
PDF viewer
Terminal
Thunar file manager
Archive manager
Git
OpenSSH client
curl
jq
KeePassXC
private-vm-guestd
WireGuard
nftables
NetworkManager
```

The desktop user should:

* Be named `private`.
* Have no reusable password.
* Have no `sudo` access.
* Be automatically logged into the local graphical session.
* Have an entirely ephemeral home directory.
* Have no SSH server.
* Have no inbound network services.
* Have no access to host directories.
* Have no direct USB access.

Autologin is acceptable because the graphical display is available only through a session-owned Unix socket on the already authenticated host. It does not expose remote network access.

## 4. Optional workstation bundles

Avoid putting every development tool into the default image. Add declarative bundles:

```text
basic
office
development
media
research
```

Example contents:

```text
basic:
  Firefox
  terminal
  file manager
  PDF viewer

office:
  basic
  LibreOffice
  spell-checking dictionaries

development:
  basic
  VSCodium
  Git
  Go
  JDK
  Kotlin
  Rust
  Python
  Node.js

media:
  basic
  VLC
  ffmpeg
  image viewer

research:
  office
  Zotero
  OCR and document tools
```

Official CI should build:

```text
workstation-basic-x86_64
workstation-office-x86_64
workstation-development-x86_64
```

The CLI selects the requested image:

```bash
private-vm desktop start --bundle development
```

Users on conventional Linux do not need Nix installed to use published bundles. They pull the prebuilt image from GHCR.

Custom bundles can be declared in Nix and built locally:

```bash
private-vm images build \
  --role workstation \
  --profile ./my-workstation.nix
```

## 5. Graphical display architecture

Use QEMU SPICE over a **Unix-domain socket**, not a TCP listening port.

```text
/run/private-vm/<session-id>/spice.sock
```

The socket should:

* Be owned by the invoking user.
* Have mode `0600`.
* Exist only for the session.
* Never listen on a host network interface.
* Be removed during teardown.

`private-vm` launches `remote-viewer` automatically after the desktop is ready:

```bash
private-vm desktop start
```

Internally:

```text
private-vm
    ↓
private-vmd
    ↓
QEMU/KVM
    ↓
SPICE Unix socket
    ↓
remote-viewer
```

The image should include `spice-vdagent` for mouse integration and automatic display resizing. SPICE guest tooling provides automatic resolution switching as well as optional clipboard integration. ([Spice Space][3])

Clipboard and file transfer must nevertheless be disabled at the QEMU server:

```text
disable-copy-paste=on
disable-agent-file-xfer=on
```

QEMU exposes both controls independently, allowing the display agent to remain available while clipboard and SPICE file transfer are blocked. ([QEMU Documentation][4])

Representative QEMU display configuration:

```text
-spice unix=on,addr=/run/private-vm/<id>/spice.sock,\
disable-ticketing=on,\
disable-copy-paste=on,\
disable-agent-file-xfer=on

-device virtio-vga
-device virtserialport,\
chardev=spicechannel0,\
name=com.redhat.spice.0

-chardev spicevmc,id=spicechannel0,name=vdagent
```

The Go implementation must generate QEMU arguments directly. It must not concatenate untrusted strings into one shell command.

## 6. Desktop isolation defaults

The following features must be disabled:

```text
Host-to-guest clipboard
Guest-to-host clipboard
SPICE file transfer
Drag and drop
Shared folders
virtiofs
9p filesystem sharing
Host SSH-agent forwarding
Host GPG-agent forwarding
Host password-manager integration
USB redirection
Webcam passthrough
Microphone passthrough
GPU passthrough
Host Docker socket
Host Wayland/X11 socket
```

Audio should be disabled by default.

It may be enabled explicitly for media work:

```bash
private-vm desktop start --audio
```

Webcam, microphone and arbitrary USB forwarding should not be implemented in the initial release.

## 7. Controlled file import

The user will need files inside the workstation. Do not solve that with a shared host directory.

Use an explicit import operation:

```bash
private-vm workspace import ~/Documents/report.pdf
```

The process should be:

```text
Host opens the explicitly selected file read-only
        ↓
private-vm computes its size and SHA-256
        ↓
Host streams bytes through the private-vmd RPC
        ↓
private-vmd relays bytes through a VirtIO serial channel
        ↓
private-vm-guestd writes the file into ~/Inbox
        ↓
Guest independently verifies size and SHA-256
```

Nothing in the guest can enumerate the host filesystem. Only files explicitly selected by the user are imported.

Directory imports should be rejected initially. Supporting directories encourages accidental exposure of source trees, credentials and hidden files.

Later, a safe directory import can package only explicitly selected files into a deterministic archive after showing the complete manifest.

## 8. Untrusted-file import

Files downloaded through the torrent workflow must never be imported directly into the workstation.

The allowed path is:

```text
Downloader VM
    ↓ encrypted quarantine disk
Scanner VM, read-only
    ↓ scan and sanitize
Host memory relay
    ↓
Workstation Inbox
```

For a sanitized document:

```bash
private-vm scan approve \
  --session <id> \
  --open-in workstation
```

For executables, scripts, ISOs or VM images, the safe policy must refuse workstation import. Those remain usable only inside another disposable quarantine VM.

## 9. Work output

The workstation’s home directory disappears when the session ends. Users therefore need an explicit export workflow.

Files intended for export should be placed in:

```text
~/Export
```

The guest daemon watches only that directory and maintains:

```text
relative path
size
MIME type
SHA-256
modification state
```

The user can inspect it:

```bash
private-vm workspace list
```

Export to the dedicated USB:

```bash
private-vm workspace export --to usb
```

Export to another new workstation session:

```bash
private-vm workspace export --to encrypted-bundle
```

Discard it intentionally:

```bash
private-vm workspace discard --all
```

The host must not directly mount the guest filesystem to collect files.

## 10. Stop protection

The CLI should prevent accidental destruction of unsaved work.

Running:

```bash
private-vm desktop stop
```

must first ask `private-vm-guestd` for the workspace state.

Possible responses:

```text
CLEAN
No files exist in ~/Export.

READY
Files exist in ~/Export and have already been exported successfully.

UNEXPORTED
Files exist in ~/Export that have never been exported.

CHANGED
Files were modified after their latest export.

UNREACHABLE
The guest agent cannot report workspace state.
```

Behavior:

| State         | Action                                    |
| ------------- | ----------------------------------------- |
| `CLEAN`       | Allow shutdown                            |
| `READY`       | Allow shutdown                            |
| `UNEXPORTED`  | Block ordinary shutdown                   |
| `CHANGED`     | Block ordinary shutdown                   |
| `UNREACHABLE` | Warn and require destructive confirmation |

The user can intentionally destroy everything:

```bash
private-vm desktop stop --discard
```

For automation:

```bash
private-vm desktop stop --require-clean
```

This should return a nonzero exit code rather than prompting.

## 11. Session command model

The primary workflow becomes:

```bash
private-vm desktop start
```

or:

```bash
private-vm run workstation
private-vm run torrent
private-vm run scanner
```

Revised command hierarchy:

```text
private-vm
├── desktop
│   ├── start
│   ├── connect
│   ├── status
│   ├── stop
│   ├── restart-viewer
│   └── bundles
│       ├── list
│       └── inspect
│
├── workspace
│   ├── import
│   ├── inbox
│   ├── list
│   ├── inspect
│   ├── export
│   ├── verify
│   └── discard
│
├── run
│   ├── workstation
│   ├── torrent
│   └── scanner
│
├── session
│   ├── list
│   ├── status
│   ├── report
│   ├── stop
│   ├── abort
│   └── cleanup
│
├── images
│   ├── list
│   ├── sync
│   ├── pull
│   ├── verify
│   ├── inspect
│   ├── build
│   ├── test
│   └── prune
│
└── doctor
```

Common examples:

```bash
# Normal disposable desktop
private-vm desktop start

# Development workstation
private-vm desktop start --bundle development

# Private desktop with audio
private-vm desktop start --bundle media --audio

# Open an existing active display again
private-vm desktop connect

# Import a trusted local file
private-vm workspace import ./document.pdf

# Export finished work
private-vm workspace export --to usb

# Stop only when all work is safely exported
private-vm desktop stop --require-clean
```

## 12. Desktop-specific preflight checks

`private-vm desktop start` should run all general checks plus:

| Check                                             | Failure behavior          |
| ------------------------------------------------- | ------------------------- |
| `remote-viewer` or supported SPICE client missing | Block                     |
| SPICE Unix-socket support unavailable             | Block                     |
| VirtIO GPU unsupported                            | Fall back to QXL or block |
| Host display session unavailable                  | Block unless `--headless` |
| Desktop image not verified                        | Block                     |
| Image role is not `workstation`                   | Block                     |
| Insufficient guest memory                         | Block                     |
| Insufficient temporary root space                 | Block                     |
| Existing socket path occupied                     | Block                     |
| Clipboard disabled flag absent                    | Block in strict mode      |
| SPICE file-transfer disable flag absent           | Block in strict mode      |
| QEMU display bound to TCP                         | Never overridable         |
| Host shared-directory device detected             | Never overridable         |
| Unexpected USB device configured                  | Never overridable         |

Recommended defaults:

```text
Workstation basic:
  4 vCPU
  8 GB RAM
  40 GB ephemeral root

Workstation development:
  8 vCPU
  16 GB RAM
  80 GB ephemeral root

Downloader:
  4 vCPU
  6 GB RAM
  20 GB ephemeral root
  Separate encrypted quarantine disk

Scanner:
  6 vCPU
  12 GB RAM
  40 GB ephemeral root

Exporter:
  2 vCPU
  1 GB RAM
  2 GB ephemeral root
```

`private-vm plan` should calculate whether the host can run the selected configuration without excessive memory pressure before creating anything.

## 13. Workstation network policy

The workstation should use the same layered network protection as the downloader:

```text
Host network namespace restriction
        +
Guest nftables kill switch
        +
Proton WireGuard tunnel
```

The workstation must not display the desktop as “online” until:

* The WireGuard configuration parses correctly.
* The Proton endpoint resolves.
* A WireGuard handshake succeeds.
* DNS resolution succeeds through the tunnel.
* Direct non-VPN IPv4 egress fails.
* Direct non-VPN IPv6 egress fails.
* The reported public address is different from the host’s public address.

The desktop should show a small local status application:

```text
VPN CONNECTED
Kill switch ACTIVE
Host sharing DISABLED
Clipboard DISABLED
Session EPHEMERAL
```

This application receives state from `private-vm-guestd`; it should not independently make security decisions.

If the VPN fails during work:

1. Guest nftables blocks normal traffic.
2. Host namespace policy blocks bypass traffic.
3. The desktop displays a full-screen warning.
4. Network applications remain open but disconnected.
5. The session is not automatically destroyed.

## 14. Browser configuration

Firefox should start with:

```text
Private browsing by default
No password saving
No form-history saving
No browser telemetry
No crash-report submission
No automatic file opening
Downloads directed to ~/Downloads
HTTPS-only mode
WebRTC proxy-only configuration where supported
No preinstalled third-party extensions
```

Do not claim that private browsing or Proton VPN makes the user anonymous. Logging into an account identifies the session to that service, and remote services retain their own activity records.

The browser profile is destroyed with the VM.

## 15. Desktop image configuration

The common NixOS desktop module should resemble:

```nix
{ pkgs, ... }:

{
  services.xserver.enable = true;

  services.xserver.desktopManager.xfce.enable = true;
  services.xserver.displayManager.lightdm.enable = true;

  services.displayManager.autoLogin = {
    enable = true;
    user = "private";
  };

  users.users.private = {
    isNormalUser = true;
    createHome = true;
    extraGroups = [ "networkmanager" ];
  };

  users.users.private.initialHashedPassword = "!";

  security.sudo.enable = false;

  services.openssh.enable = false;

  networking.networkmanager.enable = true;

  services.spice-vdagentd.enable = true;

  environment.systemPackages = with pkgs; [
    firefox
    xfce.xfce4-terminal
    xfce.thunar
    xfce.ristretto
    mousepad
    evince
    file-roller
    private-vm-guestd
  ];

  services.journald.extraConfig = ''
    Storage=volatile
    RuntimeMaxUse=64M
  '';
}
```

The exact option names must be validated against the pinned Nixpkgs revision during implementation; NixOS exposes desktop functionality declaratively through its module and configuration-option system. ([nixos.org][5])

## 16. Public image build strategy

The repository should now publish:

```text
ghcr.io/OWNER/private-vm-workstation-basic
ghcr.io/OWNER/private-vm-workstation-office
ghcr.io/OWNER/private-vm-workstation-development
ghcr.io/OWNER/private-vm-downloader
ghcr.io/OWNER/private-vm-scanner
ghcr.io/OWNER/private-vm-exporter
```

Each image gets an independent GitHub Actions job:

```yaml
strategy:
  fail-fast: false
  matrix:
    image:
      - workstation-basic
      - workstation-office
      - workstation-development
      - downloader
      - scanner
      - exporter
```

Before beginning an image build, CI should check:

```text
Available disk space
Available memory
Expected Nix closure class
Maximum allowed image size
Maximum allowed OCI compressed size
```

Each job should:

1. Remove unnecessary preinstalled runner software.
2. Install Nix.
3. Build only one image.
4. Run static image inspection.
5. Boot-test it under QEMU TCG.
6. Compress it immediately.
7. Upload it to GHCR.
8. Generate its SBOM and attestation.
9. Delete its uncompressed working files.

Public repositories can use the standard GitHub-hosted runners without billed Actions minutes, but their 14 GB SSD means builds must remain deliberately small and isolated by job. ([GitHub Docs][2])

## 17. Updated guest roles

### Workstation VM

```text
Graphical desktop
Proton-only networking
Trusted user work
Trusted imports
No torrent quarantine disk
No USB passthrough
Explicit export only
```

### Downloader VM

```text
Graphical qBittorrent
Proton-only networking
No personal accounts
No credentials
No work files
Encrypted quarantine output only
```

### Scanner VM

```text
Graphical inspection desktop
Online only before quarantine is attached
Offline while inspecting
Quarantine attached read-only
No USB access
Output streamed to workstation or exporter
```

### Exporter VM

```text
No desktop
No network
No quarantine access
Receives one approved stream
Writes one enrolled USB device
Verifies output hash
Powers off
```

## 18. Updated complete workflow

### Normal private work

```text
1. private-vm performs host preflight.
2. It pulls and verifies the workstation image.
3. It creates a temporary root overlay.
4. It injects a Proton WireGuard configuration.
5. It creates the restricted network namespace.
6. It boots the graphical workstation.
7. It verifies the VPN and kill switches.
8. It opens remote-viewer.
9. The user performs normal work.
10. The user places finished files in ~/Export.
11. private-vm exports them through the exporter VM.
12. The CLI verifies the destination hashes.
13. The workstation shuts down.
14. Root overlay, browser state, home directory, logs and runtime secrets are destroyed.
```

### Torrent and work workflow

```text
1. Start disposable downloader desktop.
2. Establish Proton and verify both kill-switch layers.
3. Fetch torrent metadata without starting payload download.
4. Confirm file selection and storage capacity.
5. Download to encrypted quarantine storage.
6. Destroy the downloader VM.
7. Update scanner definitions in a clean scanner session.
8. Restart scanner offline with quarantine read-only.
9. Scan and sanitize the selected file.
10. Destroy the scanner VM.
11. Start a clean workstation desktop.
12. Stream only approved output into ~/Inbox.
13. Perform work in the workstation.
14. Export finished results through the exporter VM.
15. Destroy every VM and the quarantine key.
```

## Final decision

The canonical end-user environment should be:

```text
NixOS XFCE graphical workstation
running ephemerally under QEMU/KVM
displayed through SPICE over a Unix socket
with Proton WireGuard and two-layer egress enforcement
with controlled file import and controlled exporter-VM output
```

The security images remain separated:

```text
workstation-desktop
downloader-desktop
scanner-desktop
exporter-headless
```

This gives you a real desktop for browsing, coding, office work and inspecting files without collapsing the downloader, scanner and work environments into one large trust boundary.

The next refinement should define the exact Go packages, RPC protocol and Nix modules for the graphical workstation path.

[1]: https://wiki.nixos.org/wiki/Xfce?utm_source=chatgpt.com "Xfce - Official NixOS Wiki"
[2]: https://docs.github.com/en/actions/reference/runners/github-hosted-runners?utm_source=chatgpt.com "GitHub-hosted runners reference"
[3]: https://www.spice-space.org/download.html?utm_source=chatgpt.com "Download"
[4]: https://qemu.readthedocs.io/en/v8.2.10/system/invocation.html?utm_source=chatgpt.com "Invocation — QEMU 8.2.10 documentation"
[5]: https://nixos.org/manual/nixos/stable/options?utm_source=chatgpt.com "Appendix A. Configuration Options - NixOS"
