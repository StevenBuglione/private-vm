{
  description = "private-vm: disposable graphical private-workstation orchestrator";

  inputs = {
    # Release branches are intentionally pinned by flake.lock. NIX-001 must
    # generate and commit the lock file against NixOS 26.05 before first build.
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";
  };

  outputs =
    { self, nixpkgs }:
    let
      supportedSystems = [
        "x86_64-linux"
        "aarch64-linux"
      ];
      forAllSystems = nixpkgs.lib.genAttrs supportedSystems;
      pkgsFor = system: import nixpkgs { inherit system; };
      projectVersion = "0.0.0-dev";
      sourceCommit = self.rev or (self.dirtyRev or "unknown");
      sourceDirty = if self ? rev then "false" else "true";
      sourceLastModifiedDate = self.lastModifiedDate or "19700101000000";
      spdxCreationTime = builtins.concatStringsSep "" [
        (builtins.substring 0 4 sourceLastModifiedDate)
        "-"
        (builtins.substring 4 2 sourceLastModifiedDate)
        "-"
        (builtins.substring 6 2 sourceLastModifiedDate)
        "T"
        (builtins.substring 8 2 sourceLastModifiedDate)
        ":"
        (builtins.substring 10 2 sourceLastModifiedDate)
        ":"
        (builtins.substring 12 2 sourceLastModifiedDate)
        "Z"
      ];
      flakeLockSHA256 = builtins.hashFile "sha256" ./flake.lock;
      workstationBundleCatalog = builtins.fromJSON (builtins.readFile ./project/workstation-bundles.json);

      capabilitiesFor =
        role:
        nixpkgs.lib.sort builtins.lessThan (
          [
            "guest-events"
            "guest-shutdown"
            "guest-status"
          ]
          ++ {
            workstation = [
              "desktop"
              "network-warning"
              "workspace-export"
              "workspace-import"
            ];
            downloader = [
              "quarantine-seal"
              "torrent-download"
              "torrent-metadata"
              "vpn-verification"
              "wireguard-config"
            ];
            scanner = [
              "approved-export"
              "definitions-update"
              "inventory"
              "offline-verification"
              "reconstruct"
              "scan"
              "scan-report"
            ];
            exporter = [
              "usb-finalize"
              "usb-inspect"
              "usb-prepare"
              "usb-verify"
              "usb-write"
            ];
          }
          .${role}
        );

      scannerForbiddenCommands = [
        "cargo"
        "cmake"
        "code"
        "codium"
        "curl"
        "evince"
        "file-roller"
        "firefox"
        "gcc"
        "gdb"
        "git"
        "go"
        "gradle"
        "javac"
        "keepassxc"
        "kotlin"
        "make"
        "mousepad"
        "node"
        "npm"
        "python"
        "python3"
        "qbittorrent"
        "ristretto"
        "rustc"
        "ssh"
        "vscodium"
        "zenity"
      ];

      privateVMFor =
        system:
        let
          pkgs = pkgsFor system;
        in
        import ./nix/package.nix {
          inherit pkgs sourceCommit sourceDirty;
          version = projectVersion;
          src = self;
        };

      guestdFor =
        system: role:
        let
          pkgs = pkgsFor system;
        in
        pkgs.buildGoModule {
          pname = "private-vm-guestd-${role}";
          version = projectVersion;
          src = self;
          vendorHash = null;
          env.CGO_ENABLED = 0;
          subPackages = [ "cmd/private-vm-guestd" ];
          ldflags = [
            "-s"
            "-w"
            "-X github.com/StevenBuglione/private-vm/internal/buildinfo.Version=${projectVersion}"
            "-X github.com/StevenBuglione/private-vm/internal/buildinfo.Commit=${sourceCommit}"
            "-X github.com/StevenBuglione/private-vm/internal/buildinfo.Dirty=${sourceDirty}"
            "-X github.com/StevenBuglione/private-vm/internal/guest.CompiledRole=${role}"
          ];
        };

      guestArgsFor = system: role: bundle: {
        privateVMPackage = guestdFor system role;
        guestRole = role;
        guestBundle = bundle;
        guestArchitecture = (pkgsFor system).stdenv.hostPlatform.parsed.cpu.name;
        guestCapabilities = capabilitiesFor role;
        guestSourceCommit = sourceCommit;
        guestFlakeLockSHA256 = flakeLockSHA256;
        guestSBOMCreated = spdxCreationTime;
        guestdVersion = projectVersion;
      };

      guest =
        system: role: bundle: module:
        nixpkgs.lib.nixosSystem {
          inherit system;
          specialArgs = guestArgsFor system role bundle;
          modules = [
            ./nix/guests/image-base.nix
            module
          ];
        };

      testTokenFor =
        system: (pkgsFor system).writeText "private-vm-test-capability" "0123456789abcdef0123456789abcdef";

      tcgQEMUOptionsFor = system: [
        "-machine"
        "accel=tcg"
        "-fw_cfg"
        "name=opt/private-vm/session-capability,file=${testTokenFor system}"
      ];

      commonGuestTestFor =
        system:
        let
          pkgs = pkgsFor system;
        in
        pkgs.testers.runNixOSTest {
          name = "private-vm-common-guest";
          requiredFeatures.kvm = false;
          node.specialArgs = guestArgsFor system "workstation" "test";
          nodes.machine = { lib, ... }: {
            imports = [ ./nix/guests/image-base.nix ];
            networking.hostName = "workstation";
            users.users.root.hashedPasswordFile = lib.mkForce null;
            users.users.private = {
              isNormalUser = true;
              hashedPassword = "!";
            };
            virtualisation.memorySize = 1024;
            virtualisation.cores = 2;
            virtualisation.vlans = [ ];
            virtualisation.qemu.options = tcgQEMUOptionsFor system;
          };
          testScript = ''
            machine.wait_for_unit("multi-user.target")
            machine.wait_for_unit("private-vm-guestd.service")
            machine.succeed("systemctl is-active private-vm-guestd.service")
            machine.succeed("grep -Eq '^root:![^:]*:' /etc/shadow")
            machine.succeed("grep -Eq '^private:![^:]*:' /etc/shadow")
            machine.succeed("! systemctl is-enabled sshd.service")
            machine.succeed("test ! -e /run/current-system/sw/bin/sudo")
            machine.succeed("test $(findmnt -n -o FSTYPE -T /tmp) = tmpfs")
            machine.succeed("test $(findmnt -n -o FSTYPE -T /var/tmp) = tmpfs")
            machine.succeed("test $(findmnt -n -o FSTYPE -T /var/log) = tmpfs")
            machine.succeed("test ! -e /var/log/journal")
            machine.succeed("grep -F '\"role\":\"workstation\"' /etc/private-vm/image.json")
            machine.succeed("private-vm-guestd --version | grep -F '\"guestRole\":\"workstation\"'")
            machine.succeed("private-vm-guestd --version | grep -F '\"workspace-import\"'")
            listeners = machine.succeed("ss -H -lntu")
            assert listeners.strip() == "", f"unexpected TCP/UDP listeners: {listeners}"
            machine.succeed("ss -H -l -A vsock | grep -E '(^|:)4050([[:space:]]|$)'")
          '';
        };

      workstationDesktopTestFor =
        system:
        let
          pkgs = pkgsFor system;
          bundleManifest = builtins.toJSON {
            schema_version = workstationBundleCatalog.schema_version;
            project = workstationBundleCatalog.project;
            role = workstationBundleCatalog.role;
            bundle = "basic";
            packages = workstationBundleCatalog.bundles.basic;
          };
          bundleManifestSHA256 = builtins.hashString "sha256" bundleManifest;
        in
        pkgs.testers.runNixOSTest {
          name = "private-vm-workstation-desktop";
          requiredFeatures.kvm = false;
          # The reduced qemu_test package intentionally omits SPICE. This gate
          # exercises the production Unix-SPICE configuration, so use the
          # pinned host-only QEMU build while retaining TCG acceleration.
          qemu.package = pkgs.qemu_kvm;
          node.specialArgs = guestArgsFor system "workstation" "basic";
          nodes.machine = { lib, ... }: {
            imports = [
              ./nix/guests/image-base.nix
              ./nix/guests/workstation-basic.nix
            ];
            users.users.root.hashedPasswordFile = lib.mkForce null;
            virtualisation.memorySize = 2048;
            virtualisation.cores = 2;
            virtualisation.vlans = [ ];
            virtualisation.qemu.options = tcgQEMUOptionsFor system ++ [
              "-spice"
              "unix=on,addr=spice.sock,disable-ticketing=on,disable-copy-paste=on,disable-agent-file-xfer=on"
              "-device"
              "virtio-serial-pci,id=spice-serial"
              "-chardev"
              "spicevmc,id=spiceagent,name=vdagent"
              "-device"
              "virtserialport,bus=spice-serial.0,chardev=spiceagent,name=com.redhat.spice.0"
            ];
          };
          testScript = ''
            machine.wait_for_unit("graphical.target")
            machine.wait_for_unit("display-manager.service")
            machine.wait_for_x()
            machine.wait_until_succeeds("loginctl list-sessions --no-legend | grep -E '[[:space:]]private[[:space:]]'")
            machine.succeed("test -x /run/current-system/sw/bin/startxfce4")
            machine.wait_until_succeeds("loginctl user-status private --no-pager | grep -F xfce4-session")
            machine.wait_until_succeeds("loginctl user-status private --no-pager | grep -F spice-vdagent")
            machine.succeed("systemctl is-active spice-vdagentd.service")
            machine.succeed("test -c /dev/virtio-ports/com.redhat.spice.0")
            machine.succeed("spice_root=$(dirname $(dirname $(readlink -f $(command -v spice-vdagent)))); test -e $spice_root/etc/xdg/autostart/spice-vdagent.desktop")
            machine.succeed("grep -Eq '^private:![^:]*:' /etc/shadow")
            machine.succeed("test $(stat -c '%U:%G:%a' /home/private) = private:users:700")
            machine.succeed("test $(stat -c '%U:%G:%a' /home/private/Downloads) = private:users:700")
            machine.succeed("test $(stat -c '%U:%G:%a' /home/private/Inbox) = private:users:700")
            machine.succeed("test $(stat -c '%U:%G:%a' /home/private/Export) = private:users:700")
            machine.succeed("test $(sha256sum /etc/private-vm/workstation-bundle.json | cut -d ' ' -f 1) = ${bundleManifestSHA256}")
            machine.succeed("jq -e '.policies.DisableTelemetry == true and .policies.DisableFirefoxStudies == true and .policies.DownloadDirectory == \"''${home}/Downloads\" and .policies.NetworkPrediction == false and .policies.Preferences[\"browser.crashReports.unsubmittedCheck.autoSubmit2\"] == {Status: \"locked\", Value: false} and .policies.Preferences[\"browser.crashReports.unsubmittedCheck.enabled\"] == {Status: \"locked\", Value: false} and .policies.Preferences[\"browser.privatebrowsing.autostart\"] == {Status: \"locked\", Value: true} and .policies.Preferences[\"browser.tabs.crashReporting.sendReport\"] == {Status: \"locked\", Value: false} and .policies.Preferences[\"media.peerconnection.enabled\"] == {Status: \"locked\", Value: false} and .policies.Preferences[\"network.prefetch-next\"] == {Status: \"locked\", Value: false}' /etc/firefox/policies/policies.json")
            machine.succeed("test -x /run/current-system/sw/bin/firefox")
            machine.succeed("xfce_pid=$(loginctl user-status private --no-pager | grep -F xfce4-session | grep -oE '[0-9]+' | head -n1); test -n \"$xfce_pid\"; tr '\\0' '\\n' < /proc/$xfce_pid/environ | grep -Fx MOZ_CRASHREPORTER_DISABLE=1")
            machine.succeed("for command in curl evince file-roller firefox git jq keepassxc mousepad ristretto ssh thunar xfce4-terminal zenity; do command -v $command >/dev/null || exit 1; done")
            machine.succeed("for command in gvfsd nm-applet parole pavucontrol tumblerd udisksctl xfce4-screenshooter xfce4-taskmanager; do ! command -v $command >/dev/null || exit 1; done")
            machine.succeed("! systemctl is-enabled sshd.service")
            machine.succeed("! systemctl --global is-enabled gcr-ssh-agent.service; ! systemctl --global is-enabled gcr-ssh-agent.socket")
            machine.succeed("su -s /bin/sh private -c 'xfconf-query -c xfce4-session -p /startup/ssh-agent/enabled | grep -Fx false'")
            machine.succeed("su -s /bin/sh private -c 'xfconf-query -c xfce4-session -p /startup/ssh-agent/enabled -s true; xfconf-query -c xfce4-session -p /startup/ssh-agent/enabled | grep -Fx false'")
            machine.succeed("! loginctl user-status private --no-pager | grep -E '(ssh-agent|gcr-ssh-agent)'")
            machine.succeed("test ! -e /run/current-system/sw/bin/sshd")
            machine.succeed("ssh_root=$(dirname $(dirname $(readlink -f $(command -v ssh)))); test ! -e $ssh_root/etc/ssh/sshd_config; test ! -e $ssh_root/libexec/sftp-server; test ! -e $ssh_root/libexec/sshd-auth; test ! -e $ssh_root/libexec/sshd-session")
            machine.succeed("test ! -e /run/current-system/sw/bin/sudo")
            listeners = machine.succeed("ss -H -lntu")
            assert listeners.strip() == "", f"unexpected TCP/UDP listeners: {listeners}"
          '';
        };

      downloaderDesktopTestFor =
        system:
        let
          pkgs = pkgsFor system;
        in
        pkgs.testers.runNixOSTest {
          name = "private-vm-downloader-desktop";
          requiredFeatures.kvm = false;
          node.specialArgs = guestArgsFor system "downloader" null;
          nodes.machine = { lib, ... }: {
            imports = [
              ./nix/guests/image-base.nix
              ./nix/guests/downloader.nix
            ];
            users.users.root.hashedPasswordFile = lib.mkForce null;
            virtualisation.memorySize = 2048;
            virtualisation.cores = 2;
            virtualisation.vlans = [ ];
            virtualisation.qemu.options = tcgQEMUOptionsFor system;
          };
          testScript = ''
            import json

            machine.wait_for_unit("graphical.target")
            machine.wait_for_unit("display-manager.service")
            machine.wait_for_x()
            machine.wait_until_succeeds("loginctl list-sessions --no-legend | grep -E '[[:space:]]private[[:space:]]'")
            machine.wait_until_succeeds("test -S /run/user/$(id -u private)/bus")
            machine.succeed("test -x /run/current-system/sw/bin/startxfce4")
            machine.succeed("test -x /run/current-system/sw/bin/wg")
            machine.succeed("test -x /run/current-system/sw/bin/nft")
            machine.succeed("test -e /run/current-system/sw/share/applications/private-vm-qbittorrent.desktop")
            machine.succeed("test ! -e /run/current-system/sw/bin/qbittorrent")
            machine.succeed("grep -Fx 'Session\\Interface=proton0' /etc/private-vm/qbittorrent/qBittorrent.conf")
            machine.succeed("grep -Fx 'Session\\InterfaceName=proton0' /etc/private-vm/qbittorrent/qBittorrent.conf")
            machine.succeed("grep -Fx 'PortForwardingEnabled=false' /etc/private-vm/qbittorrent/qBittorrent.conf")
            machine.succeed("grep -Fx 'FileLogger\\Enabled=false' /etc/private-vm/qbittorrent/qBittorrent.conf")
            machine.succeed("grep -Fx 'WebUI\\Enabled=true' /etc/private-vm/qbittorrent/qBittorrent.conf")
            machine.succeed("grep -Fx 'WebUI\\LocalHostAuth=true' /etc/private-vm/qbittorrent/qBittorrent.conf")
            machine.succeed("! grep -Eiq '(private.?key|password|magnet:|endpoint)' /etc/private-vm/qbittorrent/qBittorrent.conf")
            machine.succeed("! grep -RIE '(PrivateKey|PresharedKey|magnet:|Endpoint[[:space:]]*=)' /etc/private-vm")
            version = json.loads(machine.succeed("private-vm-guestd --version"))
            expected_capabilities = [
              "guest-events",
              "guest-shutdown",
              "guest-status",
              "quarantine-seal",
              "torrent-download",
              "torrent-metadata",
              "vpn-verification",
              "wireguard-config",
            ]
            assert version["guestRole"] == "downloader", version
            assert version["capabilities"] == expected_capabilities, version
            machine.succeed("for command in evince file-roller firefox git gvfsd jq keepassxc libreoffice mousepad nm-applet parole pavucontrol ristretto thunar tumblerd udisksctl xfce4-screenshooter xfce4-taskmanager xfce4-terminal; do ! command -v $command >/dev/null || exit 1; done")
            machine.succeed("nft list table inet private_vm_downloader | grep -F 'policy drop'")
            machine.succeed("test $(stat -c '%U:%G:%a' /run/private-vm-vpn) = root:root:711")

            machine.succeed("install -d -o private -g users -m 0700 /mnt/quarantine")
            machine.succeed("mount -t tmpfs -o nodev,nosuid,noexec,size=64M private-vm-quarantine /mnt/quarantine")
            machine.succeed("chown private:users /mnt/quarantine")
            machine.succeed("ip link add proton0 type dummy")
            machine.succeed("ip link set proton0 up")

            user_systemctl = "runuser -u private -- env XDG_RUNTIME_DIR=/run/user/$(id -u private) systemctl --user"
            machine.fail(f"{user_systemctl} start private-vm-qbittorrent.service")
            machine.succeed("! pgrep -u private -x qbittorrent")
            machine.succeed("systemctl show --user --machine=private@ private-vm-qbittorrent.service -p AssertResult | grep -Fx AssertResult=no")

            machine.succeed("install -o root -g root -m 0444 /dev/null /run/private-vm-vpn/ready")
            start_status, start_output = machine.execute(f"{user_systemctl} start private-vm-qbittorrent.service")
            if start_status != 0:
              log.error(start_output)
              log.error(machine.succeed("journalctl --no-pager -n 100 _UID=$(id -u private)"))
            assert start_status == 0, "VPN-gated qBittorrent did not start"
            machine.wait_until_succeeds(f"{user_systemctl} is-active --quiet private-vm-qbittorrent.service")
            listeners = machine.succeed("ss -H -ltn")
            for listener in listeners.splitlines():
              address = listener.split()[3]
              assert address.startswith("127.0.0.1:") or address.startswith("[::1]:"), listener
            machine.succeed("grep -Fx 'Session\\Interface=proton0' /run/user/$(id -u private)/private-vm-qbittorrent/qBittorrent/config/qBittorrent.conf")
            machine.succeed("test ! -d /run/user/$(id -u private)/private-vm-qbittorrent/qBittorrent/data/logs")

            machine.succeed(f"{user_systemctl} stop private-vm-qbittorrent.service")
            machine.wait_until_succeeds(f"! {user_systemctl} is-active --quiet private-vm-qbittorrent.service")
            machine.succeed("! pgrep -u private -x qbittorrent")
            machine.succeed("rm /run/private-vm-vpn/ready")
            machine.fail(f"{user_systemctl} start private-vm-qbittorrent.service")
            machine.succeed("! pgrep -u private -x qbittorrent")

            machine.succeed("cp /etc/private-vm/nftables/downloader-vpn-ipv4.nft.in /run/downloader-vpn-ipv4.nft")
            machine.succeed("sed -i -e 's/__PVM_ENDPOINT_IPV4__/192.0.2.1/g' -e 's/__PVM_ENDPOINT_PORT__/51820/g' /run/downloader-vpn-ipv4.nft")
            machine.succeed("nft --check --file /run/downloader-vpn-ipv4.nft")
            machine.succeed("cp /etc/private-vm/nftables/downloader-vpn-ipv6.nft.in /run/downloader-vpn-ipv6.nft")
            machine.succeed("sed -i -e 's/__PVM_ENDPOINT_IPV6__/2001:db8::1/g' -e 's/__PVM_ENDPOINT_PORT__/51820/g' /run/downloader-vpn-ipv6.nft")
            machine.succeed("nft --check --file /run/downloader-vpn-ipv6.nft")
            machine.succeed("umount /mnt/quarantine")
          '';
        };

      exporterTestFor =
        system:
        let
          pkgs = pkgsFor system;
        in
        pkgs.testers.runNixOSTest {
          name = "private-vm-exporter";
          requiredFeatures.kvm = false;
          node.specialArgs = guestArgsFor system "exporter" null;
          nodes.machine = { lib, ... }: {
            imports = [
              ./nix/guests/image-base.nix
              ./nix/guests/exporter.nix
            ];
            users.users.root.hashedPasswordFile = lib.mkForce null;
            virtualisation.memorySize = 1024;
            virtualisation.cores = 2;
            virtualisation.graphics = false;
            # The NixOS VM module otherwise supplies a default SLiRP NIC
            # independently of test VLANs. Disable both sources explicitly.
            virtualisation.vlans = [ ];
            # The exporter image test has only its harness root disk: never add
            # a writable quarantine or scratch device to this role.
            virtualisation.emptyDiskImages = [ ];
            virtualisation.qemu.networkingOptions = lib.mkForce [ "-nic none" ];
            virtualisation.qemu.options = tcgQEMUOptionsFor system ++ [ "-vga none" ];
          };
          testScript = ''
            import json

            machine.wait_for_unit("multi-user.target")
            machine.wait_for_unit("private-vm-guestd.service")
            machine.succeed("systemctl is-active private-vm-guestd.service")
            machine.succeed("readlink /etc/systemd/system/default.target | grep -E '(^|/)multi-user.target$'")

            machine.succeed("grep -Eq '^root:![^:]*:' /etc/shadow")
            machine.succeed("test ! -e /run/current-system/sw/bin/sudo")
            machine.fail("getent passwd private")
            machine.succeed("test -z \"$(awk -F: '$3 >= 1000 && $3 < 65534 && $7 !~ /(nologin|false)$/ { print $1 }' /etc/passwd)\"")

            for command in [
                "X", "Xorg", "Xwayland", "gdm", "gnome-shell", "kwin_wayland",
                "lightdm", "remote-viewer", "sddm", "spice-vdagent", "startx",
                "startxfce4", "thunar", "wayfire", "weston", "xfce4-session",
            ]:
                machine.fail(f"command -v {command}")
            machine.fail("systemctl is-enabled display-manager.service")
            machine.fail("systemctl is-enabled NetworkManager.service")
            machine.fail("systemctl is-enabled udisks2.service")
            machine.succeed("test ! -e /run/current-system/sw/share/xsessions")

            for command in [
                "blkid", "cryptsetup", "e2fsck", "findmnt", "lsblk", "lsusb",
                "mkfs.ext4", "mount", "resize2fs", "sfdisk", "sha256sum",
                "udevadm", "umount", "wipefs",
            ]:
                machine.succeed(f"command -v {command}")
            for command in ["mkfs.exfat", "mkfs.fat", "mkfs.vfat"]:
                machine.fail(f"command -v {command}")
            for command in ["devmon", "udiskie", "udisksctl"]:
                machine.fail(f"command -v {command}")

            tool_inventory = json.loads(machine.succeed("cat /etc/private-vm/exporter-tools.json"))
            assert tool_inventory["schema_version"] == 1, tool_inventory
            expected_tool_packages = [
                "coreutils", "cryptsetup", "e2fsprogs", "systemd", "usbutils",
                "util-linux",
            ]
            assert [package["name"] for package in tool_inventory["packages"]] == expected_tool_packages, tool_inventory
            for package in tool_inventory["packages"]:
                assert package["version"], package
                assert package["store_path"].startswith("/nix/store/"), package
                machine.succeed(f"test -d {package['store_path']}")

            interfaces = machine.succeed("find /sys/class/net -mindepth 1 -maxdepth 1 -printf '%f\\n'").split()
            assert interfaces == ["lo"], f"unexpected exporter interfaces: {interfaces}"
            listeners = machine.succeed("ss -H -lntu")
            assert listeners.strip() == "", f"unexpected TCP/UDP listeners: {listeners}"
            machine.succeed("ss -H -l -A vsock | grep -E '(^|:)4050([[:space:]]|$)'")
            disks = machine.succeed("lsblk -dn -o TYPE,SERIAL | awk '$1 == \"disk\" { print $2 }'").split()
            assert disks == ["root"], f"unexpected exporter disks: {disks}"
            machine.succeed("for block in /sys/class/block/*; do ! udevadm info --query=property --path=$block | grep -q '^ID_BUS=usb$' || exit 1; done")

            expected_capabilities = [
                "guest-events",
                "guest-shutdown",
                "guest-status",
                "usb-finalize",
                "usb-inspect",
                "usb-prepare",
                "usb-verify",
                "usb-write",
            ]
            identity = json.loads(machine.succeed("cat /etc/private-vm/image.json"))
            assert identity["role"] == "exporter", identity
            assert identity["bundle"] is None, identity
            assert identity["capabilities"] == expected_capabilities, identity
            version = json.loads(machine.succeed("private-vm-guestd --version"))
            assert version["guestRole"] == "exporter", version
            assert version["capabilities"] == expected_capabilities, version
          '';
        };

      workstationBundlesCheckFor =
        system:
        let
          pkgs = pkgsFor system;
          modules = {
            basic = ./nix/guests/workstation-basic.nix;
            office = ./nix/guests/workstation-office.nix;
            development = ./nix/guests/workstation-development.nix;
          };
          compareBundle =
            bundle:
            let
              configuration = guest system "workstation" bundle modules.${bundle};
              expected = builtins.toJSON {
                schema_version = workstationBundleCatalog.schema_version;
                project = workstationBundleCatalog.project;
                role = workstationBundleCatalog.role;
                inherit bundle;
                packages = workstationBundleCatalog.bundles.${bundle};
              };
              actual = configuration.config.environment.etc."private-vm/workstation-bundle.json".text;
            in
            "cmp ${pkgs.writeText "workstation-${bundle}-expected.json" expected} ${pkgs.writeText "workstation-${bundle}-actual.json" actual}";
        in
        pkgs.runCommand "private-vm-workstation-bundles" { } ''
          ${nixpkgs.lib.concatMapStringsSep "\n" compareBundle [
            "basic"
            "office"
            "development"
          ]}
          touch "$out"
        '';

      desktopRoleIsolationCheckFor =
        system:
        let
          pkgs = pkgsFor system;
          downloaderPath = (guest system "downloader" null ./nix/guests/downloader.nix).config.system.path;
          scannerPath = (guest system "scanner" null ./nix/guests/scanner.nix).config.system.path;
        in
        pkgs.runCommand "private-vm-desktop-role-isolation" { } ''
          for command in evince file-roller firefox git gvfsd jq keepassxc libreoffice mousepad nm-applet parole pavucontrol qbittorrent ristretto thunar tumblerd udisksctl xfce4-screenshooter xfce4-taskmanager xfce4-terminal; do
            test ! -e "${downloaderPath}/bin/$command"
          done
          test -x "${downloaderPath}/bin/wg"
          test -e "${downloaderPath}/share/applications/private-vm-qbittorrent.desktop"

          for command in evince file-roller firefox gvfsd mousepad nm-applet parole pavucontrol qbittorrent ristretto tumblerd udisksctl xfce4-screenshooter xfce4-taskmanager; do
            test ! -e "${scannerPath}/bin/$command"
          done
          test -x "${scannerPath}/bin/clamscan"
          test -x "${scannerPath}/bin/thunar"
          test -x "${scannerPath}/bin/xfce4-terminal"
          touch "$out"
        '';

      scannerToolchainFor =
        system:
        let
          pkgs = pkgsFor system;
          guestArgs = guestArgsFor system "scanner" null;
        in
        import ./nix/guests/scanner-toolchain.nix {
          inherit pkgs;
          inherit (guestArgs)
            guestArchitecture
            guestFlakeLockSHA256
            guestSBOMCreated
            guestSourceCommit
            ;
          lib = nixpkgs.lib;
        };

      scannerSBOMFor =
        system:
        let
          pkgs = pkgsFor system;
          toolchain = scannerToolchainFor system;
        in
        pkgs.writeTextDir "share/private-vm/sbom/scanner.spdx.json" (builtins.toJSON toolchain.sbom);

      scannerImageContractCheckFor =
        system:
        let
          pkgs = pkgsFor system;
          scannerConfiguration = guest system "scanner" null ./nix/guests/scanner.nix;
          offlineConfiguration = scannerConfiguration.config.specialisation.scan-offline.configuration;
          scannerPath = scannerConfiguration.config.system.path;
          offlinePath = offlineConfiguration.system.path;
          scannerEtc = scannerConfiguration.config.system.build.etc;
          offlineEtc = offlineConfiguration.system.build.etc;
          toolchain = scannerToolchainFor system;
          sbom = scannerSBOMFor system;
          updatePhase = pkgs.writeText "private-vm-scanner-update-phase.json" (
            scannerConfiguration.config.environment.etc."private-vm/scanner-phase.json".text
          );
          offlinePhase = pkgs.writeText "private-vm-scanner-offline-phase.json" (
            offlineConfiguration.environment.etc."private-vm/scanner-phase.json".text
          );
          verifyCommand = command: ''
            test -x "${scannerPath}/bin/${command}" || { echo "scanner update path is missing required command: ${command}" >&2; exit 1; }
            test -x "${offlinePath}/bin/${command}" || { echo "scanner offline path is missing required command: ${command}" >&2; exit 1; }
          '';
          verifyTool =
            tool:
            let
              packageName = tool.package.pname or (nixpkgs.lib.getName tool.package);
              packageVersion = tool.package.version or (nixpkgs.lib.getVersion tool.package);
            in
            ''
              jq -e --arg id "${tool.id}" --arg package "${packageName}" --arg version "${packageVersion}" \
                '.tools | any(.id == $id and .package == $package and .version == $version)' \
                "${scannerEtc}/etc/private-vm/scanner-toolchain.json" >/dev/null || { echo "scanner tool inventory mismatch: ${tool.id}" >&2; exit 1; }
              jq -e --arg id "${tool.spdxID}" --arg package "${packageName}" --arg version "${packageVersion}" \
                '.packages | any(.SPDXID == $id and .name == $package and .versionInfo == $version)' \
                "${sbom}/share/private-vm/sbom/scanner.spdx.json" >/dev/null || { echo "scanner SPDX mismatch: ${tool.id}" >&2; exit 1; }
            '';
          verifyForbiddenCommand = command: ''
            test ! -e "${scannerPath}/bin/${command}" || { echo "scanner update path contains forbidden command: ${command}" >&2; exit 1; }
            test ! -e "${offlinePath}/bin/${command}" || { echo "scanner offline path contains forbidden command: ${command}" >&2; exit 1; }
          '';
        in
        assert scannerConfiguration.config.networking.networkmanager.enable;
        assert scannerConfiguration.config.services.clamav.updater.enable;
        assert builtins.hasAttr "clamav-freshclam" scannerConfiguration.config.systemd.services;
        assert builtins.hasAttr "clamav-freshclam" scannerConfiguration.config.systemd.timers;
        assert !offlineConfiguration.networking.networkmanager.enable;
        assert !offlineConfiguration.networking.dhcpcd.enable;
        assert !offlineConfiguration.services.resolved.enable;
        assert !offlineConfiguration.services.clamav.updater.enable;
        assert !(builtins.hasAttr "clamav-freshclam" offlineConfiguration.systemd.services);
        assert !(builtins.hasAttr "clamav-freshclam" offlineConfiguration.systemd.timers);
        pkgs.runCommand "private-vm-scanner-image-contract" { nativeBuildInputs = [ pkgs.jq ]; } ''
          jq -e '.phase == "definitions-update" and .network_device_policy == "proton-only" and .quarantine_device_policy == "forbidden" and .definitions_update == "enabled"' ${updatePhase} >/dev/null
          jq -e '.phase == "scan-offline" and .network_device_policy == "forbidden" and .quarantine_device_policy == "required-read-only" and .quarantine_mount_options == ["nodev", "noexec", "nosuid", "ro"] and .definitions_update == "disabled"' ${offlinePhase} >/dev/null
          jq -e '.spdxVersion == "SPDX-2.3" and .dataLicense == "CC0-1.0" and (.packages | length) == ${toString (builtins.length toolchain.tools)}' "${sbom}/share/private-vm/sbom/scanner.spdx.json" >/dev/null
          jq -e '.archive_execution_contract == "guestd-bounded-unprivileged-private-namespace"' "${scannerEtc}/etc/private-vm/scanner-toolchain.json" >/dev/null
          cmp "${scannerEtc}/etc/private-vm/scanner-sbom.spdx.json" "${sbom}/share/private-vm/sbom/scanner.spdx.json"
          cmp "${offlineEtc}/etc/private-vm/scanner-sbom.spdx.json" "${sbom}/share/private-vm/sbom/scanner.spdx.json"
          grep -Fx 'MaxFiles 100000' "${scannerEtc}/etc/clamav/clamd.conf"
          grep -Fx 'MaxRecursion 16' "${scannerEtc}/etc/clamav/clamd.conf"
          grep -Fx 'MaxScanSize 4G' "${scannerEtc}/etc/clamav/clamd.conf"
          grep -Fx 'MaxFileSize 4G' "${scannerEtc}/etc/clamav/clamd.conf"
          grep -Fx 'MaxScanTime 300000' "${scannerEtc}/etc/clamav/clamd.conf"
          grep -Fx 'AlertEncrypted true' "${scannerEtc}/etc/clamav/clamd.conf"
          grep -Fx 'DatabaseMirror database.clamav.net' "${scannerEtc}/etc/clamav/freshclam.conf"
          grep -Fx 'ConnectTimeout 10' "${scannerEtc}/etc/clamav/freshclam.conf"
          grep -Fx 'ReceiveTimeout 60' "${scannerEtc}/etc/clamav/freshclam.conf"
          grep -Fx 'MaxAttempts 3' "${scannerEtc}/etc/clamav/freshclam.conf"
          ! grep -Eq '^(DatabaseCustomURL|PrivateMirror) ' "${scannerEtc}/etc/clamav/freshclam.conf"
          ${nixpkgs.lib.concatMapStringsSep "\n" verifyCommand toolchain.requiredCommands}
          ${nixpkgs.lib.concatMapStringsSep "\n" verifyTool toolchain.tools}
          ${nixpkgs.lib.concatMapStringsSep "\n" verifyForbiddenCommand scannerForbiddenCommands}
          touch "$out"
        '';

      scannerUpdateTestFor =
        system:
        let
          pkgs = pkgsFor system;
          freshclamTestDatabase = pkgs.writeText "private-vm-test.hdb" ''
            44d88612fea8a8f36de82e1278abb02f:68:Eicar-Test-Signature
          '';
          freshclamTestConfig = pkgs.writeText "private-vm-freshclam-test.conf" ''
            DatabaseDirectory /var/lib/clamav-test
            DatabaseOwner clamav
            DatabaseCustomURL file:///run/private-vm-freshclam-fixture/private-vm-test.hdb
            ConnectTimeout 10
            ReceiveTimeout 10
            MaxAttempts 1
            Checks 1
          '';
        in
        pkgs.testers.runNixOSTest {
          name = "private-vm-scanner-update";
          requiredFeatures.kvm = false;
          node.specialArgs = guestArgsFor system "scanner" null;
          nodes.machine = { lib, ... }: {
            imports = [
              ./nix/guests/image-base.nix
              ./nix/guests/scanner.nix
            ];
            users.users.root.hashedPasswordFile = lib.mkForce null;
            virtualisation.memorySize = 2048;
            virtualisation.cores = 2;
            virtualisation.vlans = [ 1 ];
            virtualisation.qemu.options = tcgQEMUOptionsFor system;
          };
          testScript = ''
            machine.wait_for_unit("graphical.target")
            machine.wait_for_unit("display-manager.service")
            machine.wait_for_unit("private-vm-guestd.service")
            machine.wait_for_x()
            machine.wait_until_succeeds("loginctl user-status private --no-pager | grep -F xfce4-session")
            machine.succeed("test -x /run/current-system/sw/bin/freshclam")
            machine.succeed("install -d -o clamav -g clamav -m 0750 /var/lib/clamav-test")
            machine.succeed("install -d -m 0755 /run/private-vm-freshclam-fixture && ln -s ${freshclamTestDatabase} /run/private-vm-freshclam-fixture/private-vm-test.hdb")
            machine.succeed("freshclam --config-file=${freshclamTestConfig} --datadir=/var/lib/clamav-test --no-dns --stdout")
            machine.succeed("test -s /var/lib/clamav-test/private-vm-test.hdb")
            machine.succeed("grep -Fx '44d88612fea8a8f36de82e1278abb02f:68:Eicar-Test-Signature' /var/lib/clamav-test/private-vm-test.hdb")
            machine.succeed("systemctl is-enabled clamav-freshclam.timer")
            machine.succeed("systemctl is-active clamav-freshclam.timer")
            machine.succeed("systemctl is-active NetworkManager.service")
            machine.succeed("test $(find /sys/class/net -mindepth 1 -maxdepth 1 ! -name lo | wc -l) -ge 1")
            machine.succeed("jq -e '.phase == \"definitions-update\" and .network_device_policy == \"proton-only\" and .quarantine_device_policy == \"forbidden\"' /etc/private-vm/scanner-phase.json")
            machine.succeed("jq -e '.role == \"scanner\" and (.tools | length) > 0 and ([.tools[].version | length > 0] | all)' /etc/private-vm/scanner-toolchain.json")
            machine.succeed("jq -s -e '.[0].tools as $tools | .[1].packages as $packages | ($packages | length) == ($tools | length) and all($tools[]; . as $tool | any($packages[]; .name == $tool.package and .versionInfo == $tool.version))' /etc/private-vm/scanner-toolchain.json /etc/private-vm/scanner-sbom.spdx.json")
            machine.succeed("private-vm-guestd --version | jq -e '.guestRole == \"scanner\" and .guestApiMajor == 1 and .guestApiMinor == 0 and .capabilities == [\"approved-export\", \"definitions-update\", \"guest-events\", \"guest-shutdown\", \"guest-status\", \"inventory\", \"offline-verification\", \"reconstruct\", \"scan\", \"scan-report\"]'")
            machine.succeed("jq -e '.role == \"scanner\" and .bundle == null and .capabilities == [\"approved-export\", \"definitions-update\", \"guest-events\", \"guest-shutdown\", \"guest-status\", \"inventory\", \"offline-verification\", \"reconstruct\", \"scan\", \"scan-report\"]' /etc/private-vm/image.json")
            machine.succeed("test ! -e /dev/disk/by-label/PVM_QUARANTINE")
            machine.succeed("for command in ${nixpkgs.lib.concatStringsSep " " scannerForbiddenCommands}; do ! command -v $command >/dev/null || exit 1; done")
            machine.succeed("for path in /root/.ssh /home/private/.ssh /root/.config/gh /home/private/.config/gh /root/.config/protonvpn /home/private/.config/protonvpn; do test ! -e $path || exit 1; done")
            machine.succeed("! systemctl is-enabled sshd.service")
            machine.succeed("test ! -e /run/current-system/sw/bin/sudo")
          '';
        };

      scannerOfflineTestFor =
        system:
        let
          pkgs = pkgsFor system;
          quarantineFixture =
            pkgs.runCommand "private-vm-scanner-quarantine.ext4"
              {
                nativeBuildInputs = [ pkgs.e2fsprogs ];
              }
              ''
                truncate -s 64M "$out"
                mkfs.ext4 -q -F -L PVM_QUARANTINE "$out"
              '';
        in
        pkgs.testers.runNixOSTest {
          name = "private-vm-scanner-offline";
          requiredFeatures.kvm = false;
          node.specialArgs = guestArgsFor system "scanner" null;
          nodes.machine = { lib, ... }: {
            imports = [
              ./nix/guests/image-base.nix
              ./nix/guests/scanner.nix
              ./nix/guests/scanner-offline.nix
            ];
            users.users.root.hashedPasswordFile = lib.mkForce null;
            virtualisation.memorySize = 2048;
            virtualisation.cores = 2;
            virtualisation.vlans = [ ];
            virtualisation.qemu.options = tcgQEMUOptionsFor system ++ [
              "-nic"
              "none"
              "-drive"
              "file=${quarantineFixture},if=none,format=raw,readonly=on,id=quarantine"
              "-device"
              "virtio-blk-pci,drive=quarantine"
            ];
          };
          testScript = ''
            machine.wait_for_unit("graphical.target")
            machine.wait_for_unit("display-manager.service")
            machine.wait_for_unit("private-vm-guestd.service")
            machine.wait_for_x()
            machine.wait_until_succeeds("loginctl user-status private --no-pager | grep -F xfce4-session")
            machine.succeed("test $(find /sys/class/net -mindepth 1 -maxdepth 1 ! -name lo | wc -l) -eq 0")
            machine.succeed("! systemctl is-active NetworkManager.service")
            machine.succeed("! systemctl list-unit-files --no-legend clamav-freshclam.service | grep -F clamav-freshclam.service")
            machine.succeed("! systemctl list-unit-files --no-legend clamav-freshclam.timer | grep -F clamav-freshclam.timer")
            machine.succeed("jq -e '.phase == \"scan-offline\" and .network_device_policy == \"forbidden\" and .quarantine_device_policy == \"required-read-only\" and .quarantine_mount_options == [\"nodev\", \"noexec\", \"nosuid\", \"ro\"] and .definitions_update == \"disabled\"' /etc/private-vm/scanner-phase.json")
            machine.succeed("test -x /run/current-system/sw/bin/startxfce4")
            machine.succeed("test -x /run/current-system/sw/bin/clamscan")
            machine.succeed("test -x /run/current-system/sw/bin/bsdtar")
            machine.succeed("test -x /run/current-system/sw/bin/libreoffice")
            machine.succeed("test -x /run/current-system/sw/bin/ffmpeg")
            machine.succeed("private-vm-guestd --version | jq -e '.guestRole == \"scanner\" and .guestApiMajor == 1 and .guestApiMinor == 0 and .capabilities == [\"approved-export\", \"definitions-update\", \"guest-events\", \"guest-shutdown\", \"guest-status\", \"inventory\", \"offline-verification\", \"reconstruct\", \"scan\", \"scan-report\"]'")
            machine.succeed("test $(blockdev --getro /dev/disk/by-label/PVM_QUARANTINE) -eq 1")
            machine.succeed("install -d -m 0700 /mnt/quarantine && mount -t ext4 -o ro,nodev,nosuid,noexec /dev/disk/by-label/PVM_QUARANTINE /mnt/quarantine")
            machine.succeed("for option in ro nodev nosuid noexec; do findmnt -n -o OPTIONS -T /mnt/quarantine | tr ',' '\\n' | grep -Fx $option || exit 1; done")
            machine.fail("touch /mnt/quarantine/write-must-fail")
            machine.succeed("umount /mnt/quarantine")
            machine.succeed("for command in ${nixpkgs.lib.concatStringsSep " " scannerForbiddenCommands}; do ! command -v $command >/dev/null || exit 1; done")
            machine.succeed("for path in /root/.ssh /home/private/.ssh /root/.config/gh /home/private/.config/gh /root/.config/protonvpn /home/private/.config/protonvpn; do test ! -e $path || exit 1; done")
            machine.succeed("! systemctl is-enabled sshd.service")
            machine.succeed("test ! -e /run/current-system/sw/bin/sudo")
            listeners = machine.succeed("ss -H -lntu")
            assert listeners.strip() == "", f"unexpected TCP/UDP listeners: {listeners}"
          '';
        };

      staticBinariesCheckFor =
        system:
        let
          pkgs = pkgsFor system;
          hostPackage = privateVMFor system;
          modulePackage =
            (nixpkgs.lib.nixosSystem {
              inherit system;
              modules = [
                ./nix/modules/host.nix
                { system.stateVersion = "26.05"; }
              ];
            }).config.services.private-vm.package;
          rolePackages = map (guestdFor system) [
            "workstation"
            "downloader"
            "scanner"
            "exporter"
          ];
          binaries = [
            "${hostPackage}/bin/private-vm"
            "${hostPackage}/bin/private-vmd"
            "${hostPackage}/bin/private-vm-guestd"
            "${modulePackage}/bin/private-vm"
            "${modulePackage}/bin/private-vmd"
            "${modulePackage}/bin/private-vm-guestd"
          ]
          ++ map (package: "${package}/bin/private-vm-guestd") rolePackages;
          verifyBinary = binary: ''
            test -x "${binary}"
            ${pkgs.go}/bin/go version -m "${binary}" | grep -F 'CGO_ENABLED=0'
            if ${pkgs.binutils}/bin/readelf -l "${binary}" | grep -q 'Requesting program interpreter'; then
              echo "dynamic ELF interpreter found: ${binary}" >&2
              exit 1
            fi
            if ${pkgs.binutils}/bin/readelf -d "${binary}" 2>/dev/null | grep -q '(NEEDED)'; then
              echo "dynamic dependency found: ${binary}" >&2
              exit 1
            fi
          '';
        in
        pkgs.runCommand "private-vm-static-binaries" { } ''
          ${nixpkgs.lib.concatMapStringsSep "\n" verifyBinary binaries}
          touch "$out"
        '';

      hostModuleContractCheckFor =
        system:
        let
          pkgs = pkgsFor system;
          customApplication = pkgs.writeShellScriptBin "private-vmd" "exit 1";
          host = nixpkgs.lib.nixosSystem {
            inherit system;
            modules = [
              ./nix/modules/host.nix
              {
                services.private-vm = {
                  enable = true;
                  group = "pvm-custom";
                  package = customApplication;
                };
                system.stateVersion = "26.05";
              }
            ];
          };
          service = host.config.systemd.services.private-vmd;
          policies = builtins.filter (
            package: nixpkgs.lib.hasPrefix "private-vm-polkit-policy" package.name
          ) host.config.environment.systemPackages;
          requiredPath = with pkgs; [
            host.config.security.polkit.package.bin
            qemu
            cryptsetup
            nftables
            iproute2
            e2fsprogs
            usbguard
            virt-viewer
            util-linux
          ];
          policySource = builtins.readFile ./packaging/polkit/org.private-vm.policy;
        in
        assert host.config.users.groups ? pvm-custom;
        assert service.serviceConfig.Group == "pvm-custom";
        assert nixpkgs.lib.hasInfix "--group pvm-custom" service.serviceConfig.ExecStart;
        assert service.serviceConfig.RuntimeDirectoryMode == "0750";
        assert service.serviceConfig.StateDirectoryMode == "0700";
        assert builtins.length policies == 1;
        assert nixpkgs.lib.all (package: nixpkgs.lib.elem package service.path) requiredPath;
        assert builtins.length (nixpkgs.lib.splitString "<action id=" policySource) == 2;
        assert nixpkgs.lib.hasInfix "<action id=\"org.private-vm.usb.prepare\">" policySource;
        assert !nixpkgs.lib.hasInfix "org.private-vm.session.manage" policySource;
        pkgs.writeText "private-vm-host-module-contract" (
          builtins.toJSON {
            group = service.serviceConfig.Group;
            exec_start = service.serviceConfig.ExecStart;
            runtime_mode = service.serviceConfig.RuntimeDirectoryMode;
            state_mode = service.serviceConfig.StateDirectoryMode;
            daemon_path = map (package: package.name) service.path;
            policy_sha256 = builtins.hashString "sha256" policySource;
          }
        );
    in
    {
      packages = forAllSystems (
        system:
        let
          workstationBasic = guest system "workstation" "basic" ./nix/guests/workstation-basic.nix;
          workstationOffice = guest system "workstation" "office" ./nix/guests/workstation-office.nix;
          workstationDevelopment =
            guest system "workstation" "development"
              ./nix/guests/workstation-development.nix;
          downloader = guest system "downloader" null ./nix/guests/downloader.nix;
          scanner = guest system "scanner" null ./nix/guests/scanner.nix;
          exporter = guest system "exporter" null ./nix/guests/exporter.nix;
          binaryPackages = {
            default = privateVMFor system;
            private-vm = privateVMFor system;
            private-vmd = privateVMFor system;
            private-vm-guestd = privateVMFor system;
            guestd-workstation = guestdFor system "workstation";
            guestd-downloader = guestdFor system "downloader";
            guestd-scanner = guestdFor system "scanner";
            guestd-exporter = guestdFor system "exporter";
          };
          imagePackages = nixpkgs.lib.optionalAttrs (system == "x86_64-linux") {
            image-workstation-basic = workstationBasic.config.system.build.images.qemu-efi;
            image-workstation-office = workstationOffice.config.system.build.images.qemu-efi;
            image-workstation-development = workstationDevelopment.config.system.build.images.qemu-efi;
            image-downloader = downloader.config.system.build.images.qemu-efi;
            image-scanner = scanner.config.system.build.images.qemu-efi;
            sbom-scanner = scannerSBOMFor system;
            image-exporter = exporter.config.system.build.images.qemu-efi;
          };
        in
        binaryPackages // imagePackages
      );

      apps = forAllSystems (system: {
        default = {
          type = "app";
          program = "${self.packages.${system}.private-vm}/bin/private-vm";
        };
        private-vm = {
          type = "app";
          program = "${self.packages.${system}.private-vm}/bin/private-vm";
        };
      });

      devShells = forAllSystems (
        system:
        let
          pkgs = pkgsFor system;
        in
        {
          default = pkgs.mkShell {
            packages = with pkgs; [
              go
              gotools
              gopls
              govulncheck
              go-tools
              golangci-lint
              gitleaks
              actionlint
              zizmor
              buf
              protobuf
              protoc-gen-go
              protoc-gen-go-grpc
              qemu
              cryptsetup
              e2fsprogs
              util-linux
              nftables
              iproute2
              usbguard
              virt-viewer
              oras
              syft
              cosign
              zstd
              jq
              (python3.withPackages (ps: [
                ps.jsonschema
                ps.pyyaml
              ]))
            ];
          };
        }
      );

      checks = forAllSystems (
        system:
        let
          pkgs = pkgsFor system;
          python = pkgs.python3.withPackages (ps: [
            ps.jsonschema
            ps.pyyaml
          ]);
          sourceCheck =
            name: commands:
            pkgs.runCommand name
              {
                nativeBuildInputs = [
                  pkgs.go
                  pkgs.stdenv.cc
                  python
                ];
              }
              ''
                export HOME="$TMPDIR/private-vm-home"
                mkdir -p "$HOME"
                cp -R ${self} source
                chmod -R u+w source
                cd source
                ${commands}
                touch "$out"
              '';
          baseChecks = {
            default = sourceCheck "private-vm-source-check" ''
              go test ./...
              go vet ./...
              GOOS=darwin GOARCH=amd64 go test -exec=true ./internal/secret
              python3 tools/validate_schemas.py
              python3 tools/validate_examples.py
            '';
            go-race = sourceCheck "private-vm-go-race" ''
              go test -race ./...
            '';
            daemon-rpc-fuzz = sourceCheck "private-vm-daemon-rpc-fuzz" ''
              go test ./internal/daemon -run='^$' -fuzz='^FuzzDaemonRPCInputs$' -fuzztime=2s -parallel=1
            '';
            host-module-contract = hostModuleContractCheckFor system;
            static-binaries = staticBinariesCheckFor system;
            workflow-policy = sourceCheck "private-vm-workflow-policy" ''
              export PATH="${pkgs.actionlint}/bin:${pkgs.zizmor}/bin:$PATH"
              python3 tools/test_workflow_policy.py
              python3 tools/check_workflow_policy.py
            '';
          };
        in
        baseChecks
        // nixpkgs.lib.optionalAttrs (system == "x86_64-linux") {
          desktop-role-isolation = desktopRoleIsolationCheckFor system;
          downloader-desktop = downloaderDesktopTestFor system;
          exporter = exporterTestFor system;
          guest-common = commonGuestTestFor system;
          scanner-image-contract = scannerImageContractCheckFor system;
          scanner-update = scannerUpdateTestFor system;
          scanner-offline = scannerOfflineTestFor system;
          workstation-bundles = workstationBundlesCheckFor system;
          workstation-desktop = workstationDesktopTestFor system;
        }
      );

      nixosModules.default = import ./nix/modules/host.nix;
    };
}
