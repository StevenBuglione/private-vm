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
          for command in firefox file-roller gvfsd libreoffice mousepad nm-applet parole pavucontrol ristretto thunar tumblerd udisksctl xfce4-screenshooter xfce4-taskmanager xfce4-terminal; do
            test ! -e "${downloaderPath}/bin/$command"
          done
          test -x "${downloaderPath}/bin/qbittorrent"
          test -x "${downloaderPath}/bin/wg"

          for command in evince file-roller firefox gvfsd mousepad nm-applet parole pavucontrol qbittorrent ristretto tumblerd udisksctl xfce4-screenshooter xfce4-taskmanager; do
            test ! -e "${scannerPath}/bin/$command"
          done
          test -x "${scannerPath}/bin/clamscan"
          test -x "${scannerPath}/bin/thunar"
          test -x "${scannerPath}/bin/xfce4-terminal"
          touch "$out"
        '';

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
              (python3.withPackages (ps: [ ps.jsonschema ]))
            ];
          };
        }
      );

      checks = forAllSystems (
        system:
        let
          pkgs = pkgsFor system;
          python = pkgs.python3.withPackages (ps: [ ps.jsonschema ]);
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
              python3 tools/validate_schemas.py
              python3 tools/validate_examples.py
            '';
            go-race = sourceCheck "private-vm-go-race" ''
              go test -race ./...
            '';
            static-binaries = staticBinariesCheckFor system;
          };
        in
        baseChecks
        // nixpkgs.lib.optionalAttrs (system == "x86_64-linux") {
          desktop-role-isolation = desktopRoleIsolationCheckFor system;
          guest-common = commonGuestTestFor system;
          workstation-bundles = workstationBundlesCheckFor system;
          workstation-desktop = workstationDesktopTestFor system;
        }
      );

      nixosModules.default = import ./nix/modules/host.nix;
    };
}
