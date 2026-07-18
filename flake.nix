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
        pkgs.buildGoModule {
          pname = "private-vm";
          version = projectVersion;
          src = self;
          vendorHash = null;
          subPackages = [
            "cmd/private-vm"
            "cmd/private-vmd"
            "cmd/private-vm-guestd"
          ];
          ldflags = [
            "-s"
            "-w"
            "-X github.com/StevenBuglione/private-vm/internal/buildinfo.Version=${projectVersion}"
            "-X github.com/StevenBuglione/private-vm/internal/buildinfo.Commit=${sourceCommit}"
            "-X github.com/StevenBuglione/private-vm/internal/buildinfo.Dirty=${sourceDirty}"
          ];
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

      commonGuestTestFor =
        system:
        let
          pkgs = pkgsFor system;
          testToken = pkgs.writeText "private-vm-test-capability" "0123456789abcdef0123456789abcdef";
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
            virtualisation.qemu.options = [
              "-machine"
              "accel=tcg"
              "-fw_cfg"
              "name=opt/private-vm/session-capability,file=${testToken}"
            ];
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
          };
        in
        baseChecks
        // nixpkgs.lib.optionalAttrs (system == "x86_64-linux") {
          guest-common = commonGuestTestFor system;
        }
      );

      nixosModules.default = import ./nix/modules/host.nix;
    };
}
