{
  description = "private-vm: disposable graphical private-workstation orchestrator";

  inputs = {
    # Release branches are intentionally pinned by flake.lock. NIX-001 must
    # generate and commit the lock file against NixOS 26.05 before first build.
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";
  };

  outputs = { self, nixpkgs }:
    let
      supportedSystems = [ "x86_64-linux" "aarch64-linux" ];
      forAllSystems = nixpkgs.lib.genAttrs supportedSystems;
      pkgsFor = system: import nixpkgs { inherit system; };

      privateVMFor = system:
        let pkgs = pkgsFor system;
        in pkgs.buildGoModule {
          pname = "private-vm";
          version = "0.0.0-dev";
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
            "-X github.com/StevenBuglione/private-vm/internal/buildinfo.Version=0.0.0-dev"
          ];
        };

      guest = system: module:
        nixpkgs.lib.nixosSystem {
          inherit system;
          specialArgs = {
            privateVMPackage = privateVMFor system;
          };
          modules = [
            ./nix/guests/image-base.nix
            module
          ];
        };
    in {
      packages = forAllSystems (system:
        let
          pkgs = pkgsFor system;
          workstationBasic = guest system ./nix/guests/workstation-basic.nix;
          workstationOffice = guest system ./nix/guests/workstation-office.nix;
          workstationDevelopment = guest system ./nix/guests/workstation-development.nix;
          downloader = guest system ./nix/guests/downloader.nix;
          scanner = guest system ./nix/guests/scanner.nix;
          exporter = guest system ./nix/guests/exporter.nix;
          binaryPackages = {
          default = privateVMFor system;
          private-vm = privateVMFor system;
          private-vmd = privateVMFor system;
          private-vm-guestd = privateVMFor system;
          };
          imagePackages = nixpkgs.lib.optionalAttrs (system == "x86_64-linux") {
            image-workstation-basic = workstationBasic.config.system.build.images.qemu-efi;
            image-workstation-office = workstationOffice.config.system.build.images.qemu-efi;
            image-workstation-development = workstationDevelopment.config.system.build.images.qemu-efi;
            image-downloader = downloader.config.system.build.images.qemu-efi;
            image-scanner = scanner.config.system.build.images.qemu-efi;
            image-exporter = exporter.config.system.build.images.qemu-efi;
          };
        in binaryPackages // imagePackages);

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

      devShells = forAllSystems (system:
        let pkgs = pkgsFor system;
        in {
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
        });

      checks = forAllSystems (system:
        let
          pkgs = pkgsFor system;
          python = pkgs.python3.withPackages (ps: [ ps.jsonschema ]);
          sourceCheck = name: commands: pkgs.runCommand name {
            nativeBuildInputs = [ pkgs.go pkgs.stdenv.cc python ];
          } ''
            export HOME="$TMPDIR/private-vm-home"
            mkdir -p "$HOME"
            cp -R ${self} source
            chmod -R u+w source
            cd source
            ${commands}
            touch "$out"
          '';
        in {
          default = sourceCheck "private-vm-source-check" ''
            go test ./...
            go vet ./...
            python3 tools/validate_schemas.py
            python3 tools/validate_examples.py
          '';
          go-race = sourceCheck "private-vm-go-race" ''
            go test -race ./...
          '';
        });

      nixosModules.default = import ./nix/modules/host.nix;
    };
}
