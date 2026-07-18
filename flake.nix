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
        in {
          default = privateVMFor system;
          private-vm = privateVMFor system;

          # NIX-001 must confirm the exact 26.05 image output name. The design
          # target is config.system.build.images.qcow. Keeping this expression
          # here makes the expected contract explicit for the coding agent.
          workstation-basic-image = workstationBasic.config.system.build.images.qcow;
          workstation-office-image = workstationOffice.config.system.build.images.qcow;
          workstation-development-image = workstationDevelopment.config.system.build.images.qcow;
          downloader-image = downloader.config.system.build.images.qcow;
          scanner-image = scanner.config.system.build.images.qcow;
          exporter-image = exporter.config.system.build.images.qcow;
        });

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
              buf
              protobuf
              protoc-gen-go
              protoc-gen-go-grpc
              qemu
              cryptsetup
              nftables
              iproute2
              usbguard
              virt-viewer
              oras
              syft
              cosign
              zstd
              jq
            ];
          };
        });

      checks = forAllSystems (system: {
        go-test = (pkgsFor system).runCommand "private-vm-go-test" {
          nativeBuildInputs = [ (pkgsFor system).go ];
        } ''
          export HOME="$TMPDIR/home"
          mkdir -p "$HOME"
          cp -R ${self} source
          chmod -R u+w source
          cd source
          go test ./...
          touch "$out"
        '';
      });

      nixosModules.default = import ./nix/modules/host.nix;
    };
}
