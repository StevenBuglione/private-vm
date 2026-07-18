{ config, lib, pkgs, modulesPath, privateVMPackage, ... }:

{
  imports = [
    "${modulesPath}/profiles/qemu-guest.nix"
  ];

  system.stateVersion = "26.05";

  # NixOS 26.05 exposes disk images as variants under system.build.images.
  # qemu-efi supplies GPT/UEFI and the official disk-image builder.
  image.modules.qemu-efi = {
    image.format = "qcow2";
    image.baseName = "private-vm-${config.networking.hostName}";
  };
  boot.initrd.availableKernelModules = [ "virtio_pci" "virtio_blk" "virtio_scsi" "vsock" ];
  boot.kernelModules = [ "vmw_vsock_virtio_transport" ];

  networking.useDHCP = false;
  networking.firewall.enable = true;

  services.openssh.enable = false;
  security.sudo.enable = false;

  users.mutableUsers = false;
  users.allowNoPasswordLogin = true;
  users.users.root.hashedPassword = "!";

  services.journald.extraConfig = ''
    Storage=volatile
    RuntimeMaxUse=64M
    ForwardToSyslog=no
  '';

  boot.tmp.cleanOnBoot = true;
  fileSystems."/tmp" = {
    device = "tmpfs";
    fsType = "tmpfs";
    options = [ "mode=1777" "nosuid" "nodev" ];
  };

  environment.systemPackages = [
    privateVMPackage
    pkgs.cacert
    pkgs.coreutils
    pkgs.iproute2
    pkgs.nftables
    pkgs.util-linux
  ];

  systemd.services.private-vm-guestd = {
    description = "private-vm guest control daemon";
    wantedBy = [ "multi-user.target" ];
    serviceConfig = {
      ExecStart = "${privateVMPackage}/bin/private-vm-guestd --role ${config.networking.hostName}";
      Restart = "on-failure";
      RestartSec = "1s";
      NoNewPrivileges = true;
      PrivateTmp = true;
      ProtectHome = false;
      ProtectSystem = "strict";
      LimitCORE = 0;
    };
  };

  # No unattended persistence mechanisms.
  services.fstrim.enable = false;
  nix.gc.automatic = false;
}
