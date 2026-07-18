{
  config,
  lib,
  pkgs,
  ...
}:

let
  cfg = config.services.private-vm;
in
{
  options.services.private-vm = {
    enable = lib.mkEnableOption "private-vm privileged orchestration daemon";

    package = lib.mkOption {
      type = lib.types.package;
      default = import ../package.nix {
        inherit pkgs;
        src = ../..;
      };
      description = "Package containing private-vm, private-vmd, and guestd.";
    };

    group = lib.mkOption {
      type = lib.types.str;
      default = "private-vm";
    };

    strict = lib.mkOption {
      type = lib.types.bool;
      default = true;
    };

    imageRepository = lib.mkOption {
      type = lib.types.str;
      default = "StevenBuglione/private-vm";
    };
  };

  config = lib.mkIf cfg.enable {
    users.groups.${cfg.group} = { };

    environment.systemPackages = with pkgs; [
      cfg.package
      qemu
      cryptsetup
      nftables
      iproute2
      usbguard
      virt-viewer
    ];

    boot.kernelModules = [
      "kvm"
      "vhost_vsock"
      "tun"
    ];
    services.usbguard.enable = true;
    services.usbguard.implicitPolicyTarget = "block";

    systemd.tmpfiles.rules = [
      "d /var/lib/private-vm 0700 root root -"
      "d /var/lib/private-vm/images 0755 root root -"
      "d /var/lib/private-vm/scratch 0700 root root -"
      "d /run/private-vm 0750 root ${cfg.group} -"
    ];

    systemd.services.private-vmd = {
      description = "private-vm privileged orchestration daemon";
      wantedBy = [ "multi-user.target" ];
      after = [ "local-fs.target" ];
      serviceConfig = {
        Type = "simple";
        ExecStart = "${cfg.package}/bin/private-vmd --config /etc/private-vm/config.toml";
        Restart = "on-failure";
        RestartSec = "2s";
        User = "root";
        Group = cfg.group;
        UMask = "0007";
        RuntimeDirectory = "private-vm";
        StateDirectory = "private-vm";
        NoNewPrivileges = true;
        PrivateTmp = true;
        ProtectHome = true;
        ProtectSystem = "strict";
        ReadWritePaths = [
          "/run/private-vm"
          "/var/lib/private-vm"
          "/dev"
          "/sys/fs/cgroup"
        ];
        Delegate = true;
        CapabilityBoundingSet = [
          "CAP_NET_ADMIN"
          "CAP_SYS_ADMIN"
          "CAP_SYS_RAWIO"
          "CAP_DAC_OVERRIDE"
          "CAP_CHOWN"
          "CAP_MKNOD"
          "CAP_IPC_LOCK"
        ];
        LimitCORE = 0;
        LimitMEMLOCK = "infinity";
      };
    };

    environment.etc."private-vm/config.toml".text = ''
      schema_version = 1
      strict = ${if cfg.strict then "true" else "false"}

      [image_source]
      registry = "ghcr.io"
      repository = "${cfg.imageRepository}"
      channel = "stable"
      require_attestation = true

      [logging]
      persistent_lifecycle_metadata = false
      telemetry = false
    '';
  };
}
