{
  config,
  lib,
  pkgs,
  ...
}:

let
  cfg = config.services.private-vm;
  polkitPolicy = pkgs.runCommand "private-vm-polkit-policy" { } ''
    install -Dm0444 \
      ${../../packaging/polkit/org.private-vm.policy} \
      "$out/share/polkit-1/actions/org.private-vm.policy"
    test "$(grep -Fc '<action id=' "$out/share/polkit-1/actions/org.private-vm.policy")" -eq 1
    grep -Fq '<action id="org.private-vm.usb.prepare">' \
      "$out/share/polkit-1/actions/org.private-vm.policy"
    ! grep -Fq 'org.private-vm.session.manage' \
      "$out/share/polkit-1/actions/org.private-vm.policy"
  '';
  installedApplication = lib.lowPrio cfg.package;
  installedPolkitPolicy = lib.hiPrio polkitPolicy;
  daemonPath = with pkgs; [
    config.security.polkit.package.bin
    qemu
    cryptsetup
    nftables
    iproute2
    e2fsprogs
    usbguard
    virt-viewer
    util-linux
  ];
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

    scratchBackupExcluded = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = ''
        Operator assertion that /var/lib/private-vm/scratch is excluded from
        host backup, indexing, and snapshot automation. Enabling this writes
        only private-vm's validation marker; it does not configure or claim
        support from third-party backup tools.
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    users.groups.${cfg.group} = { };

    environment.systemPackages = with pkgs; [
      installedApplication
      installedPolkitPolicy
      qemu
      cryptsetup
      nftables
      iproute2
      e2fsprogs
      usbguard
      virt-viewer
      util-linux
    ];

    boot.kernelModules = [
      "kvm"
      "vhost_vsock"
      "tun"
    ];
    services.usbguard.enable = true;
    services.usbguard.implicitPolicyTarget = "block";
    security.polkit.enable = true;

    systemd.tmpfiles.rules = [
      "d /var/lib/private-vm 0700 root root -"
      "d /var/lib/private-vm/images 0755 root root -"
      "d /var/lib/private-vm/scratch 0700 root root -"
      "d /var/lib/private-vm/enrollments 0700 root root -"
      "d /run/private-vm 0750 root ${cfg.group} -"
    ]
    ++ lib.optional cfg.scratchBackupExcluded "f /var/lib/private-vm/scratch/.private-vm-no-backup 0600 root root - private-vm-ephemeral-scratch-v1";

    systemd.services.private-vmd = {
      description = "private-vm privileged orchestration daemon";
      wantedBy = [ "multi-user.target" ];
      after = [
        "local-fs.target"
        "polkit.service"
      ];
      path = daemonPath;
      serviceConfig = {
        Type = "simple";
        ExecStart = "${cfg.package}/bin/private-vmd --config /etc/private-vm/config.toml --group ${lib.escapeShellArg cfg.group}";
        Restart = "on-failure";
        RestartSec = "2s";
        User = "root";
        Group = cfg.group;
        UMask = "0007";
        RuntimeDirectory = "private-vm";
        RuntimeDirectoryMode = "0750";
        StateDirectory = "private-vm";
        StateDirectoryMode = "0700";
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

    assertions = [
      {
        assertion = config.security.polkit.enable;
        message = "services.private-vm requires Polkit for destructive USB authorization";
      }
      {
        assertion = lib.all (package: lib.elem package config.systemd.services.private-vmd.path) daemonPath;
        message = "private-vmd must retain its complete pinned probe and runtime PATH";
      }
      {
        assertion = config.systemd.services.private-vmd.serviceConfig.RuntimeDirectoryMode == "0750";
        message = "private-vmd RuntimeDirectoryMode must remain 0750";
      }
      {
        assertion = config.systemd.services.private-vmd.serviceConfig.StateDirectoryMode == "0700";
        message = "private-vmd StateDirectoryMode must remain 0700";
      }
      {
        assertion = lib.elem installedPolkitPolicy config.environment.systemPackages;
        message = "the independently packaged private-vm Polkit action must be in the system profile";
      }
      {
        assertion = lib.elem "/share/polkit-1" config.environment.pathsToLink;
        message = "the system profile must link private-vm's packaged Polkit action";
      }
    ];

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
