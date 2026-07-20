{
  config,
  lib,
  pkgs,
  ...
}:

let
  cfg = config.services.private-vm;
  hostIntegration = pkgs.runCommand "private-vm-host-integration" { } ''
    install -Dm0444 \
      ${../../packaging/polkit/org.private-vm.policy} \
      "$out/share/polkit-1/actions/org.private-vm.policy"
    install -Dm0444 \
      ${../../packaging/udev/90-private-vm.rules} \
      "$out/lib/udev/rules.d/90-private-vm.rules"
    install -Dm0444 \
      ${../../packaging/usbguard/private-vm.conf.example} \
      "$out/share/private-vm/usbguard/private-vm.conf.example"
    test "$(grep -Fc '<action id=' "$out/share/polkit-1/actions/org.private-vm.policy")" -eq 1
    grep -Fq '<action id="org.private-vm.usb.prepare">' \
      "$out/share/polkit-1/actions/org.private-vm.policy"
    ! grep -Fq 'org.private-vm.session.manage' \
      "$out/share/polkit-1/actions/org.private-vm.policy"
  '';
  installedApplication = lib.lowPrio cfg.package;
  installedHostIntegration = lib.hiPrio hostIntegration;
  daemonPath = with pkgs; [
    config.security.polkit.package.bin
    systemd
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

    authorizedUsers = lib.mkOption {
      type = lib.types.listOf (lib.types.strMatching "[a-z_][a-z0-9_-]{0,30}");
      default = [ ];
      example = [ "alice" ];
      description = ''
        Existing local users to add to the private-vm authorization group.
        Group changes take effect for a user only after a new login session.
      '';
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
    users.users = lib.genAttrs cfg.authorizedUsers (_: {
      extraGroups = [ cfg.group ];
    });

    environment.systemPackages = with pkgs; [
      installedApplication
      installedHostIntegration
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
    # Linux requires the outer namespace's global IPv6 forwarding switch for
    # routed traffic even when the daemon enables forwarding on its owned
    # veth. IPv4 remains per-interface and the global IPv4 switch stays off.
    boot.kernel.sysctl."net.ipv6.conf.all.forwarding" = lib.mkDefault 1;
    services.usbguard.enable = true;
    services.usbguard.implicitPolicyTarget = "block";
    # First activation must not disconnect a present USB keyboard or recovery
    # device merely because the existing host policy file is empty. Preserve
    # present authorization state, block every newly inserted device, and
    # restore controller state when the service stops. Operators with a
    # reviewed complete rule set may override presentDevicePolicy to
    # "apply-policy" in their host configuration.
    services.usbguard.presentDevicePolicy = lib.mkDefault "keep";
    services.usbguard.insertedDevicePolicy = lib.mkDefault "block";
    services.usbguard.restoreControllerDeviceState = lib.mkDefault true;
    services.udev.packages = [ installedHostIntegration ];
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
        assertion = config.boot.kernel.sysctl."net.ipv6.conf.all.forwarding" == 1;
        message = "services.private-vm requires net.ipv6.conf.all.forwarding=1 for exact dual-stack VPN endpoint routing";
      }
      {
        assertion = config.services.usbguard.enable;
        message = "services.private-vm requires USBGuard to remain enabled";
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
        assertion = lib.elem installedHostIntegration config.environment.systemPackages;
        message = "the independently packaged private-vm host integration must be in the system profile";
      }
      {
        assertion = lib.elem "/share/polkit-1" config.environment.pathsToLink;
        message = "the system profile must link private-vm's packaged Polkit action";
      }
      {
        assertion = builtins.length cfg.authorizedUsers == builtins.length (lib.unique cfg.authorizedUsers);
        message = "services.private-vm.authorizedUsers must not contain duplicates";
      }
      {
        assertion = lib.all (
          name:
          let
            account = config.users.users.${name};
          in
          account.isNormalUser || account.isSystemUser
        ) cfg.authorizedUsers;
        message = "every services.private-vm.authorizedUsers entry must name an explicitly configured user";
      }
    ];

    environment.etc."private-vm/config.toml" = {
      mode = "0600";
      text = ''
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
  };
}
