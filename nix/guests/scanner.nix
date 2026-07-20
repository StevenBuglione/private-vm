{
  config,
  guestArchitecture,
  guestFlakeLockSHA256,
  guestSBOMCreated,
  guestSourceCommit,
  lib,
  pkgs,
  ...
}:

let
  toolchain = import ./scanner-toolchain.nix {
    inherit
      guestArchitecture
      guestFlakeLockSHA256
      guestSBOMCreated
      guestSourceCommit
      lib
      pkgs
      ;
  };
  freshclamConfig = pkgs.writeText "private-vm-freshclam.conf" ''
    DatabaseDirectory /var/lib/clamav
    DatabaseOwner clamav
    DNSDatabaseInfo current.cvd.clamav.net
    DatabaseMirror database.clamav.net
    ConnectTimeout 10
    ReceiveTimeout 60
    MaxAttempts 3
    Checks 1
    TestDatabases yes
    ScriptedUpdates yes
  '';
in
{
  imports = [ ./desktop-common.nix ];
  networking.hostName = "scanner";

  environment.systemPackages = [
    pkgs.wireguard-tools
    pkgs.xfce4-terminal
  ]
  ++ toolchain.packages;

  users.groups.private-vm-scanner = { };
  users.users.private-vm-scanner = {
    isSystemUser = true;
    group = "private-vm-scanner";
    extraGroups = [ "clamav" ];
  };

  environment.etc."private-vm/policy.safe.toml" = {
    mode = "0444";
    source = ../../examples/policy.safe.toml;
  };

  # Only the definitions-update boot grants guestd the socket families and
  # capability needed by the typed WireGuard/nftables controller.
  systemd.services.private-vm-guestd.serviceConfig.RestrictAddressFamilies = lib.mkForce [
    "AF_UNIX"
    "AF_VSOCK"
    "AF_INET"
    "AF_INET6"
    "AF_NETLINK"
  ];
  systemd.services.private-vm-guestd.serviceConfig.CapabilityBoundingSet = lib.mkForce [
    "CAP_IPC_LOCK"
    "CAP_NET_ADMIN"
  ];
  systemd.services.private-vm-guestd.serviceConfig.AmbientCapabilities = [
    "CAP_IPC_LOCK"
    "CAP_NET_ADMIN"
  ];
  systemd.services.private-vm-guestd.serviceConfig.User = lib.mkForce "private-vm-scanner";
  systemd.services.private-vm-guestd.serviceConfig.Group = lib.mkForce "private-vm-scanner";
  systemd.services.private-vm-guestd.serviceConfig.StateDirectory = "private-vm/scanner";
  systemd.services.private-vm-guestd.serviceConfig.StateDirectoryMode = "0700";
  # systemd creates this tmpfs inside guestd's private mount namespace before
  # running the fixed privileged preparation command. guestd itself remains
  # unprivileged and can use only the 0700 child owned by its worker account.
  systemd.services.private-vm-guestd.serviceConfig.TemporaryFileSystem = [
    "/run/private-vm/scanner-scratch:rw,nosuid,nodev,noexec,size=512M,mode=0711,uid=0,gid=0"
  ];
  systemd.services.private-vm-guestd.serviceConfig.ExecStartPre = [
    "+${pkgs.coreutils}/bin/install -d -m 0700 -o private-vm-scanner -g private-vm-scanner /run/private-vm/scanner-scratch/worker"
  ];
  systemd.services.private-vm-guestd.serviceConfig.MemoryMax = "3G";

  environment.etc."private-vm/scanner-toolchain.json" = {
    mode = "0444";
    text = builtins.toJSON toolchain.manifest;
  };
  environment.etc."private-vm/scanner-sbom.spdx.json" = {
    mode = "0444";
    text = builtins.toJSON toolchain.sbom;
  };
  environment.etc."private-vm/scanner-phase.json" = {
    mode = "0444";
    text = builtins.toJSON {
      schema_version = 1;
      role = "scanner";
      phase = "definitions-update";
      network_device_policy = "proton-only";
      quarantine_device_policy = "forbidden";
      definitions_update = "enabled";
    };
  };

  services.clamav = {
    daemon = {
      enable = true;
      settings = {
        AlertEncrypted = true;
        AlertEncryptedArchive = true;
        AlertEncryptedDoc = true;
        HeuristicAlerts = true;
        LocalSocketMode = "0660";
        MaxFiles = 100000;
        MaxRecursion = 16;
        MaxScanSize = "4G";
        MaxFileSize = "4G";
        MaxScanTime = 300000;
        ScanArchive = true;
      };
    };
    updater = {
      # guestd starts the fixed definitions oneshot only after the host and
      # guest Proton verification gates pass. A timer or boot-started updater
      # would race the kill switch.
      enable = false;
    };
  };

  systemd.services.clamav-daemon.serviceConfig = {
    LimitCORE = 0;
    MemoryMax = "2G";
    NoNewPrivileges = true;
    ProtectClock = true;
    ProtectControlGroups = true;
    ProtectHostname = true;
    ProtectKernelLogs = true;
    ProtectKernelModules = true;
    ProtectKernelTunables = true;
    TasksMax = 64;
    TimeoutStartSec = "5min";
    TimeoutStopSec = "30s";
  };

  systemd.services.private-vm-scanner-definitions-update = {
    wantedBy = [ ];
    after = [ "network-online.target" ];
    restartIfChanged = false;
    serviceConfig = {
      Type = "oneshot";
      ExecStart = "${pkgs.clamav}/bin/freshclam --config-file=${freshclamConfig} --stdout";
      SuccessExitStatus = "1";
      User = "clamav";
      Group = "clamav";
      ReadWritePaths = [ "/var/lib/clamav" ];
      LimitCORE = 0;
      MemoryMax = "2G";
      NoNewPrivileges = true;
      ProtectClock = true;
      ProtectControlGroups = true;
      ProtectHostname = true;
      ProtectKernelLogs = true;
      ProtectKernelModules = true;
      ProtectKernelTunables = true;
      TasksMax = 32;
      TimeoutStartSec = "5min";
      StandardOutput = "null";
      StandardError = "null";
    };
  };

  # After the authenticated update receipt is committed to this scanner root
  # overlay, guestd may invoke this one fixed root-owned transition. The NixOS
  # switch tool records the immutable scan-offline specialisation as the boot
  # default on the same overlay; no RPC field can select a path or boot entry.
  systemd.services.private-vm-scanner-stage-offline = {
    wantedBy = [ ];
    restartIfChanged = false;
    serviceConfig = {
      Type = "oneshot";
      ExecStart = "/run/current-system/specialisation/scan-offline/bin/switch-to-configuration boot";
      RemainAfterExit = true;
      LimitCORE = 0;
      MemoryMax = "256M";
      ProtectClock = true;
      ProtectControlGroups = true;
      ProtectHostname = true;
      ProtectKernelLogs = true;
      ProtectKernelModules = true;
      ProtectKernelTunables = true;
      StandardOutput = "null";
      StandardError = "null";
      TasksMax = 32;
      TimeoutStartSec = "2min";
      TimeoutStopSec = "30s";
      UMask = "0077";
    };
  };

  # The unprivileged guest daemon may manage only the three fixed operations
  # required by its authenticated definition-update RPC. It receives no
  # generic unit, boot-entry or command authorization.
  security.polkit.enable = true;
  security.polkit.extraConfig = ''
    polkit.addRule(function(action, subject) {
      if (subject.user != "private-vm-scanner" ||
          action.id != "org.freedesktop.systemd1.manage-units") {
        return polkit.Result.NOT_HANDLED;
      }
      var unit = action.lookup("unit");
      var verb = action.lookup("verb");
      if ((unit == "private-vm-scanner-definitions-update.service" && (verb == "start" || verb == "stop")) ||
          (unit == "clamav-daemon.service" && verb == "restart") ||
          (unit == "private-vm-scanner-stage-offline.service" && (verb == "start" || verb == "stop"))) {
        return polkit.Result.YES;
      }
      return polkit.Result.NOT_HANDLED;
    });
  '';

  specialisation.scan-offline.configuration = {
    imports = [ ./scanner-offline.nix ];
  };

  assertions = [
    {
      assertion = config.services.tumbler.enable == false;
      message = "private-vm scanner must not generate thumbnails for hostile files";
    }
    {
      assertion = config.services.gvfs.enable == false && config.services.udisks2.enable == false;
      message = "private-vm scanner must not auto-discover or auto-mount hostile storage";
    }
    {
      assertion = config.services.clamav.updater.enable == false;
      message = "private-vm scanner definitions must not update before authenticated VPN verification";
    }
    {
      assertion =
        config.systemd.services.private-vm-guestd.serviceConfig.TemporaryFileSystem == [
          "/run/private-vm/scanner-scratch:rw,nosuid,nodev,noexec,size=512M,mode=0711,uid=0,gid=0"
        ];
      message = "private-vm scanner scratch must be an exact 512 MiB non-executable private tmpfs";
    }
    {
      assertion = config.systemd.services.private-vm-guestd.serviceConfig.MemoryMax == "3G";
      message = "private-vm scanner guestd memory limit must remain below its 4 GiB VM limit";
    }
  ];

  # The online update boot and offline scan boot use the same volatile root
  # overlay. The daemon selects scan-offline only after a verified update and
  # attaches quarantine read-only only to that no-NIC boot.
}
