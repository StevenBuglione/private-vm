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
    MemoryMax = "6G";
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
    };
  };

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
  ];

  # The online update boot and offline scan boot use the same volatile root
  # overlay. The daemon selects scan-offline only after a verified update and
  # attaches quarantine read-only only to that no-NIC boot.
}
