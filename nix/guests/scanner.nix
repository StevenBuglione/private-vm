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
in
{
  imports = [ ./desktop-common.nix ];
  networking.hostName = "scanner";

  environment.systemPackages = [ pkgs.xfce4-terminal ] ++ toolchain.packages;

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
      enable = true;
      frequency = 1;
      interval = "daily";
      settings = {
        ConnectTimeout = 10;
        ReceiveTimeout = 60;
        MaxAttempts = 3;
      };
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

  systemd.services.clamav-freshclam.serviceConfig = {
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
  ];

  # The online update boot and offline scan boot use the same volatile root
  # overlay. The daemon selects scan-offline only after a verified update and
  # attaches quarantine read-only only to that no-NIC boot.
}
