{
  config,
  lib,
  pkgs,
  modulesPath,
  privateVMPackage,
  guestRole,
  guestBundle,
  guestArchitecture,
  guestCapabilities,
  guestSourceCommit,
  guestFlakeLockSHA256,
  guestdVersion,
  ...
}:

let
  imageManifest = {
    schema_version = 1;
    project = "private-vm";
    role = guestRole;
    bundle = guestBundle;
    architecture = guestArchitecture;
    nixos_version = config.system.nixos.release;
    source_repository = "StevenBuglione/private-vm";
    source_commit = guestSourceCommit;
    flake_lock_sha256 = guestFlakeLockSHA256;
    guest_api_major = 1;
    guest_api_minor = 0;
    guestd_version = guestdVersion;
    capabilities = guestCapabilities;
  };
in
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
  boot.initrd.availableKernelModules = [
    "virtio_pci"
    "virtio_blk"
    "virtio_scsi"
    "vsock"
  ];
  boot.kernelModules = [
    "qemu_fw_cfg"
    "vmw_vsock_virtio_transport"
  ];
  boot.resumeDevice = "";
  swapDevices = lib.mkForce [ ];

  networking.useDHCP = false;
  networking.firewall.enable = true;
  networking.firewall.allowedTCPPorts = [ ];
  networking.firewall.allowedUDPPorts = [ ];
  networking.nftables.enable = true;

  services.openssh.enable = false;
  security.sudo.enable = false;
  programs.ssh.startAgent = false;

  users.mutableUsers = false;
  users.allowNoPasswordLogin = true;
  users.users.root.hashedPassword = "!";

  assertions = [
    {
      assertion = builtins.elem guestRole [
        "workstation"
        "downloader"
        "scanner"
        "exporter"
      ];
      message = "private-vm image role must be one of the four frozen v1 roles";
    }
    {
      assertion = guestRole == config.networking.hostName;
      message = "private-vm compiled role must match the image hostname role";
    }
    {
      assertion = guestCapabilities == lib.sort builtins.lessThan guestCapabilities;
      message = "private-vm image capabilities must be sorted for deterministic comparison";
    }
  ];

  services.journald.extraConfig = ''
    Storage=volatile
    RuntimeMaxUse=64M
    ForwardToSyslog=no
    ForwardToKMsg=no
    ForwardToConsole=no
    ForwardToWall=no
  '';

  boot.tmp.cleanOnBoot = true;
  boot.tmp.useTmpfs = true;
  boot.tmp.tmpfsSize = "25%";
  systemd.mounts = [
    {
      what = "tmpfs";
      where = "/var/tmp";
      type = "tmpfs";
      mountConfig.Options = "mode=1777,rw,nosuid,nodev,size=128M";
    }
    {
      what = "tmpfs";
      where = "/var/log";
      type = "tmpfs";
      mountConfig.Options = "mode=0755,rw,nosuid,nodev,noexec,size=64M";
    }
  ];

  systemd.coredump.enable = false;
  systemd.settings.Manager.DefaultLimitCORE = 0;
  systemd.targets.sleep.enable = false;
  systemd.targets.suspend.enable = false;
  systemd.targets.hibernate.enable = false;
  systemd.targets.hybrid-sleep.enable = false;
  systemd.targets.suspend-then-hibernate.enable = false;

  environment.etc."private-vm/image.json" = {
    mode = "0444";
    text = builtins.toJSON imageManifest;
  };

  environment.systemPackages = [
    privateVMPackage
    pkgs.cacert
    pkgs.coreutils
    pkgs.iproute2
    pkgs.nftables
    pkgs.util-linux
  ];
  # NixOS's normal interactive core set includes general-purpose network
  # clients such as curl and OpenSSH. Guest roles opt into every user-facing
  # tool explicitly, so retain only the bounded administration primitives used
  # by boot, diagnostics and the role acceptance tests. The workstation bundle
  # adds its separately pruned client-only OpenSSH derivation when requested.
  environment.corePackages = lib.mkForce (
    with pkgs;
    [
      bashInteractive
      coreutils
      findutils
      gawk
      gnugrep
      gnused
      gnutar
      gzip
      procps
      util-linux
      xz
    ]
  );
  environment.defaultPackages = [ ];

  systemd.services.private-vm-guestd = {
    description = "private-vm guest control daemon";
    wantedBy = [ "multi-user.target" ];
    requires = [ "systemd-tmpfiles-setup.service" ];
    after = [
      "systemd-modules-load.service"
      "systemd-tmpfiles-setup.service"
    ];
    serviceConfig = {
      ExecStart = "${privateVMPackage}/bin/private-vm-guestd";
      Restart = "on-failure";
      RestartSec = "1s";
      User = "root";
      Group = "root";
      UMask = "0077";
      RuntimeDirectory = "private-vm";
      RuntimeDirectoryMode = "0700";
      NoNewPrivileges = true;
      PrivateTmp = true;
      ProtectHome = false;
      ProtectSystem = "strict";
      ProtectClock = true;
      ProtectControlGroups = true;
      ProtectHostname = true;
      ProtectKernelLogs = true;
      ProtectKernelModules = true;
      ProtectKernelTunables = true;
      ProtectProc = "invisible";
      ProcSubset = "pid";
      LockPersonality = true;
      MemoryDenyWriteExecute = true;
      RemoveIPC = true;
      RestrictAddressFamilies = [
        "AF_UNIX"
        "AF_VSOCK"
      ];
      RestrictNamespaces = true;
      RestrictRealtime = true;
      # RestrictSUIDSGID's seccomp implementation rejects openat2 outright,
      # while guestd requires openat2 for race-safe dirfd traversal. Deny each
      # path-based chmod entry point instead. The only fd-only fchmod call sets
      # a freshly created anonymous secret memfd to its fixed 0600 mode.
      RestrictSUIDSGID = false;
      SystemCallFilter = [ "~chmod fchmodat fchmodat2" ];
      SystemCallArchitectures = "native";
      CapabilityBoundingSet = [ "CAP_IPC_LOCK" ];
      DevicePolicy = "strict";
      DeviceAllow = [
        "/dev/null rw"
        "/dev/vsock rw"
      ];
      LimitCORE = 0;
      LimitMEMLOCK = "infinity";
      LimitNOFILE = 1024;
      TasksMax = 64;
    };
  };

  # No unattended persistence mechanisms.
  services.fstrim.enable = false;
  nix.gc.automatic = false;
}
