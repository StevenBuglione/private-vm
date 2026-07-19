{ lib, pkgs, ... }:

let
  quarantineMount = "/mnt/quarantine";
in
{
  imports = [ ./desktop-common.nix ];
  networking.hostName = "downloader";
  services.resolved.enable = true;

  # The immutable image boots with no packet egress. NET-003 replaces this
  # table atomically with one of the typed runtime templates only after it has
  # validated a streamed WireGuard profile and its resolved endpoint.
  networking.nftables.tables.private_vm_downloader = {
    family = "inet";
    content = builtins.readFile ./downloader-blocked.nft;
  };

  environment.etc = {
    "private-vm/nftables/downloader-vpn-ipv4.nft.in" = {
      mode = "0444";
      source = ./downloader-vpn-ipv4.nft.in;
    };
    "private-vm/nftables/downloader-vpn-ipv6.nft.in" = {
      mode = "0444";
      source = ./downloader-vpn-ipv6.nft.in;
    };
  };

  # qBittorrent itself is deliberately not linked into the global command
  # path. Only the fixed gated system unit references the pinned package
  # directly from the Nix store.
  environment.systemPackages = [
    pkgs.e2fsprogs
    pkgs.wireguard-tools
  ];

  # guestd owns the writable quarantine mount and per-boot qBittorrent
  # credential/configuration. Neither exists in the immutable image.
  systemd.tmpfiles.rules = [
    "d ${quarantineMount} 0700 root root -"
    "d /run/private-vm-qbittorrent 0750 root users -"
  ];
  systemd.services.private-vm-guestd.serviceConfig.ReadWritePaths = [
    quarantineMount
    "/run/private-vm-qbittorrent"
  ];
  # guestd validates the fixed virtio serial before formatting or mounting.
  # Hold startup until udev has exposed that exact device identity.
  systemd.services.private-vm-guestd.requires = [
    "dev-disk-by\\x2did-virtio\\x2dquarantine.device"
  ];
  systemd.services.private-vm-guestd.after = [
    "dev-disk-by\\x2did-virtio\\x2dquarantine.device"
  ];
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
    "CAP_SYS_ADMIN"
  ];
  systemd.services.private-vm-guestd.serviceConfig.DeviceAllow = lib.mkForce [
    "/dev/null rw"
    "/dev/vsock rw"
    "/dev/vdb rw"
    "/dev/disk/by-id/virtio-quarantine rw"
  ];

  # This fixed system unit has no install target and cannot start at boot. The
  # downloader guestd starts it through one typed owner only after the guest
  # kill switch and proton0 configuration are active.
  systemd.services.private-vm-qbittorrent = {
    description = "VPN-gated private-vm qBittorrent";
    after = [ "display-manager.service" ];
    partOf = [ "private-vm-guestd.service" ];
    environment = {
      DISPLAY = ":0";
      XAUTHORITY = "/home/private/.Xauthority";
      XDG_CONFIG_HOME = "/run/private-vm-qbittorrent/config";
      XDG_DATA_HOME = "${quarantineMount}/.qbit-data";
      XDG_CACHE_HOME = "${quarantineMount}/.qbit-cache";
    };
    unitConfig = {
      AssertPathIsMountPoint = quarantineMount;
    };
    serviceConfig = {
      Type = "simple";
      ExecStart = "${pkgs.qbittorrent}/bin/qbittorrent --confirm-legal-notice --no-splash";
      Restart = "no";
      User = "private";
      Group = "users";
      UMask = "0077";
      WorkingDirectory = quarantineMount;
      StandardOutput = "null";
      StandardError = "null";
      NoNewPrivileges = true;
      PrivateTmp = true;
      ProtectSystem = "strict";
      # The downloader home starts empty and remains read-only to this service;
      # qBittorrent can read only LightDM's Xauthority token there. Its profile
      # and torrent output are constrained to volatile runtime/quarantine paths.
      ProtectHome = "read-only";
      ReadOnlyPaths = [ "/run/private-vm-qbittorrent/config" ];
      ReadWritePaths = [ quarantineMount ];
      ProtectClock = true;
      ProtectControlGroups = true;
      ProtectKernelLogs = true;
      ProtectKernelModules = true;
      ProtectKernelTunables = true;
      LockPersonality = true;
      MemoryDenyWriteExecute = true;
      RestrictAddressFamilies = [
        "AF_UNIX"
        "AF_INET"
        "AF_INET6"
        "AF_NETLINK"
      ];
      RestrictNamespaces = true;
      RestrictRealtime = true;
      RestrictSUIDSGID = true;
      CapabilityBoundingSet = "";
      LimitCORE = 0;
      LimitNOFILE = 4096;
      TasksMax = 256;
      TimeoutStopSec = "10s";
    };
  };

  assertions = [
    {
      assertion = lib.hasPrefix "/mnt/" quarantineMount;
      message = "downloader qBittorrent may write only to the quarantine mount";
    }
  ];
}
