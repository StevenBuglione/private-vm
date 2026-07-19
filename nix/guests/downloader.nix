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
    # This immutable, package-pinned link is the only executable accepted by
    # guestd's typed qBittorrent process owner. It is deliberately outside the
    # global command path.
    "private-vm/qbittorrent" = {
      source = "${pkgs.qbittorrent}/bin/qbittorrent";
    };
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
  # path. Only guestd's fixed gated process owner references the immutable
  # package link above.
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
  systemd.services.private-vm-guestd.serviceConfig.ProtectHome = lib.mkForce "read-only";
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

  assertions = [
    {
      assertion = lib.hasPrefix "/mnt/" quarantineMount;
      message = "downloader qBittorrent may write only to the quarantine mount";
    }
  ];
}
