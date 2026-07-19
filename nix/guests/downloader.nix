{ lib, pkgs, ... }:

let
  vpnReadyMarker = "/run/private-vm-vpn/ready";
  quarantineMount = "/mnt/quarantine";
  qBittorrentProfile = "%t/private-vm-qbittorrent";
  # TOR-002 replaces qBittorrent's volatile first-boot API credential before
  # guestd uses the loopback API. The immutable image must not contain a
  # reusable Web API credential.
  qBittorrentConfig = pkgs.writeText "private-vm-qbittorrent.conf" ''
    [Application]
    FileLogger\Enabled=false

    [AutoRun]
    ConsoleEnabled=false
    OnTorrentAdded\Enabled=false
    enabled=false

    [BitTorrent]
    Session\AddTorrentStopped=true
    Session\AnonymousModeEnabled=true
    Session\DefaultSavePath=${quarantineMount}/
    Session\DHTEnabled=false
    Session\FinishedTorrentExportDirectory=
    Session\Interface=proton0
    Session\InterfaceName=proton0
    Session\LSDEnabled=false
    Session\PeXEnabled=false
    Session\ShareLimitAction=Stop
    Session\TempPath=${quarantineMount}/.incomplete/
    Session\TempPathEnabled=true
    Session\TorrentExportDirectory=

    [Network]
    PortForwardingEnabled=false

    [Preferences]
    Advanced\trackerPortForwarding=false
    WebUI\Address=127.0.0.1
    WebUI\AuthSubnetWhitelistEnabled=false
    WebUI\CSRFProtection=true
    WebUI\ClickjackingProtection=true
    WebUI\Enabled=true
    WebUI\HostHeaderValidation=true
    WebUI\LocalHostAuth=true
    WebUI\Port=8080
    WebUI\ServerDomains=localhost
    WebUI\UseUPnP=false
  '';
  qBittorrentLauncher = pkgs.makeDesktopItem {
    name = "private-vm-qbittorrent";
    desktopName = "qBittorrent (private-vm)";
    comment = "Start qBittorrent after private-vm verifies the VPN";
    exec = "systemctl --user start private-vm-qbittorrent.service";
    icon = "qbittorrent";
    categories = [ "Network" ];
    terminal = false;
  };
in
{
  imports = [ ./desktop-common.nix ];
  networking.hostName = "downloader";

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
    "private-vm/qbittorrent/qBittorrent.conf" = {
      mode = "0444";
      source = qBittorrentConfig;
    };
  };

  # qBittorrent itself is deliberately not linked into the global command
  # path. The desktop entry can reach only the gated user service below; the
  # service references the pinned package directly from the Nix store.
  environment.systemPackages = [
    pkgs.wireguard-tools
    qBittorrentLauncher
  ];

  # Only root (guestd) can create the readiness marker. The downloader role
  # extends guestd's sandbox with this one volatile writable directory.
  systemd.tmpfiles.rules = [
    "d /run/private-vm-vpn 0711 root root -"
  ];
  systemd.services.private-vm-guestd.serviceConfig.ReadWritePaths = [
    "/run/private-vm-vpn"
  ];

  systemd.user.services.private-vm-qbittorrent = {
    description = "VPN-gated private-vm qBittorrent";
    after = [ "graphical-session.target" ];
    partOf = [ "graphical-session.target" ];
    environment = {
      DISPLAY = ":0";
      XAUTHORITY = "%h/.Xauthority";
    };
    unitConfig = {
      AssertPathExists = vpnReadyMarker;
      AssertPathIsMountPoint = quarantineMount;
    };
    serviceConfig = {
      Type = "simple";
      ExecStartPre = [
        "${pkgs.coreutils}/bin/install -d -m 0700 ${qBittorrentProfile}/qBittorrent/config"
        "${pkgs.coreutils}/bin/install -m 0600 ${qBittorrentConfig} ${qBittorrentProfile}/qBittorrent/config/qBittorrent.conf"
      ];
      ExecStart = "${pkgs.qbittorrent}/bin/qbittorrent --confirm-legal-notice --no-splash --profile=${qBittorrentProfile}";
      Restart = "no";
      RuntimeDirectory = "private-vm-qbittorrent";
      RuntimeDirectoryMode = "0700";
      UMask = "0077";
      WorkingDirectory = quarantineMount;
      StandardOutput = "null";
      StandardError = "null";
      NoNewPrivileges = true;
      ProtectSystem = "strict";
      # The downloader home starts empty and remains read-only to this service;
      # qBittorrent can read only LightDM's Xauthority token there. Its profile
      # and torrent output are constrained to volatile runtime/quarantine paths.
      ProtectHome = "read-only";
      BindPaths = [ qBittorrentProfile ];
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
      assertion = lib.hasPrefix "/run/" vpnReadyMarker;
      message = "downloader VPN readiness evidence must remain volatile";
    }
    {
      assertion = lib.hasPrefix "/mnt/" quarantineMount;
      message = "downloader qBittorrent may write only to the quarantine mount";
    }
  ];
}
