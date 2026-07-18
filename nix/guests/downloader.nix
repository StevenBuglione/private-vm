{ pkgs, ... }:
{
  imports = [ ./desktop-common.nix ];
  networking.hostName = "downloader";

  environment.systemPackages = with pkgs; [
    wireguard-tools
    qbittorrent
  ];

  # private-vm-guestd must generate nftables rules before launching qBittorrent.
  # The application is configured at runtime to bind only to proton0.
}
