{ pkgs, ... }:
{
  networking.hostName = "exporter";

  environment.systemPackages = with pkgs; [
    cryptsetup
    e2fsprogs
    dosfstools
  ];

  networking.interfaces = { };
  networking.firewall.enable = true;
  networking.firewall.allowedTCPPorts = [ ];
  networking.firewall.allowedUDPPorts = [ ];

  # No desktop, NIC, USB automount, or interactive login.
}
