{ config, lib, pkgs, ... }:

{
  services.xserver.enable = true;
  services.xserver.desktopManager.xfce.enable = true;
  services.xserver.displayManager.lightdm.enable = true;

  services.displayManager.autoLogin = {
    enable = true;
    user = "private";
  };

  services.spice-vdagentd.enable = true;
  services.qemuGuest.enable = true;

  users.users.private = {
    isNormalUser = true;
    createHome = true;
    hashedPassword = "!";
    extraGroups = [ "networkmanager" ];
  };

  networking.networkmanager.enable = true;

  environment.systemPackages = with pkgs; [
    firefox
    xfce4-terminal
    thunar
    ristretto
    mousepad
    evince
    file-roller
  ];

  # Desktop policy is additionally enforced by private-vm-guestd on first boot.
  programs.firefox.policies = {
    DisableAppUpdate = true;
    DisableFirefoxAccounts = true;
    DisableFirefoxStudies = true;
    DisableFormHistory = true;
    DisablePasswordReveal = true;
    DisablePocket = true;
    DisableTelemetry = true;
    DontCheckDefaultBrowser = true;
    OfferToSaveLogins = false;
    PasswordManagerEnabled = false;
    Preferences = {
      "browser.privatebrowsing.autostart" = true;
      "browser.download.useDownloadDir" = true;
      "browser.download.dir" = "/home/private/Downloads";
      "dom.security.https_only_mode" = true;
      "media.peerconnection.ice.proxy_only_if_behind_proxy" = true;
    };
  };
}
