{
  guestRole,
  lib,
  pkgs,
  ...
}:

{
  services.xserver.enable = true;
  services.xserver.desktopManager.xfce.enable = true;
  services.xserver.desktopManager.xfce.enableScreensaver = false;
  services.xserver.displayManager.lightdm.enable = true;

  # The upstream XFCE module includes several convenience applications. Keep
  # the shared role layer to the desktop shell; each role declares its own
  # user-facing tools explicitly.
  environment.xfce.excludePackages = with pkgs; [
    mousepad
    networkmanagerapplet
    parole
    pavucontrol
    ristretto
    xfce4-power-manager
    xfce4-pulseaudio-plugin
    xfce4-screenshooter
    xfce4-taskmanager
    xfce4-terminal
    xfce4-volumed-pulse
  ];

  services.displayManager.autoLogin = {
    enable = true;
    user = "private";
  };

  services.spice-vdagentd.enable = true;
  # Online roles use systemd-resolved only as the guestd-controlled DNS
  # boundary. Link-local discovery is never part of that boundary and would
  # otherwise open wildcard UDP/TCP listeners before proton0 is verified.
  services.avahi.enable = lib.mkForce false;
  services.resolved.settings.Resolve = {
    LLMNR = false;
    MulticastDNS = false;
  };
  services.gnome.gcr-ssh-agent.enable = false;
  services.gnome.gnome-keyring.enable = guestRole == "workstation";
  programs.thunar.enable = lib.mkForce (builtins.elem guestRole [
    "workstation"
    "scanner"
  ]);
  services.gvfs.enable = lib.mkForce false;
  services.tumbler.enable = lib.mkForce false;
  services.udisks2.enable = lib.mkForce false;

  # XFCE manages its own optional SSH agent independently of the NixOS and GCR
  # agent settings. Keep its system default disabled for every graphical role.
  environment.etc."xdg/xfce4/xfconf/xfce-perchannel-xml/xfce4-session.xml".text = ''
    <?xml version="1.0" encoding="UTF-8"?>
    <channel name="xfce4-session" version="1.0">
      <property name="startup" type="empty">
        <property name="ssh-agent" type="empty">
          <property name="enabled" type="bool" value="false" locked="private"/>
        </property>
      </property>
    </channel>
  '';

  users.users.private = {
    isNormalUser = true;
    createHome = true;
    homeMode = "0700";
    hashedPassword = "!";
  };

  networking.networkmanager.enable = true;
  networking.modemmanager.enable = false;
}
