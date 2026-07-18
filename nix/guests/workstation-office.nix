{ pkgs, ... }:
{
  imports = [ ./workstation-basic.nix ];
  environment.systemPackages = with pkgs; [
    libreoffice-fresh
    hunspell
    hunspellDicts.en_US
    keepassxc
  ];
}
