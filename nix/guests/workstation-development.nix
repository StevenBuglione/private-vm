{ pkgs, ... }:
{
  imports = [ ./workstation-office.nix ];
  environment.systemPackages = with pkgs; [
    git
    openssh
    curl
    jq
    go
    jdk
    kotlin
    rustc
    cargo
    python3
    nodejs
    vscodium
  ];
}
