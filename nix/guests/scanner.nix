{ pkgs, ... }:
{
  imports = [ ./desktop-common.nix ];
  networking.hostName = "scanner";

  environment.systemPackages = with pkgs; [
    clamav
    file
    binutils
    p7zip
    unar
    ffmpeg
    qpdf
    exiftool
    imagemagick
    libreoffice-fresh
    poppler_utils
    ghostscript
  ];

  # The online update boot and offline scan boot use the same volatile root
  # overlay. The quarantine disk is attached only during the offline boot.
}
