{
  guestBundle,
  guestRole,
  lib,
  pkgs,
  ...
}:
let
  # Keep the security-sensitive exporter tool closure explicit. The release
  # SBOM generator consumes the complete image closure; this embedded inventory
  # gives the image test a deterministic package/version cross-check without
  # pretending to be the release SPDX document.
  exporterToolPackages = with pkgs; [
    coreutils
    cryptsetup
    e2fsprogs
    systemd
    usbutils
    util-linux
  ];
  exporterToolInventory = {
    schema_version = 1;
    packages = map (package: {
      name = lib.getName package;
      version = lib.getVersion package;
      store_path = builtins.toString package;
    }) exporterToolPackages;
  };
in
{
  networking.hostName = "exporter";

  assertions = [
    {
      assertion = guestRole == "exporter";
      message = "the exporter image requires the exporter-compiled guestd";
    }
    {
      assertion = guestBundle == null;
      message = "the exporter image does not accept a desktop bundle";
    }
  ];

  environment.systemPackages = exporterToolPackages;

  environment.etc."private-vm/exporter-tools.json" = {
    mode = "0444";
    text = builtins.toJSON exporterToolInventory;
  };

  # NixOS places dosfstools in system.fsPackages even when the declared root
  # filesystem is ext4. The frozen exporter format is LUKS2 plus ext4 only, so
  # keep FAT formatters out of the runtime PATH. UEFI boot support remains in
  # the image/initrd closure and does not require a guest-visible formatter.
  system.fsPackages = lib.mkForce [ ];

  # A physical transfer device is attached only by the typed exporter launch
  # model. Keep the storage drivers available without adding an automounter or
  # broadening the guestd service's device policy in the base image.
  boot.initrd.availableKernelModules = [
    "sd_mod"
    "uas"
    "usb_storage"
    "xhci_pci"
  ];

  # The production QEMU model supplies no NIC. These image-level settings keep
  # the role free of desktop and network-management services even if a future
  # module attempts to add role-neutral conveniences.
  systemd.defaultUnit = lib.mkForce "multi-user.target";
  services.xserver.enable = lib.mkForce false;
  services.udisks2.enable = lib.mkForce false;
  networking.networkmanager.enable = lib.mkForce false;
  networking.modemmanager.enable = lib.mkForce false;

  # Root remains locked by image-base.nix. There is no normal user, desktop,
  # network manager, USB automounter, or compatibility filesystem formatter.
}
