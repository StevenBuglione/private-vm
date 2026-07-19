{ lib, ... }:

{
  # This module is both the production boot specialisation and the exact module
  # imported by the TCG acceptance test. QEMU must additionally omit every NIC;
  # guestd treats any non-loopback interface as a blocking scan failure.
  networking.networkmanager.enable = lib.mkForce false;
  networking.dhcpcd.enable = lib.mkForce false;
  services.resolved.enable = lib.mkForce false;
  services.clamav.updater.enable = lib.mkForce false;

  environment.etc."private-vm/scanner-phase.json" = {
    mode = "0444";
    text = lib.mkForce (
      builtins.toJSON {
        schema_version = 1;
        role = "scanner";
        phase = "scan-offline";
        network_device_policy = "forbidden";
        quarantine_device_policy = "required-read-only";
        quarantine_mount_options = [
          "nodev"
          "noexec"
          "nosuid"
          "ro"
        ];
        definitions_update = "disabled";
      }
    );
  };
}
