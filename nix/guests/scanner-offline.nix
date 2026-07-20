{ lib, ... }:

{
  # This module is both the production boot specialisation and the exact module
  # imported by the TCG acceptance test. QEMU must additionally omit every NIC;
  # guestd treats any non-loopback interface as a blocking scan failure.
  networking.networkmanager.enable = lib.mkForce false;
  networking.dhcpcd.enable = lib.mkForce false;
  services.resolved.enable = lib.mkForce false;
  services.clamav.updater.enable = lib.mkForce false;
  systemd.services.private-vm-scanner-definitions-update.enable = lib.mkForce false;
  systemd.services.private-vm-scanner-stage-offline.enable = lib.mkForce false;
  fileSystems."/mnt/quarantine" = {
    device = "/dev/disk/by-id/virtio-quarantine";
    fsType = "ext4";
    options = [
      "ro"
      "nodev"
      "nosuid"
      "noexec"
      "x-systemd.device-timeout=30s"
    ];
  };
  systemd.services.private-vm-guestd = {
    requires = [ "mnt-quarantine.mount" ];
    after = [ "mnt-quarantine.mount" ];
  };
  systemd.services.private-vm-guestd.serviceConfig.RestrictAddressFamilies = lib.mkForce [
    "AF_UNIX"
    "AF_VSOCK"
  ];
  systemd.services.private-vm-guestd.serviceConfig.CapabilityBoundingSet = lib.mkForce [
    "CAP_IPC_LOCK"
  ];
  systemd.services.private-vm-guestd.serviceConfig.AmbientCapabilities = lib.mkForce [
    "CAP_IPC_LOCK"
  ];

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
