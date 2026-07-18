{ guestBundle, ... }:
{
  imports = [ ./workstation-common.nix ];
  assertions = [
    {
      assertion = guestBundle == "basic";
      message = "workstation-basic image requires the basic bundle";
    }
  ];
}
