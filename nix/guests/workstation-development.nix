{ guestBundle, ... }:
{
  imports = [ ./workstation-common.nix ];
  assertions = [
    {
      assertion = guestBundle == "development";
      message = "workstation-development image requires the development bundle";
    }
  ];
}
