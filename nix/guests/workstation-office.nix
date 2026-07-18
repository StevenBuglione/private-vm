{ guestBundle, ... }:
{
  imports = [ ./workstation-common.nix ];
  assertions = [
    {
      assertion = guestBundle == "office";
      message = "workstation-office image requires the office bundle";
    }
  ];
}
