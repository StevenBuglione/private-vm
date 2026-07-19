{
  pkgs,
  src,
  version ? "0.0.0-dev",
  sourceCommit ? "unknown",
  sourceDirty ? "true",
}:

pkgs.buildGoModule {
  pname = "private-vm";
  inherit version src;
  vendorHash = null;
  env.CGO_ENABLED = 0;
  subPackages = [
    "cmd/private-vm"
    "cmd/private-vmd"
    "cmd/private-vm-guestd"
  ];
  ldflags = [
    "-s"
    "-w"
    "-X github.com/StevenBuglione/private-vm/internal/buildinfo.Version=${version}"
    "-X github.com/StevenBuglione/private-vm/internal/buildinfo.Commit=${sourceCommit}"
    "-X github.com/StevenBuglione/private-vm/internal/buildinfo.Dirty=${sourceDirty}"
  ];

  postInstall = ''
    install -Dm0444 \
      ${../packaging/polkit/org.private-vm.policy} \
      "$out/share/polkit-1/actions/org.private-vm.policy"

    cmp \
      ${../packaging/polkit/org.private-vm.policy} \
      "$out/share/polkit-1/actions/org.private-vm.policy"
    test "$(grep -Fc '<action id=' "$out/share/polkit-1/actions/org.private-vm.policy")" -eq 1
    grep -Fq '<action id="org.private-vm.usb.prepare">' \
      "$out/share/polkit-1/actions/org.private-vm.policy"
    ! grep -Fq 'org.private-vm.session.manage' \
      "$out/share/polkit-1/actions/org.private-vm.policy"
  '';
}
