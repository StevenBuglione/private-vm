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
    "cmd/private-vm-image-release"
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
      ${../packaging/default/config.toml} \
      "$out/share/private-vm/config.toml"
    install -Dm0444 \
      ${../packaging/systemd/private-vmd.service} \
      "$out/lib/systemd/system/private-vmd.service"
    install -Dm0444 \
      ${../packaging/tmpfiles/private-vm.conf} \
      "$out/lib/tmpfiles.d/private-vm.conf"
    install -Dm0444 \
      ${../packaging/sysusers/private-vm.conf} \
      "$out/lib/sysusers.d/private-vm.conf"
    install -Dm0444 \
      ${../packaging/sysctl/90-private-vm.conf} \
      "$out/lib/sysctl.d/90-private-vm.conf"
    install -Dm0444 \
      ${../packaging/udev/90-private-vm.rules} \
      "$out/lib/udev/rules.d/90-private-vm.rules"
    install -Dm0444 \
      ${../packaging/usbguard/private-vm.conf.example} \
      "$out/share/private-vm/usbguard/private-vm.conf.example"
    install -Dm0444 \
      ${../packaging/polkit/org.private-vm.policy} \
      "$out/share/polkit-1/actions/org.private-vm.policy"
    install -Dm0444 ${../packaging/man/private-vm.1} "$out/share/man/man1/private-vm.1"
    install -Dm0444 ${../packaging/man/private-vmd.8} "$out/share/man/man8/private-vmd.8"
    install -Dm0444 ${../LICENSE} "$out/share/doc/private-vm/LICENSE"
    install -Dm0444 ${../README.md} "$out/share/doc/private-vm/README.md"

    installShellCompletion --cmd private-vm \
      --bash <($out/bin/private-vm completion bash) \
      --zsh <($out/bin/private-vm completion zsh) \
      --fish <($out/bin/private-vm completion fish)

    cmp \
      ${../packaging/polkit/org.private-vm.policy} \
      "$out/share/polkit-1/actions/org.private-vm.policy"
    test "$(grep -Fc '<action id=' "$out/share/polkit-1/actions/org.private-vm.policy")" -eq 1
    grep -Fq '<action id="org.private-vm.usb.prepare">' \
      "$out/share/polkit-1/actions/org.private-vm.policy"
    ! grep -Fq 'org.private-vm.session.manage' \
      "$out/share/polkit-1/actions/org.private-vm.policy"
  '';

  nativeBuildInputs = [ pkgs.installShellFiles ];
}
