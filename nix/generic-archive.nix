{
  pkgs,
  src,
  application,
  version,
  sourceDateEpoch,
}:

let
  manifestTool = pkgs.buildGoModule {
    pname = "private-vm-bundle-manifest";
    inherit version src;
    vendorHash = null;
    env.CGO_ENABLED = 0;
    subPackages = [ "cmd/private-vm-bundle-manifest" ];
  };
  bundleName = "private-vm_${version}_linux_amd64";
in
pkgs.runCommand "${bundleName}-archive"
  {
    nativeBuildInputs = [ pkgs.gnutar pkgs.zstd ];
    passthru = {
      format = "tar.zst";
      manifestSchemaVersion = 1;
    };
  }
  ''
    bundle="$TMPDIR/${bundleName}"
    install -d "$bundle"
    install -Dm0755 ${application}/bin/private-vm "$bundle/private-vm"
    install -Dm0755 ${application}/bin/private-vmd "$bundle/private-vmd"
    install -Dm0600 ${application}/share/private-vm/config.toml "$bundle/config.toml"
    install -Dm0444 ${application}/lib/systemd/system/private-vmd.service "$bundle/integration/private-vmd.service"
    install -Dm0444 ${application}/lib/tmpfiles.d/private-vm.conf "$bundle/integration/private-vm.tmpfiles"
    install -Dm0444 ${application}/lib/sysusers.d/private-vm.conf "$bundle/integration/private-vm.sysusers"
    install -Dm0444 ${application}/lib/udev/rules.d/90-private-vm.rules "$bundle/integration/90-private-vm.rules"
    install -Dm0444 ${application}/share/polkit-1/actions/org.private-vm.policy "$bundle/integration/org.private-vm.policy"
    install -Dm0444 ${application}/share/private-vm/usbguard/private-vm.conf.example "$bundle/integration/private-vm.conf.example"
    install -Dm0444 ${application}/share/bash-completion/completions/private-vm "$bundle/completions/bash/private-vm"
    install -Dm0444 ${application}/share/zsh/site-functions/_private-vm "$bundle/completions/zsh/_private-vm"
    install -Dm0444 ${application}/share/fish/vendor_completions.d/private-vm.fish "$bundle/completions/fish/private-vm.fish"
    install -Dm0444 ${application}/share/man/man1/private-vm.1 "$bundle/man/private-vm.1"
    install -Dm0444 ${application}/share/man/man8/private-vmd.8 "$bundle/man/private-vmd.8"
    install -Dm0444 ${application}/share/doc/private-vm/LICENSE "$bundle/LICENSE"
    install -Dm0444 ${application}/share/doc/private-vm/README.md "$bundle/README.md"

    ${manifestTool}/bin/private-vm-bundle-manifest \
      --root "$bundle" \
      --version ${pkgs.lib.escapeShellArg version} \
      > "$bundle/manifest.json"
    chmod 0444 "$bundle/manifest.json"

    mkdir -p "$out"
    export SOURCE_DATE_EPOCH=${toString sourceDateEpoch}
    tar \
      --sort=name \
      --mtime="@$SOURCE_DATE_EPOCH" \
      --owner=0 \
      --group=0 \
      --numeric-owner \
      -C "$TMPDIR" \
      -cf - \
      ${pkgs.lib.escapeShellArg bundleName} \
      | zstd -T1 -19 --no-progress -o "$out/${bundleName}.tar.zst"
    test -s "$out/${bundleName}.tar.zst"
  ''
