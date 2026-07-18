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
}
