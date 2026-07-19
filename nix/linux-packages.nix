{
  pkgs,
  application,
  version,
  sourceDateEpoch,
}:

let
  spec = builtins.fromJSON (builtins.readFile ../packaging/packages/linux-package.json);
  fixedMtime = "1970-01-01T00:00:00Z";

  contentFor = entry: {
    src = "${application}/${entry.source}";
    dst = entry.destination;
    type = entry.type or "file";
    file_info = {
      inherit (entry) mode;
      owner = "root";
      group = "root";
      mtime = fixedMtime;
    };
  };

  configFor =
    format:
    let
      formatConfig = spec.formats.${format};
    in
    pkgs.writeText "private-vm-${format}-nfpm.json" (
      builtins.toJSON (
        {
          inherit (spec)
            name
            platform
            maintainer
            vendor
            homepage
            license
            description
            ;
          arch = spec.architecture;
          inherit version;
          version_schema = "semver";
          release = "1";
          mtime = fixedMtime;
          disable_globbing = true;
          depends = formatConfig.dependencies;
          contents = map contentFor spec.contents;
        }
        // (if format == "deb" then {
          inherit (formatConfig) section priority;
          deb.compression = "xz";
        } else {
          inherit (formatConfig) group;
          rpm.compression = "zstd";
        })
      )
    );

  packageFor =
    format:
    pkgs.runCommand "private-vm-${version}-${format}"
      {
        nativeBuildInputs = [ pkgs.nfpm ];
        passthru = {
          packageFormat = format;
          packageSpecification = ../packaging/packages/linux-package.json;
        };
      }
      ''
        mkdir -p "$out"
        export SOURCE_DATE_EPOCH=${toString sourceDateEpoch}
        nfpm package \
          --config ${configFor format} \
          --packager ${format} \
          --target "$out/private-vm.${format}"
        test -s "$out/private-vm.${format}"
      '';
in
{
  deb = packageFor "deb";
  rpm = packageFor "rpm";
}
