{
  config,
  guestBundle,
  lib,
  pkgs,
  ...
}:

let
  catalog = builtins.fromJSON (builtins.readFile ../../project/workstation-bundles.json);
  opensshClientOnly = pkgs.openssh.overrideAttrs (previous: {
    pname = "openssh-client-only";
    postInstall = (previous.postInstall or "") + ''
      rm -f \
        "$out/bin/sshd" \
        "$out/etc/ssh/moduli" \
        "$out/etc/ssh/sshd_config" \
        "$out/libexec/sftp-server" \
        "$out/libexec/sshd-auth" \
        "$out/libexec/sshd-session"
    '';
    installCheckPhase = ''
      "$out/bin/ssh" -V
    '';
  });
  packagesByName = {
    cargo = pkgs.cargo;
    cmake = pkgs.cmake;
    curl = pkgs.curl;
    evince = pkgs.evince;
    "file-roller" = pkgs.file-roller;
    firefox = config.programs.firefox.finalPackage;
    gcc = pkgs.gcc;
    gdb = pkgs.gdb;
    git = pkgs.git;
    go = pkgs.go;
    gradle = pkgs.gradle;
    gnumake = pkgs.gnumake;
    hunspell = pkgs.hunspell;
    "hunspell-en-us" = pkgs.hunspellDicts.en_US;
    jdk = pkgs.jdk;
    jq = pkgs.jq;
    keepassxc = pkgs.keepassxc;
    kotlin = pkgs.kotlin;
    libreoffice = pkgs.libreoffice-fresh;
    mousepad = pkgs.mousepad;
    nodejs = pkgs.nodejs;
    "openssh-client" = opensshClientOnly;
    "pkg-config" = pkgs.pkg-config;
    python = pkgs.python3;
    ristretto = pkgs.ristretto;
    rustc = pkgs.rustc;
    thunar = pkgs.thunar;
    vscodium = pkgs.vscodium;
    "xfce4-terminal" = pkgs.xfce4-terminal;
    zenity = pkgs.zenity;
  };
  bundleNames = builtins.attrNames catalog.bundles;
  selectedPackageNames = catalog.bundles.${guestBundle};
  unknownPackageNames = builtins.filter (
    name: !(builtins.hasAttr name packagesByName)
  ) selectedPackageNames;
  bundleManifest = {
    schema_version = catalog.schema_version;
    project = catalog.project;
    role = catalog.role;
    bundle = guestBundle;
    packages = selectedPackageNames;
  };
in
{
  imports = [ ./desktop-common.nix ];

  networking.hostName = "workstation";
  services.resolved.enable = true;

  assertions = [
    {
      assertion = catalog.schema_version == 1 && catalog.project == "private-vm";
      message = "workstation bundle catalog must use the frozen v1 private-vm contract";
    }
    {
      assertion = catalog.role == "workstation";
      message = "workstation bundle catalog role must be workstation";
    }
    {
      assertion = builtins.elem guestBundle bundleNames;
      message = "workstation image must select a declared bundle";
    }
    {
      assertion = unknownPackageNames == [ ];
      message = "workstation bundle contains an unmapped package identifier";
    }
    {
      assertion = builtins.all (
        names: names == lib.sort builtins.lessThan names && names == lib.unique names
      ) (builtins.attrValues catalog.bundles);
      message = "workstation bundle package identifiers must be sorted and unique";
    }
    {
      assertion = builtins.all (name: builtins.elem name catalog.bundles.office) catalog.bundles.basic;
      message = "the workstation office bundle must include every basic package";
    }
    {
      assertion = builtins.all (
        name: builtins.elem name catalog.bundles.development
      ) catalog.bundles.office;
      message = "the workstation development bundle must include every office package";
    }
  ];

  environment.systemPackages = (map (name: packagesByName.${name}) selectedPackageNames) ++ [
    pkgs.wireguard-tools
  ];

  # guestd, not desktop applications, owns the fixed proton0 lifecycle. The
  # broader socket families and NET_ADMIN capability are required only for
  # typed WireGuard/nftables/netlink operations after authenticated VSOCK RPC.
  systemd.services.private-vm-guestd.serviceConfig.RestrictAddressFamilies = lib.mkForce [
    "AF_UNIX"
    "AF_VSOCK"
    "AF_INET"
    "AF_INET6"
    "AF_NETLINK"
  ];
  systemd.services.private-vm-guestd.serviceConfig.CapabilityBoundingSet = lib.mkForce [
    "CAP_IPC_LOCK"
    "CAP_NET_ADMIN"
  ];
  # ProtectSystem=strict makes the image immutable. Grant guestd only the two
  # workspace paths used by the typed import/export API; desktop applications
  # continue to own the rest of the private user's home.
  systemd.services.private-vm-guestd.serviceConfig.ReadWritePaths = [
    "/home/private/Inbox"
    "/home/private/Export"
  ];

  # NixOS installs programs.ssh.package as a core package. Point that module at
  # the same client-only derivation so the stock server-capable output cannot
  # win a buildEnv collision and reintroduce sshd.
  programs.ssh.package = opensshClientOnly;

  environment.etc."private-vm/workstation-bundle.json" = {
    mode = "0444";
    text = builtins.toJSON bundleManifest;
  };

  systemd.tmpfiles.rules = [
    "d /home/private/Downloads 0700 private users -"
    "d /home/private/Inbox 0700 private users -"
    "d /home/private/Export 0700 private users -"
  ];

  environment.sessionVariables.MOZ_CRASHREPORTER_DISABLE = "1";

  programs.firefox = {
    enable = true;
    policies = {
      DisableFeedbackCommands = true;
      DisableFirefoxAccounts = true;
      DisableFirefoxStudies = true;
      DisableFormHistory = true;
      DisablePasswordReveal = true;
      DisableProfileImport = true;
      DisableProfileRefresh = true;
      DisableSetDesktopBackground = true;
      DisableTelemetry = true;
      DontCheckDefaultBrowser = true;
      DownloadDirectory = "\${home}/Downloads";
      NetworkPrediction = false;
      NoDefaultBookmarks = true;
      OfferToSaveLogins = false;
      OverrideFirstRunPage = "";
      OverridePostUpdatePage = "";
      PasswordManagerEnabled = false;
    };
    preferences = {
      "browser.download.alwaysOpenPanel" = false;
      "browser.download.manager.addToRecentDocs" = false;
      "browser.download.open_pdf_attachments_inline" = false;
      "browser.crashReports.unsubmittedCheck.autoSubmit2" = false;
      "browser.crashReports.unsubmittedCheck.enabled" = false;
      "browser.formfill.enable" = false;
      "browser.privatebrowsing.autostart" = true;
      "browser.sessionstore.resume_from_crash" = false;
      "browser.shell.checkDefaultBrowser" = false;
      "browser.tabs.crashReporting.sendReport" = false;
      "dom.security.https_only_mode" = true;
      "extensions.pocket.enabled" = false;
      "media.peerconnection.enabled" = false;
      "network.dns.disablePrefetch" = true;
      "network.http.speculative-parallel-limit" = 0;
      "network.predictor.enabled" = false;
      "network.prefetch-next" = false;
      "signon.rememberSignons" = false;
    };
    preferencesStatus = "locked";
  };
}
