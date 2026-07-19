{
  guestArchitecture,
  guestFlakeLockSHA256,
  guestSBOMCreated,
  guestSourceCommit,
  lib,
  pkgs,
}:

let
  tools = [
    {
      id = "clamav";
      spdxID = "SPDXRef-Package-clamav";
      package = pkgs.clamav;
      commands = [
        "clamd"
        "clamdscan"
        "clamscan"
        "freshclam"
      ];
      purpose = "official-definition update and malware-signature evidence";
    }
    {
      id = "file";
      spdxID = "SPDXRef-Package-file";
      package = pkgs.file;
      commands = [ "file" ];
      purpose = "libmagic-backed content identification";
    }
    {
      id = "jq";
      spdxID = "SPDXRef-Package-jq";
      package = pkgs.jq;
      commands = [ "jq" ];
      purpose = "structured scan-report inspection";
    }
    {
      id = "binutils";
      spdxID = "SPDXRef-Package-binutils";
      package = pkgs.binutils;
      commands = [
        "readelf"
        "strings"
      ];
      purpose = "bounded binary inspection primitives";
    }
    {
      id = "hexyl";
      spdxID = "SPDXRef-Package-hexyl";
      package = pkgs.hexyl;
      commands = [ "hexyl" ];
      purpose = "non-interpreting hexadecimal inspection";
    }
    {
      id = "libarchive";
      spdxID = "SPDXRef-Package-libarchive";
      package = pkgs.libarchive;
      commands = [ "bsdtar" ];
      purpose = "archive listing and extraction under guestd-enforced limits";
    }
    {
      id = "p7zip";
      spdxID = "SPDXRef-Package-p7zip";
      package = pkgs.p7zip;
      commands = [ "7z" ];
      purpose = "7-Zip archive listing under guestd-enforced limits";
    }
    {
      id = "unar";
      spdxID = "SPDXRef-Package-unar";
      package = pkgs.unar;
      commands = [
        "lsar"
        "unar"
      ];
      purpose = "archive metadata inspection under guestd-enforced limits";
    }
    {
      id = "bubblewrap";
      spdxID = "SPDXRef-Package-bubblewrap";
      package = pkgs.bubblewrap;
      commands = [ "bwrap" ];
      purpose = "unprivileged parser namespace containment";
    }
    {
      id = "mupdf";
      spdxID = "SPDXRef-Package-mupdf";
      package = pkgs.mupdf;
      commands = [ "mutool" ];
      purpose = "bounded PDF parsing and rasterization";
    }
    {
      id = "poppler-utils";
      spdxID = "SPDXRef-Package-poppler-utils";
      package = pkgs.poppler-utils;
      commands = [
        "pdfinfo"
        "pdftoppm"
        "pdftotext"
      ];
      purpose = "PDF inventory and rasterization";
    }
    {
      id = "qpdf";
      spdxID = "SPDXRef-Package-qpdf";
      package = pkgs.qpdf;
      commands = [ "qpdf" ];
      purpose = "PDF structural validation and reconstruction";
    }
    {
      id = "img2pdf";
      spdxID = "SPDXRef-Package-img2pdf";
      package = pkgs.img2pdf;
      commands = [ "img2pdf" ];
      purpose = "raster-only PDF reconstruction";
    }
    {
      id = "libreoffice";
      spdxID = "SPDXRef-Package-libreoffice";
      package = pkgs.libreoffice-fresh;
      commands = [ "libreoffice" ];
      purpose = "headless Office document rendering";
    }
    {
      id = "imagemagick";
      spdxID = "SPDXRef-Package-imagemagick";
      package = pkgs.imagemagick_light;
      commands = [ "magick" ];
      purpose = "full image decode and metadata-free re-encode";
    }
    {
      id = "exiftool";
      spdxID = "SPDXRef-Package-exiftool";
      package = pkgs.exiftool;
      commands = [ "exiftool" ];
      purpose = "metadata inventory and removal verification";
    }
    {
      id = "ffmpeg";
      spdxID = "SPDXRef-Package-ffmpeg";
      package = pkgs.ffmpeg-headless;
      commands = [
        "ffmpeg"
        "ffprobe"
      ];
      purpose = "full media decode, probe and metadata-free re-encode";
    }
    {
      id = "ghostscript";
      spdxID = "SPDXRef-Package-ghostscript";
      package = pkgs.ghostscript_headless;
      commands = [ "gs" ];
      purpose = "document rasterization fallback under guestd-enforced limits";
    }
  ];

  packageName = tool: tool.package.pname or (lib.getName tool.package);
  packageVersion = tool: tool.package.version or (lib.getVersion tool.package);
  toolRecord = tool: {
    inherit (tool) commands id purpose;
    package = packageName tool;
    version = packageVersion tool;
  };
  spdxPackage = tool: {
    SPDXID = tool.spdxID;
    name = packageName tool;
    versionInfo = packageVersion tool;
    downloadLocation = "NOASSERTION";
    filesAnalyzed = false;
    licenseConcluded = "NOASSERTION";
    licenseDeclared = "NOASSERTION";
    copyrightText = "NOASSERTION";
    externalRefs = [
      {
        referenceCategory = "PACKAGE-MANAGER";
        referenceType = "purl";
        referenceLocator = "pkg:nix/${tool.id}@${packageVersion tool}";
      }
    ];
    comment = "Pinned Nix store package ${tool.package}; ${tool.purpose}.";
  };
  documentIdentity = builtins.hashString "sha256" (
    builtins.toJSON {
      architecture = guestArchitecture;
      flake_lock_sha256 = guestFlakeLockSHA256;
      source_commit = guestSourceCommit;
      tools = map toolRecord tools;
    }
  );
in
{
  inherit documentIdentity tools;
  packages = map (tool: tool.package) tools;
  requiredCommands = lib.concatMap (tool: tool.commands) tools;

  manifest = {
    schema_version = 1;
    project = "private-vm";
    role = "scanner";
    architecture = guestArchitecture;
    source_commit = guestSourceCommit;
    flake_lock_sha256 = guestFlakeLockSHA256;
    archive_execution_contract = "guestd-bounded-unprivileged-private-namespace";
    tools = map toolRecord tools;
  };

  sbom = {
    spdxVersion = "SPDX-2.3";
    dataLicense = "CC0-1.0";
    SPDXID = "SPDXRef-DOCUMENT";
    name = "private-vm-scanner-image-toolchain";
    documentNamespace = "https://private-vm.dev/spdx/scanner/${guestArchitecture}/${guestFlakeLockSHA256}/${documentIdentity}";
    creationInfo = {
      created = guestSBOMCreated;
      creators = [ "Tool: private-vm Nix image definition" ];
      comment = "The deterministic creation time is the source commit time.";
    };
    documentDescribes = map (tool: tool.spdxID) tools;
    packages = map spdxPackage tools;
  };
}
