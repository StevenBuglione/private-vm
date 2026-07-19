#!/usr/bin/env python3
"""Validate the closed, hook-free Linux package and host-integration contract."""

from __future__ import annotations

import json
import pathlib
import re
import sys


ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC_PATH = ROOT / "packaging/packages/linux-package.json"


def fail(message: str) -> None:
    raise ValueError(message)


def walk_keys(value: object):
    if isinstance(value, dict):
        for key, child in value.items():
            yield key
            yield from walk_keys(child)
    elif isinstance(value, list):
        for child in value:
            yield from walk_keys(child)


def main() -> int:
    spec = json.loads(SPEC_PATH.read_text(encoding="utf-8"))
    expected_fields = {
        "schema_version", "name", "architecture", "platform", "maintainer",
        "vendor", "homepage", "license", "description", "contents", "formats",
        "preserved_on_upgrade_or_remove",
    }
    if set(spec) != expected_fields:
        fail("package specification has an unknown or missing top-level field")
    if spec["schema_version"] != 1 or spec["name"] != "private-vm":
        fail("package identity is not the frozen v1 contract")
    if spec["architecture"] != "amd64" or spec["platform"] != "linux":
        fail("v1 distro packages must target linux/amd64")

    forbidden_hooks = {
        "scripts", "preinstall", "postinstall", "preremove", "postremove",
        "pretrans", "posttrans", "preupgrade", "postupgrade",
    }
    if forbidden_hooks.intersection(walk_keys(spec)):
        fail("package lifecycle shell hooks are prohibited")

    destinations: set[str] = set()
    sources: set[str] = set()
    for item in spec["contents"]:
        allowed = {"source", "destination", "mode", "type"}
        if not isinstance(item, dict) or not set(item).issubset(allowed):
            fail("package content entry is malformed")
        source = item.get("source")
        destination = item.get("destination")
        mode = item.get("mode")
        if not isinstance(source, str) or source.startswith("/") or ".." in pathlib.PurePosixPath(source).parts:
            fail("package source must be a safe application-output-relative path")
        if not isinstance(destination, str) or not destination.startswith("/") or ".." in pathlib.PurePosixPath(destination).parts:
            fail("package destination must be an absolute normalized path")
        if destination in destinations or source in sources:
            fail("package content paths must be unique")
        if destination.startswith(("/run/private-vm", "/var/lib/private-vm")):
            fail("volatile or persistent state must not be package-owned")
        if mode not in (292, 384, 493):
            fail("package file mode is not allowlisted")
        if destination == "/etc/private-vm/config.toml":
            if item.get("type") != "config|noreplace" or mode != 384:
                fail("daemon configuration must be mode 0600 and non-replacing")
        elif item.get("type", "file") != "file":
            fail("only the daemon configuration may use a special content type")
        destinations.add(destination)
        sources.add(source)

    required_destinations = {
        "/usr/bin/private-vm",
        "/usr/libexec/private-vmd",
        "/etc/private-vm/config.toml",
        "/usr/lib/systemd/system/private-vmd.service",
        "/usr/lib/tmpfiles.d/private-vm.conf",
        "/usr/lib/sysusers.d/private-vm.conf",
        "/usr/lib/udev/rules.d/90-private-vm.rules",
        "/usr/share/polkit-1/actions/org.private-vm.policy",
        "/usr/share/man/man1/private-vm.1",
        "/usr/share/man/man8/private-vmd.8",
    }
    if not required_destinations.issubset(destinations):
        fail("package omits a required host-integration path")

    expected_dependencies = {
        "deb": {"systemd", "qemu-system-x86", "qemu-utils", "ovmf", "virt-viewer", "cryptsetup", "nftables", "iproute2", "usbguard", "polkitd", "util-linux", "e2fsprogs", "zstd"},
        "rpm": {"systemd", "qemu-kvm", "qemu-img", "edk2-ovmf", "virt-viewer", "cryptsetup", "nftables", "iproute", "usbguard", "polkit", "util-linux", "e2fsprogs", "zstd"},
    }
    if set(spec["formats"]) != set(expected_dependencies):
        fail("only deb and rpm package formats are supported")
    for package_format, required in expected_dependencies.items():
        dependencies = spec["formats"][package_format].get("dependencies")
        if not isinstance(dependencies, list) or len(dependencies) != len(set(dependencies)):
            fail(f"{package_format} dependencies must be a unique list")
        if set(dependencies) != required:
            fail(f"{package_format} dependency contract drifted")

    preserved = set(spec["preserved_on_upgrade_or_remove"])
    if preserved != {"/etc/private-vm/config.toml", "/var/lib/private-vm", "/var/lib/private-vm/images"}:
        fail("upgrade/removal preservation contract drifted")

    service = (ROOT / "packaging/systemd/private-vmd.service").read_text(encoding="utf-8")
    for required in (
        "ExecStart=/usr/libexec/private-vmd --config /etc/private-vm/config.toml --group private-vm",
        "NoNewPrivileges=yes", "ProtectSystem=strict", "LimitCORE=0", "Delegate=yes",
    ):
        if required not in service:
            fail(f"service hardening is missing {required}")
    if re.search(r"Environment=.*(?:KEY|TOKEN|PASSWORD|MAGNET)", service, re.IGNORECASE):
        fail("service environment contains a secret-shaped field")

    policy = (ROOT / "packaging/polkit/org.private-vm.policy").read_text(encoding="utf-8")
    if policy.count("<action id=") != 1 or "org.private-vm.usb.prepare" not in policy:
        fail("Polkit policy must contain only the destructive USB prepare action")
    udev = (ROOT / "packaging/udev/90-private-vm.rules").read_text(encoding="utf-8")
    if any(token in udev for token in ("RUN{", "RUN+=", "authorized", "bind", "uaccess")):
        fail("udev integration must only tag candidates")
    if (ROOT / "packaging/sysusers/private-vm.conf").read_text(encoding="utf-8").strip() != "g private-vm - -":
        fail("sysusers integration must create only the authorization group")

    print("packaging asset contract: ok")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"packaging asset contract: failed: {error}", file=sys.stderr)
        raise SystemExit(1)
