#!/usr/bin/env python3
from __future__ import annotations

import json
import tomllib
from copy import deepcopy
from pathlib import Path

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]
pairs = [
    ("schemas/cli-error.schema.json", "examples/cli-error.example.json", "json"),
    ("schemas/cli-event.schema.json", "examples/cli-event.example.json", "json"),
    ("schemas/cli-success.schema.json", "examples/cli-success.example.json", "json"),
    ("schemas/cli-success.schema.json", "examples/cli-session-success.example.json", "json"),
    ("schemas/config.schema.json", "examples/config.example.toml", "toml"),
    ("schemas/policy.schema.json", "examples/policy.safe.toml", "toml"),
    ("schemas/policy.schema.json", "examples/policy.quarantine.toml", "toml"),
    (
        "schemas/scanner-toolchain.schema.json",
        "examples/scanner-toolchain.example.json",
        "json",
    ),
    (
        "schemas/scanner-phase.schema.json",
        "examples/scanner-phase.update.example.json",
        "json",
    ),
    (
        "schemas/scanner-phase.schema.json",
        "examples/scanner-phase.offline.example.json",
        "json",
    ),
    (
        "schemas/exporter-tool-inventory.schema.json",
        "examples/exporter-tool-inventory.example.json",
        "json",
    ),
    ("schemas/guest-image-identity.schema.json", "examples/guest-image-identity.example.json", "json"),
    ("schemas/guest-vpn-status.schema.json", "examples/guest-vpn-status.example.json", "json"),
    ("schemas/image-cache-entry.schema.json", "examples/image-cache-entry.example.json", "json"),
    ("schemas/image-manifest.schema.json", "examples/image-manifest.example.json", "json"),
    ("schemas/image-provenance-payload.schema.json", "examples/image-provenance-payload.example.json", "json"),
    ("schemas/image-release-receipt.schema.json", "examples/image-release-receipt.example.json", "json"),
    ("schemas/image-sbom.schema.json", "examples/image-sbom.spdx.example.json", "json"),
    ("schemas/network-status.schema.json", "examples/network-status.example.json", "json"),
    ("schemas/torrent-status.schema.json", "examples/torrent-status.example.json", "json"),
    ("schemas/scan-report.schema.json", "examples/scan-report.example.json", "json"),
    ("schemas/vpn-profile-status.schema.json", "examples/vpn-profile-status.example.json", "json"),
    ("schemas/workstation-bundles.schema.json", "project/workstation-bundles.json", "json"),
]

for schema_rel, example_rel, encoding in pairs:
    schema = json.loads((ROOT / schema_rel).read_text(encoding="utf-8"))
    example_bytes = (ROOT / example_rel).read_bytes()
    example = json.loads(example_bytes) if encoding == "json" else tomllib.loads(example_bytes.decode("utf-8"))
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(example)
    print(f"ok: {example_rel}")

# These mutations are the security-critical conditionals most likely to drift
# between the examples and their effective-snapshot schemas.
config_schema = json.loads((ROOT / "schemas/config.schema.json").read_text(encoding="utf-8"))
config = tomllib.loads((ROOT / "examples/config.example.toml").read_text(encoding="utf-8"))
policy_schema = json.loads((ROOT / "schemas/policy.schema.json").read_text(encoding="utf-8"))
safe_policy = tomllib.loads((ROOT / "examples/policy.safe.toml").read_text(encoding="utf-8"))
scanner_toolchain_schema = json.loads(
    (ROOT / "schemas/scanner-toolchain.schema.json").read_text(encoding="utf-8")
)
scanner_toolchain = json.loads(
    (ROOT / "examples/scanner-toolchain.example.json").read_text(encoding="utf-8")
)
scanner_phase_schema = json.loads(
    (ROOT / "schemas/scanner-phase.schema.json").read_text(encoding="utf-8")
)
scanner_update_phase = json.loads(
    (ROOT / "examples/scanner-phase.update.example.json").read_text(encoding="utf-8")
)
scanner_offline_phase = json.loads(
    (ROOT / "examples/scanner-phase.offline.example.json").read_text(encoding="utf-8")
)
exporter_tool_schema = json.loads(
    (ROOT / "schemas/exporter-tool-inventory.schema.json").read_text(encoding="utf-8")
)
exporter_tool_inventory = json.loads(
    (ROOT / "examples/exporter-tool-inventory.example.json").read_text(encoding="utf-8")
)
image_cache_schema = json.loads(
    (ROOT / "schemas/image-cache-entry.schema.json").read_text(encoding="utf-8")
)
image_cache_entry = json.loads(
    (ROOT / "examples/image-cache-entry.example.json").read_text(encoding="utf-8")
)
image_manifest_schema = json.loads(
    (ROOT / "schemas/image-manifest.schema.json").read_text(encoding="utf-8")
)
image_manifest = json.loads(
    (ROOT / "examples/image-manifest.example.json").read_text(encoding="utf-8")
)
image_provenance_schema = json.loads(
    (ROOT / "schemas/image-provenance-payload.schema.json").read_text(encoding="utf-8")
)
image_provenance = json.loads(
    (ROOT / "examples/image-provenance-payload.example.json").read_text(encoding="utf-8")
)
image_release_receipt_schema = json.loads(
    (ROOT / "schemas/image-release-receipt.schema.json").read_text(encoding="utf-8")
)
image_release_receipt = json.loads(
    (ROOT / "examples/image-release-receipt.example.json").read_text(encoding="utf-8")
)
image_sbom_schema = json.loads(
    (ROOT / "schemas/image-sbom.schema.json").read_text(encoding="utf-8")
)
image_sbom = json.loads(
    (ROOT / "examples/image-sbom.spdx.example.json").read_text(encoding="utf-8")
)
scan_report_schema = json.loads((ROOT / "schemas/scan-report.schema.json").read_text(encoding="utf-8"))
scan_report = json.loads((ROOT / "examples/scan-report.example.json").read_text(encoding="utf-8"))

negative_cases = []
unsigned = deepcopy(config)
unsigned["image_source"]["require_attestation"] = False
negative_cases.append(("unsigned config", config_schema, unsigned))
telemetry = deepcopy(config)
telemetry["logging"]["telemetry"] = True
negative_cases.append(("telemetry config", config_schema, telemetry))
bad_registry = deepcopy(config)
bad_registry["image_source"]["registry"] = "ghcr..io"
negative_cases.append(("malformed registry", config_schema, bad_registry))
bad_port = deepcopy(config)
bad_port["image_source"]["registry"] = "ghcr.io:65536"
negative_cases.append(("out-of-range registry port", config_schema, bad_port))
broad_cache = deepcopy(config)
broad_cache["runtime"]["image_cache"] = "/etc"
negative_cases.append(("broad cache path", config_schema, broad_cache))
overlapping_paths = deepcopy(config)
overlapping_paths["runtime"]["scratch_directory"] = overlapping_paths["runtime"]["image_cache"]
negative_cases.append(("overlapping runtime paths", config_schema, overlapping_paths))
secret = deepcopy(config)
secret["private_key"] = "redacted-test-value"
negative_cases.append(("secret field config", config_schema, secret))
vpn_status_schema = json.loads((ROOT / "schemas/vpn-profile-status.schema.json").read_text(encoding="utf-8"))
vpn_status = json.loads((ROOT / "examples/vpn-profile-status.example.json").read_text(encoding="utf-8"))
vpn_endpoint = deepcopy(vpn_status)
vpn_endpoint["endpoint"] = "198.51.100.20:51820"
negative_cases.append(("VPN endpoint in status", vpn_status_schema, vpn_endpoint))
vpn_key = deepcopy(vpn_status)
vpn_key["profile"]["private_key"] = "redacted-test-value"
negative_cases.append(("VPN private key in status", vpn_status_schema, vpn_key))
network_status_schema = json.loads((ROOT / "schemas/network-status.schema.json").read_text(encoding="utf-8"))
network_status = json.loads((ROOT / "examples/network-status.example.json").read_text(encoding="utf-8"))
forbidden_network_fields = {
    "endpoint": "1.1.1.1:51820",
    "address": "10.240.0.2/30",
    "interface": "pvt-example",
    "namespace": "pvmn-example",
    "profile": "proton-p2p",
}
for field, value in forbidden_network_fields.items():
    unsafe_network = deepcopy(network_status)
    unsafe_network[field] = value
    negative_cases.append((f"network {field} in status", network_status_schema, unsafe_network))
guest_vpn_status_schema = json.loads((ROOT / "schemas/guest-vpn-status.schema.json").read_text(encoding="utf-8"))
guest_vpn_status = json.loads((ROOT / "examples/guest-vpn-status.example.json").read_text(encoding="utf-8"))
for field, value in {
    "endpoint": "1.1.1.1:51820",
    "address": "10.2.0.2/32",
    "dns_server": "10.2.0.1",
    "public_ip": "1.0.0.1",
    "raw_output": "synthetic command output",
}.items():
    unsafe_guest_vpn = deepcopy(guest_vpn_status)
    unsafe_guest_vpn[field] = value
    negative_cases.append((f"guest VPN {field} in status", guest_vpn_status_schema, unsafe_guest_vpn))
torrent_status_schema = json.loads((ROOT / "schemas/torrent-status.schema.json").read_text(encoding="utf-8"))
torrent_status = json.loads((ROOT / "examples/torrent-status.example.json").read_text(encoding="utf-8"))
for field, value in {
    "magnet": "magnet:?" + "xt=urn:btih:public-fixture",
    "info_hash": "public-fixture",
    "display_name": "private-name",
    "file_path": "private/path",
    "endpoint": "1.1.1.1:51820",
    "raw_output": "synthetic command output",
}.items():
    unsafe_torrent = deepcopy(torrent_status)
    unsafe_torrent[field] = value
    negative_cases.append((f"torrent {field} in status", torrent_status_schema, unsafe_torrent))
weakened = deepcopy(safe_policy)
weakened["rules"]["sanitize_documents"] = False
negative_cases.append(("weakened safe policy", policy_schema, weakened))
raw = deepcopy(safe_policy)
raw["name"] = raw["mode"] = "raw"
negative_cases.append(("raw policy", policy_schema, raw))
oversized_single_file = deepcopy(safe_policy)
oversized_single_file["limits"]["max_single_file_bytes"] = 4294967297
negative_cases.append(("oversized scanner file", policy_schema, oversized_single_file))
oversized_expansion = deepcopy(safe_policy)
oversized_expansion["limits"]["max_expanded_bytes"] = 4294967297
negative_cases.append(("oversized scanner expansion", policy_schema, oversized_expansion))
oversized_scan_timeout = deepcopy(safe_policy)
oversized_scan_timeout["limits"]["scan_timeout_seconds"] = 301
negative_cases.append(("oversized scanner timeout", policy_schema, oversized_scan_timeout))
empty_scanner_toolchain = deepcopy(scanner_toolchain)
empty_scanner_toolchain["tools"] = []
negative_cases.append(
    ("empty scanner toolchain", scanner_toolchain_schema, empty_scanner_toolchain)
)
unknown_scanner_tool_field = deepcopy(scanner_toolchain)
unknown_scanner_tool_field["tools"][0]["credential"] = "forbidden"
negative_cases.append(
    ("unknown scanner tool field", scanner_toolchain_schema, unknown_scanner_tool_field)
)
update_with_quarantine_options = deepcopy(scanner_update_phase)
update_with_quarantine_options["quarantine_mount_options"] = ["nodev", "noexec", "nosuid", "ro"]
negative_cases.append(
    ("scanner update quarantine options", scanner_phase_schema, update_with_quarantine_options)
)
offline_with_network = deepcopy(scanner_offline_phase)
offline_with_network["network_device_policy"] = "proton-only"
negative_cases.append(("networked offline scanner", scanner_phase_schema, offline_with_network))
offline_with_reordered_mounts = deepcopy(scanner_offline_phase)
offline_with_reordered_mounts["quarantine_mount_options"] = ["ro", "nodev", "noexec", "nosuid"]
negative_cases.append(
    ("scanner mount option drift", scanner_phase_schema, offline_with_reordered_mounts)
)
duplicate_exporter_tool = deepcopy(exporter_tool_inventory)
duplicate_exporter_tool["packages"][-1]["name"] = "coreutils"
negative_cases.append(
    ("duplicate/missing exporter tool", exporter_tool_schema, duplicate_exporter_tool)
)
unknown_exporter_tool_field = deepcopy(exporter_tool_inventory)
unknown_exporter_tool_field["packages"][0]["credential"] = "forbidden"
negative_cases.append(
    ("unknown exporter tool field", exporter_tool_schema, unknown_exporter_tool_field)
)
traversal_cache_name = deepcopy(image_cache_entry)
traversal_cache_name["files"][0]["name"] = "../image.qcow2"
negative_cases.append(("cache traversal filename", image_cache_schema, traversal_cache_name))
duplicate_cache_component = deepcopy(image_cache_entry)
duplicate_cache_component["files"][1] = deepcopy(duplicate_cache_component["files"][0])
negative_cases.append(("duplicate cache component", image_cache_schema, duplicate_cache_component))
unknown_cache_field = deepcopy(image_cache_entry)
unknown_cache_field["source_reference"] = "mutable-tag"
negative_cases.append(("unknown cache field", image_cache_schema, unknown_cache_field))
missing_manifest_bundle = deepcopy(image_manifest)
del missing_manifest_bundle["bundle"]
negative_cases.append(("missing image bundle field", image_manifest_schema, missing_manifest_bundle))
wrong_manifest_capability = deepcopy(image_manifest)
wrong_manifest_capability["capabilities"].append("unexpected")
negative_cases.append(("wrong role capability set", image_manifest_schema, wrong_manifest_capability))
mutable_provenance_ref = deepcopy(image_provenance)
mutable_provenance_ref["predicate"]["buildDefinition"]["externalParameters"]["workflow"]["ref"] = "refs/heads/main"
negative_cases.append(("mutable provenance ref", image_provenance_schema, mutable_provenance_ref))
reused_repository_name = deepcopy(image_provenance)
reused_repository_name["predicate"]["buildDefinition"]["internalParameters"]["github"]["repository_id"] = "999999999"
negative_cases.append(("reused provenance repository name", image_provenance_schema, reused_repository_name))
receipt_secret_field = deepcopy(image_release_receipt)
receipt_secret_field["registry_token"] = "forbidden"
negative_cases.append(("release receipt secret field", image_release_receipt_schema, receipt_secret_field))
receipt_branch_ref = deepcopy(image_release_receipt)
receipt_branch_ref["source_ref"] = "refs/heads/main"
negative_cases.append(("release receipt branch ref", image_release_receipt_schema, receipt_branch_ref))
receipt_role_repository_mismatch = deepcopy(image_release_receipt)
receipt_role_repository_mismatch["repository"] = "ghcr.io/stevenbuglione/private-vm/scanner"
negative_cases.append(("release receipt role repository mismatch", image_release_receipt_schema, receipt_role_repository_mismatch))
receipt_fifth_file = deepcopy(image_release_receipt)
receipt_fifth_file["files"].append("provenance.json")
negative_cases.append(("release receipt fifth file", image_release_receipt_schema, receipt_fifth_file))
receipt_reordered_files = deepcopy(image_release_receipt)
receipt_reordered_files["files"][0], receipt_reordered_files["files"][1] = receipt_reordered_files["files"][1], receipt_reordered_files["files"][0]
negative_cases.append(("release receipt reordered files", image_release_receipt_schema, receipt_reordered_files))
receipt_null_workstation_bundle = deepcopy(image_release_receipt)
receipt_null_workstation_bundle["bundle"] = None
negative_cases.append(("release receipt null workstation bundle", image_release_receipt_schema, receipt_null_workstation_bundle))
missing_sbom_checksum = deepcopy(image_sbom)
del missing_sbom_checksum["packages"][1]["checksums"]
negative_cases.append(("missing closure checksum field", image_sbom_schema, missing_sbom_checksum))
unknown_sbom_field = deepcopy(image_sbom)
unknown_sbom_field["packages"][0]["source"] = "unsupported"
negative_cases.append(("unknown SPDX package field", image_sbom_schema, unknown_sbom_field))
incomplete_report = deepcopy(scan_report)
incomplete_report["phases"]["output_rescan_complete"] = False
incomplete_report["complete"] = False
negative_cases.append(("incomplete approved scan report", scan_report_schema, incomplete_report))
networked_report = deepcopy(scan_report)
networked_report["isolation"]["no_network"] = False
negative_cases.append(("networked scan report", scan_report_schema, networked_report))
unrescanned_report = deepcopy(scan_report)
unrescanned_report["sanitized_outputs"][0]["rescan_verdict"] = "SKIPPED"
negative_cases.append(("unrescanned scan output", scan_report_schema, unrescanned_report))

for label, schema, value in negative_cases:
    if Draft202012Validator(schema).is_valid(value):
        raise SystemExit(f"schema accepted forbidden case: {label}")
    print(f"ok: rejects {label}")
