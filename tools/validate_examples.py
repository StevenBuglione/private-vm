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
    ("schemas/config.schema.json", "examples/config.example.toml", "toml"),
    ("schemas/policy.schema.json", "examples/policy.safe.toml", "toml"),
    ("schemas/policy.schema.json", "examples/policy.quarantine.toml", "toml"),
    (
        "schemas/exporter-tool-inventory.schema.json",
        "examples/exporter-tool-inventory.example.json",
        "json",
    ),
    ("schemas/guest-image-identity.schema.json", "examples/guest-image-identity.example.json", "json"),
    ("schemas/image-manifest.schema.json", "examples/image-manifest.example.json", "json"),
    ("schemas/scan-report.schema.json", "examples/scan-report.example.json", "json"),
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
exporter_tool_schema = json.loads(
    (ROOT / "schemas/exporter-tool-inventory.schema.json").read_text(encoding="utf-8")
)
exporter_tool_inventory = json.loads(
    (ROOT / "examples/exporter-tool-inventory.example.json").read_text(encoding="utf-8")
)

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
weakened = deepcopy(safe_policy)
weakened["rules"]["sanitize_documents"] = False
negative_cases.append(("weakened safe policy", policy_schema, weakened))
raw = deepcopy(safe_policy)
raw["name"] = raw["mode"] = "raw"
negative_cases.append(("raw policy", policy_schema, raw))
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

for label, schema, value in negative_cases:
    if Draft202012Validator(schema).is_valid(value):
        raise SystemExit(f"schema accepted forbidden case: {label}")
    print(f"ok: rejects {label}")
