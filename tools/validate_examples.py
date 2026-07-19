#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]
pairs = [
    ("schemas/cli-error.schema.json", "examples/cli-error.example.json"),
    ("schemas/cli-event.schema.json", "examples/cli-event.example.json"),
    ("schemas/cli-success.schema.json", "examples/cli-success.example.json"),
    ("schemas/guest-image-identity.schema.json", "examples/guest-image-identity.example.json"),
    ("schemas/image-manifest.schema.json", "examples/image-manifest.example.json"),
    ("schemas/scan-report.schema.json", "examples/scan-report.example.json"),
    ("schemas/workstation-bundles.schema.json", "project/workstation-bundles.json"),
]

for schema_rel, example_rel in pairs:
    schema = json.loads((ROOT / schema_rel).read_text(encoding="utf-8"))
    example = json.loads((ROOT / example_rel).read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(example)
    print(f"ok: {example_rel}")
