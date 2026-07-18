#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]
pairs = [
    ("schemas/image-manifest.schema.json", "examples/image-manifest.example.json"),
    ("schemas/scan-report.schema.json", "examples/scan-report.example.json"),
]

for schema_rel, example_rel in pairs:
    schema = json.loads((ROOT / schema_rel).read_text(encoding="utf-8"))
    example = json.loads((ROOT / example_rel).read_text(encoding="utf-8"))
    Draft202012Validator(schema).validate(example)
    print(f"ok: {example_rel}")
