#!/usr/bin/env python3
"""Dependency-free structural validation for the checked-in JSON schemas.

This does not replace Draft 2020-12 validation in CI. It catches malformed JSON
and missing root metadata before a schema validator is introduced.
"""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
required = {"$schema", "$id", "title", "type"}

for path in sorted((ROOT / "schemas").glob("*.json")):
    value = json.loads(path.read_text(encoding="utf-8"))
    missing = required - set(value)
    if missing:
        raise SystemExit(f"{path}: missing {sorted(missing)}")
    if value["type"] != "object":
        raise SystemExit(f"{path}: root type must be object")
    if path.name.startswith("cli-"):
        if value.get("additionalProperties") is not False:
            raise SystemExit(f"{path}: CLI envelope must reject unknown top-level fields")
        required_fields = set(value.get("required", []))
        if "schema_version" not in required_fields:
            raise SystemExit(f"{path}: CLI envelope must require schema_version")
    print(f"ok: {path.relative_to(ROOT)}")
