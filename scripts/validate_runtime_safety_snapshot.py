#!/usr/bin/env python3
"""Schema validation for a single runtime safety snapshot payload."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_INPUT = ROOT / "examples/runtime-safety/sample-runtime-safety-snapshot.json"
MANIFEST_PATH = ROOT / "docs/runtime-safety/runtime-safety-manifest.json"


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def validate(snapshot: dict, manifest: dict) -> list[str]:
    errors: list[str] = []
    schema = manifest.get("snapshot_schema", {})

    for key in schema.get("required_keys", []):
        if key not in snapshot:
            errors.append(f"missing required key: {key}")

    if not isinstance(snapshot.get("schema_version"), int):
        errors.append("schema_version must be an integer")
    if not isinstance(snapshot.get("snapshot_id"), str) or not snapshot.get("snapshot_id"):
        errors.append("snapshot_id must be a non-empty string")
    if not isinstance(snapshot.get("window_minutes"), int) or snapshot.get("window_minutes", 0) <= 0:
        errors.append("window_minutes must be a positive integer")

    for collection in schema.get("required_collections", []):
        if not isinstance(snapshot.get(collection), dict):
            errors.append(f"collection '{collection}' must be present and an object")

    diagnostics = snapshot.get("diagnostics", {})
    if isinstance(diagnostics, dict):
        checks = diagnostics.get("checks", [])
        if not isinstance(checks, list):
            errors.append("diagnostics.checks must be a list")
            checks = []
        observed_failures = sum(1 for c in checks if isinstance(c, dict) and c.get("ok") is False)
        if diagnostics.get("failure_count") != observed_failures:
            errors.append(
                f"diagnostics.failure_count ({diagnostics.get('failure_count')!r}) "
                f"does not match ok:false count in checks ({observed_failures})"
            )

    human_oversight = snapshot.get("human_oversight", {})
    if isinstance(human_oversight, dict):
        for key in ("human_review_coverage_percent", "attribution_chain_complete_percent"):
            v = human_oversight.get(key)
            if not isinstance(v, int) or not (0 <= v <= 100):
                errors.append(f"human_oversight.{key} must be an integer in [0, 100]")

    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT)
    parser.add_argument("--manifest", type=Path, default=MANIFEST_PATH)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    if not args.input.exists():
        errors = [f"missing snapshot input: {args.input}"]
    else:
        snapshot = _load(args.input)
        manifest = _load(args.manifest) if args.manifest.exists() else {}
        errors = validate(snapshot, manifest)

    ok = not errors

    if args.json:
        print(json.dumps({"ok": ok, "input": str(args.input), "errors": errors}, sort_keys=True))
    else:
        print(f"validate_runtime_safety_snapshot: {'OK' if ok else 'FAILED'}")
        for err in errors:
            print(f"  - {err}", file=sys.stderr)

    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
