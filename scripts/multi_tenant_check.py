#!/usr/bin/env python3
"""Validate the multi-tenant/ governance bundle: artifacts, docs, examples, Makefile wiring.

Per docs/multi-tenant/README.md: "These checks assert file presence, JSON
shape, Makefile wiring, and example paths." Does not change compliance
verdict semantics or Rust runtime enforcement.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BUNDLE_DIR = ROOT / "multi-tenant"
MANIFEST_PATH = BUNDLE_DIR / "governance-manifest.json"

REQUIRED_MAKEFILE_TARGETS = ("multi-tenant-check", "tenant-isolation-check")


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _makefile_targets() -> set[str]:
    text = (ROOT / "Makefile").read_text(encoding="utf-8")
    return set(re.findall(r"^([A-Za-z0-9_.-]+):", text, re.MULTILINE))


def validate() -> list[str]:
    errors: list[str] = []

    if not MANIFEST_PATH.exists():
        return [f"missing: {MANIFEST_PATH.relative_to(ROOT)}"]

    manifest = _load(MANIFEST_PATH)

    for key in ("schema_version", "artifacts", "documentation_index", "example_paths"):
        if key not in manifest:
            errors.append(f"governance-manifest.json missing key: {key}")

    for artefact_key, rel_path in manifest.get("artifacts", {}).items():
        path = ROOT / rel_path
        if not path.exists():
            errors.append(f"artifacts.{artefact_key} missing on disk: {rel_path}")
            continue
        try:
            _load(path)
        except json.JSONDecodeError as e:
            errors.append(f"artifacts.{artefact_key} ({rel_path}) is not valid JSON: {e}")

    for rel_path in manifest.get("documentation_index", []):
        if not (ROOT / rel_path).exists():
            errors.append(f"documentation_index entry missing on disk: {rel_path}")

    for rel_path in manifest.get("example_paths", []):
        if not (ROOT / rel_path).exists():
            errors.append(f"example_paths entry missing on disk: {rel_path}")

    targets = _makefile_targets()
    for target in REQUIRED_MAKEFILE_TARGETS:
        if target not in targets:
            errors.append(f"Makefile target not defined: {target}")

    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    errors = validate()
    ok = not errors

    if args.json:
        print(json.dumps({"ok": ok, "errors": errors}, sort_keys=True))
    else:
        if ok:
            print("multi_tenant_check: OK")
        else:
            print("multi_tenant_check: FAILED", file=sys.stderr)
            for err in errors:
                print(f"  - {err}", file=sys.stderr)

    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
