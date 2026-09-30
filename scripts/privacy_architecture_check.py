#!/usr/bin/env python3
"""Checks the 'privacy' bundle from docs/research/research-support-manifest.json exists on disk."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = ROOT / "docs/research/research-support-manifest.json"
BUNDLE_KEY = "privacy"


def validate() -> list[str]:
    if not MANIFEST_PATH.exists():
        return [f"missing: {MANIFEST_PATH.relative_to(ROOT)}"]
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    bundle = manifest.get("bundles", {}).get(BUNDLE_KEY, [])
    if not bundle:
        return [f"bundles.{BUNDLE_KEY} is empty or missing in {MANIFEST_PATH.relative_to(ROOT)}"]
    return [f"bundles.{BUNDLE_KEY} entry missing on disk: {p}" for p in bundle if not (ROOT / p).exists()]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    errors = validate()
    ok = not errors
    name = Path(__file__).stem

    if args.json:
        print(json.dumps({"ok": ok, "errors": errors}, sort_keys=True))
    else:
        print(f"{name}: {'OK' if ok else 'FAILED'}")
        for err in errors:
            print(f"  - {err}", file=sys.stderr)

    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
