#!/usr/bin/env python3
"""Aggregate check for docs/research/research-support-manifest.json.

Validates every bundle, every top-level documentation/example path, and
that every script the manifest lists actually exists. Rolls up the five
bundle-specific checkers (threat_model_check, legal_positioning_check,
privacy_architecture_check, provider_cooperation_check,
scalability_patterns_check) plus empirical_evaluation_check.
"""

from __future__ import annotations

import argparse
import importlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = ROOT / "docs/research/research-support-manifest.json"
sys.path.insert(0, str(Path(__file__).resolve().parent))

BUNDLE_CHECK_MODULES = (
    "threat_model_check",
    "legal_positioning_check",
    "privacy_architecture_check",
    "provider_cooperation_check",
    "scalability_patterns_check",
    "empirical_evaluation_check",
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    errors: list[str] = []

    if not MANIFEST_PATH.exists():
        errors.append(f"missing: {MANIFEST_PATH.relative_to(ROOT)}")
        manifest = {}
    else:
        manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))

    for key in ("bundles", "documentation", "examples", "scripts"):
        if key not in manifest:
            errors.append(f"research-support-manifest.json missing key: {key}")

    for rel_path in manifest.get("documentation", []):
        if not (ROOT / rel_path).exists():
            errors.append(f"documentation entry missing on disk: {rel_path}")

    for rel_path in manifest.get("examples", []):
        if not (ROOT / rel_path).exists():
            errors.append(f"examples entry missing on disk: {rel_path}")

    for rel_path in manifest.get("scripts", []):
        if not (ROOT / rel_path).exists():
            errors.append(f"scripts entry missing on disk: {rel_path}")

    sub_results = {}
    for mod_name in BUNDLE_CHECK_MODULES:
        mod = importlib.import_module(mod_name)
        sub_errors = mod.validate()
        sub_results[mod_name] = {"ok": not sub_errors, "errors": sub_errors}
        errors.extend(f"{mod_name}: {e}" for e in sub_errors)

    ok = not errors

    if args.json:
        print(json.dumps({"ok": ok, "sub_checks": sub_results, "errors": errors}, sort_keys=True))
    else:
        if ok:
            print("research_support_check: OK")
        else:
            print("research_support_check: FAILED", file=sys.stderr)
            for err in errors:
                print(f"  - {err}", file=sys.stderr)

    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
