#!/usr/bin/env python3
"""Schema and reference-path validation for docs/policy-intelligence/policy-intelligence-manifest.json."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = ROOT / "docs/policy-intelligence/policy-intelligence-manifest.json"

REQUIRED_TOP_LEVEL_KEYS = (
    "policy_intelligence_program",
    "coverage_model",
    "maturity_model",
    "gap_analysis_model",
    "risk_weighted_controls_model",
    "reporting_contract",
    "review_workflow",
    "data_boundaries",
    "referenced_documents",
    "referenced_examples",
    "required_checks",
    "non_goals",
)

MODEL_SECTIONS_WITH_ENTRYPOINTS = (
    "coverage_model",
    "maturity_model",
    "gap_analysis_model",
    "risk_weighted_controls_model",
    "reporting_contract",
    "review_workflow",
    "data_boundaries",
)


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def validate(manifest_path: Path) -> list[str]:
    errors: list[str] = []

    if not manifest_path.exists():
        return [f"missing manifest: {manifest_path}"]

    manifest = _load(manifest_path)

    for key in REQUIRED_TOP_LEVEL_KEYS:
        if key not in manifest:
            errors.append(f"missing top-level key: {key}")

    for section_key in MODEL_SECTIONS_WITH_ENTRYPOINTS:
        section = manifest.get(section_key, {})
        for entrypoint in section.get("entrypoints", []):
            if not (ROOT / entrypoint).exists():
                errors.append(f"{section_key}.entrypoints references missing file: {entrypoint}")

    for entry_list, label in (
        (manifest.get("referenced_documents", []), "referenced_documents"),
        (manifest.get("referenced_examples", []), "referenced_examples"),
    ):
        for entry in entry_list:
            rel_path = entry.get("path") if isinstance(entry, dict) else None
            if not rel_path:
                errors.append(f"{label} entry missing 'path': {entry!r}")
            elif not (ROOT / rel_path).exists():
                errors.append(f"{label} references missing file: {rel_path}")

    for rel_path in manifest.get("required_checks", []):
        if rel_path.startswith("scripts/") and not (ROOT / rel_path).exists():
            errors.append(f"required_checks references missing script: {rel_path}")

    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=MANIFEST_PATH)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    errors = validate(args.manifest)
    ok = not errors

    if args.json:
        print(json.dumps({"ok": ok, "manifest": str(args.manifest), "errors": errors}, sort_keys=True))
    else:
        print(f"validate_policy_intelligence_manifest: {'OK' if ok else 'FAILED'}")
        for err in errors:
            print(f"  - {err}", file=sys.stderr)

    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
