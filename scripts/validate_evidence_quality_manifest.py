#!/usr/bin/env python3
"""Schema and path validation for docs/evidence-quality/evidence-quality-manifest.json."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = ROOT / "docs/evidence-quality/evidence-quality-manifest.json"

REQUIRED_TOP_LEVEL_KEYS = (
    "evidence_quality_program",
    "provenance_requirements",
    "lineage_requirements",
    "retention_requirements",
    "scoring_model",
    "referenced_documents",
    "referenced_examples",
    "required_checks",
)


def validate(manifest_path: Path) -> list[str]:
    errors: list[str] = []

    if not manifest_path.exists():
        return [f"missing: {manifest_path}"]

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    for key in REQUIRED_TOP_LEVEL_KEYS:
        if key not in manifest:
            errors.append(f"manifest missing key: {key}")

    for entry_list, label in (
        (manifest.get("referenced_documents", []), "referenced_documents"),
        (manifest.get("referenced_examples", []), "referenced_examples"),
    ):
        for entry in entry_list:
            path = entry.get("path")
            if not path:
                errors.append(f"{label} entry missing 'path': {entry!r}")
            elif not (ROOT / path).exists():
                errors.append(f"{label} references missing file: {path}")

    for section_key in ("provenance_requirements", "lineage_requirements", "retention_requirements", "scoring_model", "evidence_quality_program"):
        section = manifest.get(section_key, {})
        for entrypoint in section.get("entrypoints", []):
            if not (ROOT / entrypoint).exists():
                errors.append(f"{section_key}.entrypoints references missing file: {entrypoint}")

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
        if ok:
            print("validate_evidence_quality_manifest: OK")
        else:
            print("validate_evidence_quality_manifest: FAILED", file=sys.stderr)
            for err in errors:
                print(f"  - {err}", file=sys.stderr)

    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
