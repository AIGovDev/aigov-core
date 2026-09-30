#!/usr/bin/env python3
"""Schema and path validation for docs/regulatory/regulatory-evidence-manifest.json."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = ROOT / "docs/regulatory/regulatory-evidence-manifest.json"

REQUIRED_KEYS = (
    "ai_act_mapping_scope",
    "evidence_themes",
    "non_goals",
    "obligations_index",
    "operational_probes",
    "referenced_documents",
    "referenced_examples",
    "required_checks",
    "summary",
    "version",
)


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def validate(manifest_path: Path) -> list[str]:
    errors: list[str] = []

    if not manifest_path.exists():
        return [f"missing: {manifest_path}"]

    manifest = _load(manifest_path)

    for key in REQUIRED_KEYS:
        if key not in manifest:
            errors.append(f"manifest missing key: {key}")

    obligations_index = manifest.get("obligations_index")
    if obligations_index and not (ROOT / obligations_index).exists():
        errors.append(f"obligations_index missing on disk: {obligations_index}")

    for entry in manifest.get("evidence_themes", []):
        guide = entry.get("guide")
        if guide and not (ROOT / guide).exists():
            errors.append(f"evidence_themes[{entry.get('id')}].guide missing on disk: {guide}")

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
            print("validate_regulatory_evidence_manifest: OK")
        else:
            print("validate_regulatory_evidence_manifest: FAILED", file=sys.stderr)
            for err in errors:
                print(f"  - {err}", file=sys.stderr)

    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
