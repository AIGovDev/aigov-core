#!/usr/bin/env python3
"""Structural validation for research/research-manifest.json.

Checks required top-level keys and that every path the manifest points at
(research_artifacts, documentation_paths, example_paths, research_readme_path)
actually exists on disk. See docs/research/README.md.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = ROOT / "research/research-manifest.json"

REQUIRED_KEYS = (
    "manifest_artifact_id",
    "package_id",
    "package_version",
    "schema_version",
    "research_artifacts",
    "research_readme_path",
    "documentation_paths",
    "example_paths",
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
            errors.append(f"research-manifest.json missing key: {key}")

    readme_path = manifest.get("research_readme_path")
    if readme_path and not (ROOT / readme_path).exists():
        errors.append(f"research_readme_path missing on disk: {readme_path}")

    for artefact_key, rel_path in manifest.get("research_artifacts", {}).items():
        path = ROOT / rel_path
        if not path.exists():
            errors.append(f"research_artifacts.{artefact_key} missing on disk: {rel_path}")
            continue
        try:
            _load(path)
        except json.JSONDecodeError as e:
            errors.append(f"research_artifacts.{artefact_key} ({rel_path}) is not valid JSON: {e}")

    for rel_path in manifest.get("documentation_paths", []):
        if not (ROOT / rel_path).exists():
            errors.append(f"documentation_paths entry missing on disk: {rel_path}")

    for rel_path in manifest.get("example_paths", []):
        if not (ROOT / rel_path).exists():
            errors.append(f"example_paths entry missing on disk: {rel_path}")

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
            print("validate_research_manifest: OK")
        else:
            print("validate_research_manifest: FAILED", file=sys.stderr)
            for err in errors:
                print(f"  - {err}", file=sys.stderr)

    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
