#!/usr/bin/env python3
"""Validate the conformity/ EU AI Act workflow bundle and its obligation cross-references.

Per docs/conformity/README.md: "assert workflow file presence and JSON
shape, cross-reference each control with a known AI Act obligation,
validate that Makefile and example wiring exist, and confirm that linked
regulatory references resolve." Does not change compliance verdict
semantics, Rust runtime enforcement, or database migrations.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BUNDLE_DIR = ROOT / "conformity"
MANIFEST_PATH = BUNDLE_DIR / "regulatory-workflow-manifest.json"
CONTROL_MAPPING_PATH = BUNDLE_DIR / "ai-act-control-mapping.json"
OBLIGATIONS_PATH = ROOT / "docs/regulatory/ai-act-obligations.json"

REQUIRED_MAKEFILE_TARGETS = ("conformity-workflow-check", "regulatory-workflow-check")


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

    for key in ("schema_version", "artifacts", "documentation_index", "example_paths", "regulatory_references"):
        if key not in manifest:
            errors.append(f"regulatory-workflow-manifest.json missing key: {key}")

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

    for rel_path in manifest.get("regulatory_references", []):
        if not (ROOT / rel_path).exists():
            errors.append(f"regulatory_references entry missing on disk: {rel_path}")

    # Cross-reference: every control in ai-act-control-mapping.json must cite a known obligation id,
    # and every supporting_artefact it names must exist on disk.
    if not CONTROL_MAPPING_PATH.exists():
        errors.append(f"missing: {CONTROL_MAPPING_PATH.relative_to(ROOT)}")
    elif not OBLIGATIONS_PATH.exists():
        errors.append(f"missing: {OBLIGATIONS_PATH.relative_to(ROOT)}")
    else:
        control_mapping = _load(CONTROL_MAPPING_PATH)
        obligations = _load(OBLIGATIONS_PATH)
        known_obligation_ids = {o.get("id") for o in obligations.get("obligations", [])}

        for control in control_mapping.get("controls", []):
            obligation_id = control.get("obligation_id")
            control_id = control.get("control_id", "<unknown>")
            if obligation_id not in known_obligation_ids:
                errors.append(
                    f"ai-act-control-mapping.json: control {control_id!r} cites unknown obligation_id {obligation_id!r}"
                )
            for artefact_path in control.get("supporting_artefacts", []):
                if not (ROOT / artefact_path).exists():
                    errors.append(
                        f"ai-act-control-mapping.json: control {control_id!r} supporting_artefacts "
                        f"entry missing on disk: {artefact_path}"
                    )

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
            print("conformity_workflow_check: OK")
        else:
            print("conformity_workflow_check: FAILED", file=sys.stderr)
            for err in errors:
                print(f"  - {err}", file=sys.stderr)

    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
