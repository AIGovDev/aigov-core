#!/usr/bin/env python3
"""Schema and reference-path validation for docs/observability/observability-manifest.json."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = ROOT / "docs/observability/observability-manifest.json"

REQUIRED_TOP_LEVEL_KEYS = (
    "boundaries",
    "evidence_flow_signals",
    "non_goals",
    "operational_probes",
    "readiness_signals",
    "referenced_documents",
    "referenced_examples",
    "required_checks",
    "runtime_health_signals",
    "score_weights",
    "snapshot_schema",
    "summary",
    "version",
)

REQUIRED_WEIGHT_KEYS = ("diagnostics", "evidence_flow", "readiness", "runtime_health")


def _load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def validate(manifest_path: Path) -> list[str]:
    errors: list[str] = []

    if not manifest_path.exists():
        return [f"missing manifest: {manifest_path.relative_to(ROOT)}"]

    manifest = _load(manifest_path)

    for key in REQUIRED_TOP_LEVEL_KEYS:
        if key not in manifest:
            errors.append(f"missing top-level key: {key}")

    weights = manifest.get("score_weights", {})
    for key in REQUIRED_WEIGHT_KEYS:
        if key not in weights:
            errors.append(f"score_weights missing key: {key}")
    total_weight = sum(v for v in weights.values() if isinstance(v, (int, float)))
    if weights and total_weight != 100:
        errors.append(f"score_weights must sum to 100 (got {total_weight})")

    for entry_list, label in (
        (manifest.get("referenced_documents", []), "referenced_documents"),
        (manifest.get("referenced_examples", []), "referenced_examples"),
    ):
        for entry in entry_list:
            rel_path = entry.get("path") if isinstance(entry, dict) else None
            if not rel_path:
                errors.append(f"{label} entry missing 'path': {entry!r}")
                continue
            if not (ROOT / rel_path).exists():
                errors.append(f"{label} references missing file: {rel_path}")

    schema = manifest.get("snapshot_schema", {})
    if "required_keys" not in schema or "required_collections" not in schema:
        errors.append("snapshot_schema must define required_keys and required_collections")

    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=MANIFEST_PATH)
    parser.add_argument("--json", action="store_true", help="emit a single JSON object on stdout")
    args = parser.parse_args()

    errors = validate(args.manifest)
    ok = not errors

    if args.json:
        print(json.dumps({"ok": ok, "manifest": str(args.manifest), "errors": errors}, sort_keys=True))
    else:
        if ok:
            print("validate_observability_manifest: OK")
        else:
            print("validate_observability_manifest: FAILED", file=sys.stderr)
            for err in errors:
                print(f"  - {err}", file=sys.stderr)

    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
