#!/usr/bin/env python3
"""Aggregate check for the evidence-quality package: manifest, sample snapshot, Makefile wiring."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(Path(__file__).resolve().parent))

from validate_dataset_provenance_snapshot import (
    DEFAULT_INPUT as SAMPLE_SNAPSHOT,
)
from validate_dataset_provenance_snapshot import validate as validate_snapshot
from validate_evidence_quality_manifest import MANIFEST_PATH
from validate_evidence_quality_manifest import validate as validate_manifest

REQUIRED_MAKEFILE_TARGETS = ("evidence-quality-check",)


def _makefile_targets() -> set[str]:
    text = (ROOT / "Makefile").read_text(encoding="utf-8")
    return set(re.findall(r"^([A-Za-z0-9_.-]+):", text, re.MULTILINE))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    errors = list(validate_manifest(MANIFEST_PATH))

    if not SAMPLE_SNAPSHOT.exists():
        errors.append(f"missing: {SAMPLE_SNAPSHOT.relative_to(ROOT)}")
    else:
        snapshot = json.loads(SAMPLE_SNAPSHOT.read_text(encoding="utf-8"))
        errors.extend(f"sample snapshot: {e}" for e in validate_snapshot(snapshot))

    targets = _makefile_targets()
    for target in REQUIRED_MAKEFILE_TARGETS:
        if target not in targets:
            errors.append(f"Makefile target not defined: {target}")

    ok = not errors

    if args.json:
        print(json.dumps({"ok": ok, "errors": errors}, sort_keys=True))
    else:
        if ok:
            print("evidence_quality_check: OK")
        else:
            print("evidence_quality_check: FAILED", file=sys.stderr)
            for err in errors:
                print(f"  - {err}", file=sys.stderr)

    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
