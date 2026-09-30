#!/usr/bin/env python3
"""Aggregated regulatory-evidence diagnostics: manifest + obligations + Makefile wiring.

Per docs/regulatory/regulatory-evidence-manifest.json's own operational_probes
entry: "Aggregated diagnostics (score, checks, failures, warnings, checked_paths)."
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(Path(__file__).resolve().parent))

from validate_ai_act_obligations import OBLIGATIONS_PATH
from validate_ai_act_obligations import validate as validate_obligations
from validate_regulatory_evidence_manifest import MANIFEST_PATH
from validate_regulatory_evidence_manifest import validate as validate_manifest

REQUIRED_MAKEFILE_TARGETS = (
    "regulatory-manifest",
    "ai-act-obligations",
    "regulatory-evidence",
    "regulatory-export",
    "regulatory-check",
)


def _makefile_targets() -> set[str]:
    text = (ROOT / "Makefile").read_text(encoding="utf-8")
    return set(re.findall(r"^([A-Za-z0-9_.-]+):", text, re.MULTILINE))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    checks: list[dict] = []

    manifest_errors = validate_manifest(MANIFEST_PATH)
    checks.append({"name": "regulatory_evidence_manifest", "ok": not manifest_errors, "failures": manifest_errors})

    obligations_errors = validate_obligations(OBLIGATIONS_PATH)
    checks.append({"name": "ai_act_obligations", "ok": not obligations_errors, "failures": obligations_errors})

    targets = _makefile_targets()
    makefile_failures = [f"Makefile target not defined: {t}" for t in REQUIRED_MAKEFILE_TARGETS if t not in targets]
    checks.append({"name": "makefile_wiring", "ok": not makefile_failures, "failures": makefile_failures})

    checked_paths = [str(MANIFEST_PATH.relative_to(ROOT)), str(OBLIGATIONS_PATH.relative_to(ROOT)), "Makefile"]

    failures = [f for c in checks for f in c["failures"]]
    passed = sum(1 for c in checks if c["ok"])
    score = round((passed / len(checks)) * 100) if checks else 0
    ok = not failures

    result = {
        "ok": ok,
        "score": score,
        "checks": checks,
        "failures": failures,
        "warnings": [],
        "checked_paths": checked_paths,
    }

    if args.json:
        print(json.dumps(result, sort_keys=True))
    else:
        if ok:
            print(f"regulatory_evidence_check: OK (score={score})")
        else:
            print(f"regulatory_evidence_check: FAILED (score={score})", file=sys.stderr)
            for f in failures:
                print(f"  - {f}", file=sys.stderr)

    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
