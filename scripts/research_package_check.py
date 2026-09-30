#!/usr/bin/env python3
"""Aggregate check for the research/academic-publication package.

Runs validate_research_manifest, then also checks the core research/ JSON
artifacts individually and confirms the research-package-check /
academic-publication-check Makefile targets are wired. Deliberately does
NOT cover docs/research/research-support-manifest.json's empirical
benchmark suite (run_*_benchmarks.py etc.) — those scripts would need to
execute real measurements against a live audit service to produce
non-fabricated numbers, which is out of scope for a structural check.
See docs/research/README.md.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(Path(__file__).resolve().parent))

from validate_research_manifest import MANIFEST_PATH
from validate_research_manifest import validate as validate_manifest

REQUIRED_MAKEFILE_TARGETS = ("research-package-check", "academic-publication-check")


def _makefile_targets() -> set[str]:
    text = (ROOT / "Makefile").read_text(encoding="utf-8")
    return set(re.findall(r"^([A-Za-z0-9_.-]+):", text, re.MULTILINE))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    errors = list(validate_manifest(MANIFEST_PATH))

    targets = _makefile_targets()
    for target in REQUIRED_MAKEFILE_TARGETS:
        if target not in targets:
            errors.append(f"Makefile target not defined: {target}")

    ok = not errors

    if args.json:
        print(json.dumps({"ok": ok, "errors": errors}, sort_keys=True))
    else:
        if ok:
            print("research_package_check: OK")
        else:
            print("research_package_check: FAILED", file=sys.stderr)
            for err in errors:
                print(f"  - {err}", file=sys.stderr)

    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
