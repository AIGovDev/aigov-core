#!/usr/bin/env python3
"""Runs the full manuscript-evidence checklist: research package + research support checks.

This package is not legal advice and does not certify regulatory
compliance — see docs/research/README.md. Used by `make
manuscript-evidence-check`. Runs each sub-check as a subprocess (not an
in-process import) so each keeps its own clean argv/exit-code contract.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS_DIR = Path(__file__).resolve().parent

SUB_CHECKS = ("research_package_check.py", "research_support_check.py")


def run_check(script_name: str) -> dict:
    proc = subprocess.run(
        [sys.executable, str(SCRIPTS_DIR / script_name), "--json"],
        capture_output=True,
        text=True,
        cwd=ROOT,
        check=False,
    )
    try:
        payload = json.loads(proc.stdout.strip() or "{}")
    except json.JSONDecodeError:
        payload = {"ok": False, "errors": [f"non-JSON output: {proc.stdout!r} / stderr: {proc.stderr!r}"]}
    payload.setdefault("ok", proc.returncode == 0)
    payload["exit_code"] = proc.returncode
    return payload


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    results = {name: run_check(name) for name in SUB_CHECKS}
    ok = all(r["ok"] for r in results.values())

    if args.json:
        print(json.dumps({"ok": ok, "checks": results}, sort_keys=True))
    else:
        print(f"manuscript_evidence_runner: {'OK' if ok else 'FAILED'}")
        for name, r in results.items():
            print(f"  - {name}: {'OK' if r['ok'] else 'FAILED'}")
            for err in r.get("errors", []):
                print(f"      - {err}", file=sys.stderr)

    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
