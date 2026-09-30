#!/usr/bin/env python3
"""Wiring + (if present) output-shape validation for the empirical benchmark suite.

Does NOT run the benchmarks itself — that's `make empirical-evaluation-run`
(run_full_empirical_evaluation.py). This check verifies every benchmark
script exists and is importable, and if benchmark-runs/latest/*.json
artifacts already exist from a prior run, validates their basic shape.
"""

from __future__ import annotations

import argparse
import importlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BENCHMARK_RUNS_DIR = ROOT / "benchmark-runs" / "latest"
sys.path.insert(0, str(Path(__file__).resolve().parent))

REQUIRED_MODULES = (
    "empirical_benchmark_lib",
    "run_event_ingestion_benchmarks",
    "run_hash_chain_benchmarks",
    "run_export_benchmarks",
    "run_storage_benchmarks",
    "run_multi_tenant_benchmarks",
    "run_failure_benchmarks",
    "run_full_empirical_evaluation",
)

EXPECTED_ARTIFACTS = (
    "event-ingestion-benchmarks.json",
    "hash-chain-benchmarks.json",
    "export-benchmarks.json",
    "storage-benchmarks.json",
    "multi-tenant-benchmarks.json",
    "failure-benchmarks.json",
    "empirical-evaluation-summary.json",
)


def validate() -> list[str]:
    errors: list[str] = []

    for mod_name in REQUIRED_MODULES:
        script_path = ROOT / "scripts" / f"{mod_name}.py"
        if not script_path.exists():
            errors.append(f"missing script: scripts/{mod_name}.py")
            continue
        try:
            importlib.import_module(mod_name)
        except Exception as e:  # noqa: BLE001
            errors.append(f"scripts/{mod_name}.py failed to import: {e!r}")

    if BENCHMARK_RUNS_DIR.exists():
        for name in EXPECTED_ARTIFACTS:
            path = BENCHMARK_RUNS_DIR / name
            if not path.exists():
                errors.append(f"benchmark-runs/latest/ exists but is missing: {name} (re-run make empirical-evaluation-run)")
                continue
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except json.JSONDecodeError as e:
                errors.append(f"benchmark-runs/latest/{name} is not valid JSON: {e}")
                continue
            if "environment" not in data:
                errors.append(f"benchmark-runs/latest/{name} missing 'environment' field")
    # No artifacts yet is fine — this check validates wiring, not that a run has happened.

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
            print("empirical_evaluation_check: OK")
        else:
            print("empirical_evaluation_check: FAILED", file=sys.stderr)
            for err in errors:
                print(f"  - {err}", file=sys.stderr)

    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
