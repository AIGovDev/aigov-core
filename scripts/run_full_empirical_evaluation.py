#!/usr/bin/env python3
"""Orchestrator: runs all six empirical benchmark scripts and writes a summary.

Writes benchmark-runs/latest/empirical-evaluation-summary.json. See
docs/research/empirical-evaluation.md and docs/research/performance-results.md.
"""

from __future__ import annotations

import importlib
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import empirical_benchmark_lib as lib

BENCHMARK_MODULES = (
    "run_event_ingestion_benchmarks",
    "run_hash_chain_benchmarks",
    "run_export_benchmarks",
    "run_storage_benchmarks",
    "run_multi_tenant_benchmarks",
    "run_failure_benchmarks",
)


def main() -> int:
    started_at = time.time()
    results = []
    ok = True

    for mod_name in BENCHMARK_MODULES:
        mod = importlib.import_module(mod_name)
        start = lib.timer()
        try:
            rc = mod.main()
        except Exception as e:  # noqa: BLE001 - orchestrator must report, not crash, on one benchmark failing
            rc = 1
            lib.eprint(f"{mod_name}: raised {e!r}")
        elapsed_s = lib.elapsed_ms(start) / 1000.0
        results.append({"benchmark": mod_name, "ok": rc == 0, "wall_seconds": round(elapsed_s, 3)})
        ok = ok and (rc == 0)

    summary = {
        "orchestrator": "run_full_empirical_evaluation",
        "ok": ok,
        "environment": lib.env_metadata(),
        "total_wall_seconds": round(time.time() - started_at, 3),
        "benchmarks": results,
    }
    path = lib.write_artifact("empirical-evaluation-summary.json", summary)
    print(json.dumps({"ok": ok, "artifact": str(path)}, sort_keys=True))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
