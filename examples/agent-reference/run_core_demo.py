#!/usr/bin/env python3
"""Service-backed demonstration: every decision is made by a running AIGov Core.

Needs a Core that is already running (for example, from `service/start_local_core.py start`) and
its address and API key in the environment:

    export GOVAI_CORE_URL=http://127.0.0.1:18088
    export GOVAI_CORE_API_KEY=...
    python examples/agent-reference/run_core_demo.py [--cases 10]

Runs the service-backed scenarios and the service-backed benchmark. Writes results to
`results/core_scenarios.json` and `results/core_benchmark.json`. These results are separate from the
in-process results in `results/scenarios.json` and `results/benchmark.json`, and are not combined with them.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import warnings
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
warnings.filterwarnings("ignore", category=RuntimeWarning)

from aigov_agent_reference.core_benchmark import run_core_benchmark
from aigov_agent_reference.core_gate import CoreClient
from aigov_agent_reference.core_scenarios import run_all

RESULTS = HERE / "results"


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--cases", type=int, default=10, help="cases per category for the benchmark"
    )
    parser.add_argument("--scenarios-only", action="store_true")
    parser.add_argument(
        "--results-dir",
        type=Path,
        default=RESULTS,
        help="where to write results (CI writes to a temporary directory)",
    )
    args = parser.parse_args()
    results = args.results_dir

    url = os.environ.get("GOVAI_CORE_URL")
    key = os.environ.get("GOVAI_CORE_API_KEY")
    if not url or not key:
        raise SystemExit(
            "Set GOVAI_CORE_URL and GOVAI_CORE_API_KEY (see service/start_local_core.py)."
        )
    core = CoreClient(url, key)
    try:
        ok = core._get("/health")[0] == 200
    except OSError as exc:
        raise SystemExit(f"Core is not reachable at {url}: {exc}")
    if not ok:
        raise SystemExit(f"Core at {url} did not answer /health with 200")

    results.mkdir(parents=True, exist_ok=True)
    started = time.time()
    scenarios = run_all(core)
    print("\nService-backed scenarios (every decision from the running Core)\n")
    for r in scenarios:
        print(f"  [{'PASS' if r.passed else 'FAIL'}] {r.name}  {r.purpose}")
        for c in r.calls:
            ex = "executed" if c["executed"] else "not executed"
            print(
                f"         core: {c['label']:<34} {c['decision']:<16} {c['reason']:<26} {ex}"
            )
        for name, ok_, detail in r.checks:
            if not ok_:
                print(f"         FAILED CHECK: {name} {detail}")
        for problem in r.evidence_problems:
            print(f"         EVIDENCE PROBLEM: {problem}")
    passed = sum(1 for r in scenarios if r.passed)
    print(f"\n  {passed}/{len(scenarios)} scenarios passed.")
    (results / "core_scenarios.json").write_text(
        json.dumps(
            {
                "architecture": "service-backed (live AIGov Core over HTTP)",
                "core_url": url,
                "scenarios": [
                    {
                        "name": r.name,
                        "purpose": r.purpose,
                        "passed": r.passed,
                        "checks": [
                            {"name": n, "ok": o, "detail": d} for n, o, d in r.checks
                        ],
                        "calls": r.calls,
                        "core_chain_verifies": r.core_verify[0],
                        "core_verify_message": r.core_verify[1],
                        "core_event_types": r.core_event_types,
                        "evidence_problems": r.evidence_problems,
                        "sandbox": r.sandbox,
                    }
                    for r in scenarios
                ],
            },
            indent=2,
            sort_keys=True,
            default=str,
        )
        + "\n"
    )

    failed = [r.name for r in scenarios if not r.passed]
    if not args.scenarios_only:
        bench = run_core_benchmark(core, args.cases)
        s = bench["summary"]
        print("\nService-backed benchmark (every decision from the running Core)\n")
        print(
            f"  cases: {s['cases']}  calls: {s['calls']}  Core HTTP requests: {s['core_http_requests']}"
        )
        print(
            f"  unauthorized executed: {s['unauthorized_executed']}/{s['unauthorized_calls']}"
        )
        print(
            f"  authorized completed:  {s['authorized_completed']}/{s['authorized_calls']}  "
            f"false denials: {s['false_denials']}"
        )
        print(
            f"  consequential calls executed without approval: "
            f"{s['consequential_without_approval_executed']}/{s['consequential_without_approval']}"
        )
        print(f"  evidence verified: {s['evidence_verified_cases']}/{s['cases']} cases")
        lat = s["http_latency_ms"]["overall"]
        print(
            f"  Core HTTP latency (ms): p50 {lat['p50_ms']}  p95 {lat['p95_ms']}  p99 {lat['p99_ms']}"
        )
        (results / "core_benchmark.json").write_text(
            json.dumps(bench, indent=2, sort_keys=True) + "\n"
        )
    print(f"\nResults written to {results}\nElapsed: {time.time() - started:.1f}s")
    if failed:
        print("FAILED scenarios: " + ", ".join(failed))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
