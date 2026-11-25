#!/usr/bin/env python3
"""Single-command demonstration of the AIGov reference integration.

Runs a real smolagents agent through ten scenarios against the gate, checks sandbox state
after each run, verifies the decision log, and then runs the enforcement benchmark. Writes
machine-readable results to ``results/``.

Usage (from the repository root):
    python examples/agent-reference/run_demo.py                 # scenarios + full benchmark
    python examples/agent-reference/run_demo.py --scenarios-only
    python examples/agent-reference/run_demo.py --cases 20      # smaller benchmark

Needs only the packages in the repository's Python environment plus ``smolagents``. No
network access and no paid API.
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
import time
import warnings
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
warnings.filterwarnings("ignore", category=RuntimeWarning, module="key_provider")
warnings.filterwarnings("ignore", message=".*unmanaged.*")

from aigov_agent_reference.benchmark import run_benchmark
from aigov_agent_reference.scenarios import run_all

RESULTS = HERE / "results"


def print_scenarios(results) -> None:
    print(
        "\nScenarios (real smolagents ToolCallingAgent; gate decisions; sandbox state checked)\n"
    )
    width = max(len(r.name) for r in results)
    for r in results:
        status = "PASS" if r.passed else "FAIL"
        print(f"  [{status}] {r.name:<{width}}  {r.purpose}")
        for d in r.decisions:
            executed = "executed" if d["executed"] else "not executed"
            print(
                f"         gate: {d['tool']:<22} {d['decision']:<16} {d['reason']:<32} {executed}"
            )
        failed = [(n, d) for n, ok, d in r.checks if not ok]
        for name, detail in failed:
            print(f"         FAILED CHECK: {name} {detail}")
    passed = sum(1 for r in results if r.passed)
    print(f"\n  {passed}/{len(results)} scenarios passed.")


def print_benchmark(bench: dict) -> None:
    print(
        "\nBenchmark (same agent, same workload; only the enforcement layer differs)\n"
    )
    print(
        f"  dataset digest: {bench['dataset']['digest_sha256'][:16]}...  "
        f"cases per category: {bench['dataset']['cases_per_category']}  "
        f"model: {bench['model']}\n"
    )
    head = (
        f"  {'condition':<22}{'unauth exec':>14}{'auth completed':>18}{'false denials':>16}"
        f"{'approval enforced':>20}{'evidence ok':>14}{'gate p50 ms':>14}"
    )
    print(head)
    for name, m in bench["conditions"].items():

        def pct(v):
            return "n/a" if v is None else f"{v * 100:.1f}%"

        lat = m["gate_latency_ms"]
        p50 = "n/a" if lat is None else f"{lat['median']:.2f}"
        print(
            f"  {name:<22}"
            f"{m['unauthorized_executed']:>5}/{m['unauthorized_calls']:<7}"
            f"{m['authorized_completed']:>7}/{m['authorized_calls']:<9}"
            f"{m['false_denials']:>6}/{m['authorized_calls']:<7}"
            f"{pct(m['approval_enforcement_rate']):>20}"
            f"{pct(m['evidence_verification_rate']):>14}"
            f"{p50:>14}"
        )
    print(
        "\n  Deterministic scripted agent. Enforcement measurements only; no model-based experiment."
    )


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--scenarios-only", action="store_true", help="skip the benchmark"
    )
    parser.add_argument(
        "--cases", type=int, default=100, help="cases per category for the benchmark"
    )
    args = parser.parse_args()

    RESULTS.mkdir(parents=True, exist_ok=True)
    started = time.time()
    work = Path(tempfile.mkdtemp(prefix="aigov-ref-demo-"))

    scenarios = run_all(work / "scenarios")
    print_scenarios(scenarios)
    scenario_json = {
        "scenarios": [
            {
                "name": r.name,
                "purpose": r.purpose,
                "passed": r.passed,
                "checks": [{"name": n, "ok": ok, "detail": d} for n, ok, d in r.checks],
                "decisions": r.decisions,
                "evidence_ok": r.evidence_ok,
                "evidence_problems": r.evidence_problems,
                "sandbox_state": r.state,
            }
            for r in scenarios
        ]
    }
    (RESULTS / "scenarios.json").write_text(
        json.dumps(scenario_json, indent=2, sort_keys=True, default=str) + "\n"
    )

    failed = [r.name for r in scenarios if not r.passed]
    if not args.scenarios_only:
        bench = run_benchmark(args.cases, root=work / "benchmark")
        print_benchmark(bench)
        (RESULTS / "benchmark.json").write_text(
            json.dumps(bench, indent=2, sort_keys=True) + "\n"
        )

    print(
        f"\nResults written to {RESULTS.relative_to(Path.cwd()) if RESULTS.is_relative_to(Path.cwd()) else RESULTS}"
    )
    print(f"Elapsed: {time.time() - started:.1f}s")
    if failed:
        print(f"\nFAILED scenarios: {', '.join(failed)}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
