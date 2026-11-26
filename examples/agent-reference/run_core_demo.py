#!/usr/bin/env python3
"""Trusted-execution demonstration against a running AIGov Core.

Needs a Core started with the trusted-execution configuration (``service/start_local_core.py start`` or
``service/start_core_binary.py``). The identities and keys are read from the state file that the launcher writes:

    export GOVAI_CORE_URL=http://127.0.0.1:18088
    export GOVAI_TRUST_STATE=~/.cache/aigov-agent-reference/state.json
    python examples/agent-reference/run_core_demo.py [--cases 10]

Runs the trusted scenarios (separate agent, approver, and executor identities; Core issues authorizations; the executor
verifies them before any side effect) and the trusted benchmark. Writes ``results/trusted_scenarios.json`` and
``results/trusted_benchmark.json``. These results are separate from the in-process results and are not combined with
them.
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

from aigov_agent_reference.core_gate import CoreClient
from aigov_agent_reference.core_trusted import load_state
from aigov_agent_reference.trusted_benchmark import run_trusted_benchmark
from aigov_agent_reference.trusted_scenarios import run_all

RESULTS = HERE / "results"
DEFAULT_STATE = Path.home() / ".cache" / "aigov-agent-reference" / "state.json"


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--cases", type=int, default=10, help="cases per category for the benchmark"
    )
    parser.add_argument("--scenarios-only", action="store_true")
    parser.add_argument("--results-dir", type=Path, default=RESULTS)
    parser.add_argument(
        "--state",
        type=Path,
        default=Path(os.environ.get("GOVAI_TRUST_STATE", DEFAULT_STATE)),
    )
    parser.add_argument(
        "--workdir", type=Path, default=None, help="where executor stores are kept"
    )
    args = parser.parse_args()

    state = load_state(args.state)
    url = state["core_url"]
    if not CoreClient(url, state["keys"]["agent"]).health():
        raise SystemExit(f"Core at {url} is not answering /health")

    results = args.results_dir
    results.mkdir(parents=True, exist_ok=True)
    workdir = (
        args.workdir
        or Path(os.environ.get("TMPDIR", "/tmp")) / f"aigov-trusted-{int(time.time())}"
    )
    started = time.time()
    scenarios = run_all(url, state, workdir)
    print(
        "\nTrusted-execution scenarios (agent, approver, and executor are separate identities)\n"
    )
    for r in scenarios:
        print(f"  [{'PASS' if r.passed else 'FAIL'}] {r.name}  {r.purpose}")
        for c in r.calls:
            ex = "executed" if c["executed"] else "not executed"
            print(
                f"         {c['label']:<34} {c['decision']:<16} {c['reason']:<30} {ex}"
            )
        for name, ok_, detail in r.checks:
            if not ok_:
                print(f"         FAILED CHECK: {name} {detail}")
        for problem in r.evidence_problems:
            print(f"         EVIDENCE PROBLEM: {problem}")
    passed = sum(1 for r in scenarios if r.passed)
    print(f"\n  {passed}/{len(scenarios)} scenarios passed.")
    (results / "trusted_scenarios.json").write_text(
        json.dumps(
            {
                "architecture": "trusted execution (live AIGov Core decides; separate executor performs side effects)",
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
        bench = run_trusted_benchmark(url, state, args.cases, workdir)
        s = bench["summary"]
        print("\nTrusted-execution benchmark (deterministic; scripted agent)\n")
        print(
            f"  cases: {s['cases']}  calls: {s['calls']}  Core HTTP requests: {s['core_http_latency_ms']['overall']['count']}"
        )
        print(
            f"  unauthorized executed: {s['unauthorized_executed']}/{s['unauthorized_calls']}"
        )
        print(
            f"  authorized completed:  {s['authorized_completed']}/{s['authorized_calls']}  false denials: {s['false_denials']}"
        )
        print(
            f"  consequential calls executed without approval: "
            f"{s['consequential_without_approval_executed']}/{s['consequential_without_approval']}"
        )
        print(f"  evidence verified: {s['evidence_verified_cases']}/{s['cases']} cases")
        for label, key in [
            ("authorization", "authorization_latency_ms"),
            ("executor verification", "executor_verification_latency_ms"),
            ("end-to-end", "end_to_end_latency_ms"),
        ]:
            b = s[key]
            print(
                f"  {label} latency (ms): p50 {b['p50_ms']}  p95 {b['p95_ms']}  p99 {b['p99_ms']}  (n={b['count']})"
            )
        (results / "trusted_benchmark.json").write_text(
            json.dumps(bench, indent=2, sort_keys=True, default=str) + "\n"
        )
    print(f"\nResults written to {results}\nElapsed: {time.time() - started:.1f}s")
    if failed:
        print("FAILED scenarios: " + ", ".join(failed))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
