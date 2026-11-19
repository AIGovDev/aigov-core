#!/usr/bin/env python3
"""
AIGov Real-Agent Benchmark using local Qwen2.5-3B-Instruct-4bit via MLX.

Each scenario is run against a real locally-executed Qwen model.
The external-state oracle is fully independent of:
  - the agent's self-report
  - the AIGov verifier (verify_evidence)

Usage:
    python run_qwen_benchmark.py [--smoke] [--seed 42] [--out results_qwen.json]

    --smoke   Run only the first 3 scenarios (fast validation)
    --seed N  Scenario dataset seed (default: 42)
    --out     Write full JSON results to file
"""

from __future__ import annotations

import argparse
import json
import math
import os
import platform
import subprocess
import sys
import time
import tracemalloc
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "python"))

from independent_benchmark import (
    Scenario,
    build_dataset,
    condition_a,
    condition_b,
    condition_c,
    condition_d,
    compute_metrics,
)
from mlx_qwen_adapter import ADAPTER_METADATA, AgentTrace, QwenAgent


# ---------------------------------------------------------------------------
# Scenario → SandboxToolExecutor state builder
# ---------------------------------------------------------------------------

def build_scenario_state(s: Scenario) -> dict[str, Any]:
    """
    Build honest, oracle-consistent tool state for one scenario.

    Tool responses reflect ACTUAL scenario state — independent of the agent's
    self-report (s.agent_reports_success) and the AIGov verifier.

    Key invariant: the agent CANNOT query the oracle (s.ground_truth) through
    tool responses.  Instead, tool state is derived from scenario parameters
    that describe the physical world state:
      - expected_hash_valid → audit record present and consistent
      - approval_identity_valid + approval_not_expired → approval valid
      - external_state_valid → external system confirms execution
    """
    approvals: dict[str, Any] = {}
    audit_records: dict[str, Any] = {}
    external_state: dict[str, Any] = {}

    # Build approvals table
    if s.approval_id != "MISSING":
        approvals[s.approval_id] = {
            "proposal_id": s.proposal_id,
            "approver": "compliance-officer@example.com" if s.approval_identity_valid else "unknown@external.invalid",
            "active": s.approval_not_expired,
        }

    # Build audit records table — only add record if hash is valid (record is real)
    if s.expected_hash_valid:
        audit_records[s.proposal_id] = {
            "executed_value": s.executed_value,
            "status": "completed",
            "hash_verified": True,
        }
    # Missing or tampered = no valid record

    # External state reflects whether execution actually changed state
    if s.external_state_valid:
        external_state["proc-2026-001"] = {
            "deadline": s.executed_value,
            "last_modified_by": s.proposal_id,
        }
    else:
        # State unchanged from baseline — does not reflect executed_value
        external_state["proc-2026-001"] = {
            "deadline": "2027-06-30T17:00:00+02:00",  # original value
            "last_modified_by": None,
        }

    return {
        "audit_records": audit_records,
        "approvals": approvals,
        "external_state": external_state,
    }


def build_scenario_summary(s: Scenario) -> dict[str, Any]:
    """
    Public scenario context passed to the agent prompt.
    Does NOT include oracle labels (ground_truth, expected_hash_valid, etc.).
    """
    return {
        "description": s.description,
        "proposal_id": s.proposal_id,
        "approval_id": s.approval_id,
        "executed_value": s.executed_value,
        "record_id": "proc-2026-001",
    }


# ---------------------------------------------------------------------------
# Confusion matrix and metrics
# ---------------------------------------------------------------------------

def compute_confusion(preds: list[bool | None], gts: list[bool]) -> dict[str, Any]:
    """TP/FP/TN/FN from lists (None = abstention = treated as False)."""
    tp = fp = tn = fn = abstain = 0
    for p, g in zip(preds, gts):
        if p is None:
            abstain += 1
            # Treat None as False for metric computation
            p = False
        if g and p:
            tp += 1
        elif not g and p:
            fp += 1
        elif not g and not p:
            tn += 1
        else:
            fn += 1
    n = len(preds)
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
    accuracy = (tp + tn) / n if n > 0 else 0.0
    far = fp / (fp + tn) if (fp + tn) > 0 else 0.0  # false acceptance rate
    frr = fn / (fn + tp) if (fn + tp) > 0 else 0.0  # false rejection rate

    # 95% CI for accuracy via normal approximation
    z = 1.96
    se = math.sqrt(accuracy * (1 - accuracy) / n) if n > 0 else 0.0
    ci_lo = max(0.0, accuracy - z * se)
    ci_hi = min(1.0, accuracy + z * se)

    return {
        "tp": tp, "fp": fp, "tn": tn, "fn": fn, "abstain": abstain,
        "n": n,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "accuracy": round(accuracy, 4),
        "accuracy_ci_95": [round(ci_lo, 4), round(ci_hi, 4)],
        "far": round(far, 4),
        "frr": round(frr, 4),
    }


# ---------------------------------------------------------------------------
# Main benchmark runner
# ---------------------------------------------------------------------------

def run_qwen_benchmark(
    seed: int = 42,
    smoke: bool = False,
    out_path: str | None = None,
) -> dict[str, Any]:

    dataset = build_dataset(seed=seed)
    if smoke:
        # Smoke test: first 3 scenarios (1 positive, 2 negatives)
        dataset = dataset[:3]

    n = len(dataset)
    print(f"\n{'='*60}")
    print(f"AIGov Real-Agent Benchmark — Qwen2.5-3B-Instruct-4bit via MLX")
    print(f"{'='*60}")
    print(f"Model:    {ADAPTER_METADATA['model_id']}")
    print(f"Scenarios: {n} (seed={seed}){' [SMOKE TEST]' if smoke else ''}")
    print(f"Platform: {platform.machine()} / {platform.system()} {platform.release()}")
    print()

    # Load model once
    t_load_start = time.perf_counter()
    print("Loading model...", flush=True)
    tracemalloc.start()
    agent = QwenAgent()
    load_ms = (time.perf_counter() - t_load_start) * 1000
    mem_after_load, _ = tracemalloc.get_traced_memory()
    print(f"Model loaded in {load_ms:.0f} ms\n")

    # --- Run real Qwen agent on each scenario ---
    print("Running real-agent evaluation (Qwen)...")
    traces: list[AgentTrace] = []
    agent_preds: list[bool | None] = []
    t_agent_start = time.perf_counter()

    for i, s in enumerate(dataset):
        print(f"  [{i+1:2d}/{n}] {s.scenario_id}", end=" ", flush=True)
        summary = build_scenario_summary(s)
        state = build_scenario_state(s)
        trace = agent.run(s.scenario_id, summary, state)
        traces.append(trace)
        agent_preds.append(trace.verdict)

        status = "✓" if trace.verdict == s.ground_truth else "✗"
        blocked = " [PARSE_ERROR]" if trace.parse_error else ""
        print(
            f"pred={trace.verdict!s:5} gt={s.ground_truth!s:5} {status} "
            f"({trace.total_ms:.0f}ms){blocked}"
        )

    agent_total_ms = (time.perf_counter() - t_agent_start) * 1000
    mem_peak, _ = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    # --- Scripted baselines (conditions A, B, C, D) ---
    print("\nScripted baselines:")
    baseline_results: dict[str, Any] = {}
    for cond_name, cond_fn in [
        ("A_self_report", condition_a),
        ("B_tool_response", condition_b),
        ("C_external_state", condition_c),
        ("D_aigov_evidence", condition_d),
    ]:
        t0 = time.perf_counter()
        preds = [cond_fn(s) for s in dataset]
        elapsed_ms = (time.perf_counter() - t0) * 1000
        m = compute_metrics(preds, [s.ground_truth for s in dataset])
        m["latency_ms"] = round(elapsed_ms, 1)
        baseline_results[cond_name] = m
        print(
            f"  {cond_name:20s}: F1={m['f1']:.3f}  FAR={m['far']:.3f}  "
            f"Acc={m['accuracy']:.3f} [{m['accuracy_ci_95'][0]:.3f},{m['accuracy_ci_95'][1]:.3f}]"
        )

    # --- Qwen agent metrics ---
    gts = [s.ground_truth for s in dataset]
    qwen_metrics = compute_confusion(agent_preds, gts)
    qwen_metrics["total_ms"] = round(agent_total_ms, 1)
    qwen_metrics["load_ms"] = round(load_ms, 1)
    qwen_metrics["avg_inference_ms"] = round(
        sum(t.inference_ms for t in traces) / n if n > 0 else 0, 1
    )
    qwen_metrics["n_parse_errors"] = sum(1 for t in traces if t.parse_error)
    qwen_metrics["n_tool_calls"] = sum(len(t.tool_calls) for t in traces)
    qwen_metrics["peak_memory_mb"] = round(mem_peak / 1024 / 1024, 1)

    # Verdict source breakdown: model_tool / prose_parse / fallback
    n_model_tool = sum(1 for t in traces if t.verdict_source == "model_tool")
    n_prose = sum(1 for t in traces if t.verdict_source == "prose_parse")
    n_fallback = sum(1 for t in traces if t.verdict_source == "fallback")
    qwen_metrics["verdict_source_counts"] = {
        "model_tool": n_model_tool,
        "prose_parse": n_prose,
        "fallback": n_fallback,
    }

    # Separate accuracy for model-generated vs fallback verdicts
    model_preds = [(t.verdict, s.ground_truth) for t, s in zip(traces, dataset)
                   if t.verdict_source in ("model_tool", "prose_parse")]
    fallback_preds = [(t.verdict, s.ground_truth) for t, s in zip(traces, dataset)
                      if t.verdict_source == "fallback"]
    if model_preds:
        mp, mg = zip(*model_preds)
        model_m = compute_confusion(list(mp), list(mg))
        qwen_metrics["model_generated_metrics"] = model_m
    if fallback_preds:
        fp_v, fg = zip(*fallback_preds)
        fb_m = compute_confusion(list(fp_v), list(fg))
        qwen_metrics["fallback_metrics"] = fb_m

    print(f"\nQwen agent (Condition E — real local model):")
    print(
        f"  F1={qwen_metrics['f1']:.3f}  FAR={qwen_metrics['far']:.3f}  "
        f"Acc={qwen_metrics['accuracy']:.3f} "
        f"[{qwen_metrics['accuracy_ci_95'][0]:.3f},{qwen_metrics['accuracy_ci_95'][1]:.3f}]  "
        f"n_tool_calls={qwen_metrics['n_tool_calls']}  "
        f"parse_errors={qwen_metrics['n_parse_errors']}"
    )
    print(f"  Verdict sources: model_tool={n_model_tool} prose_parse={n_prose} fallback={n_fallback}")
    print(f"  Total inference: {qwen_metrics['total_ms']:.0f} ms "
          f"| avg per scenario: {qwen_metrics['avg_inference_ms']:.0f} ms")
    print(f"  Peak memory (traced): {qwen_metrics['peak_memory_mb']:.1f} MB")

    # --- Failure analysis ---
    failures = []
    for trace, s in zip(traces, dataset):
        if trace.verdict != s.ground_truth:
            failures.append({
                "scenario_id": s.scenario_id,
                "ground_truth": s.ground_truth,
                "predicted": trace.verdict,
                "tags": s.tags,
                "parse_error": trace.parse_error,
                "n_tool_calls": len(trace.tool_calls),
            })

    if failures:
        print(f"\nFailures ({len(failures)}):")
        for f in failures:
            print(f"  {f['scenario_id']}: gt={f['ground_truth']} pred={f['predicted']} "
                  f"tags={f['tags']} parse_err={'yes' if f['parse_error'] else 'no'}")

    # --- Git metadata ---
    git_sha = "unknown"
    try:
        git_sha = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=REPO_ROOT, stderr=subprocess.DEVNULL
        ).decode().strip()
    except Exception:
        pass

    # --- Full report ---
    report: dict[str, Any] = {
        "run_id": f"aigov-qwen-benchmark-{seed}-{int(time.time())}",
        "git_sha": git_sha,
        "seed": seed,
        "smoke_test": smoke,
        "n_scenarios": n,
        "n_positive": sum(1 for s in dataset if s.ground_truth),
        "n_negative": sum(1 for s in dataset if not s.ground_truth),
        "model": {
            **ADAPTER_METADATA,
            "load_ms": round(load_ms, 1),
        },
        "conditions": {
            **baseline_results,
            "E_qwen_local": qwen_metrics,
        },
        "failures": failures,
        "traces": [
            {
                "scenario_id": t.scenario_id,
                "verdict": t.verdict,
                "verdict_source": t.verdict_source,
                "ground_truth": s.ground_truth,
                "correct": t.verdict == s.ground_truth,
                "n_tool_calls": len(t.tool_calls),
                "tool_calls": [
                    {"name": tc.name, "result": tc.result, "error": tc.error}
                    for tc in t.tool_calls
                ],
                "parse_error": t.parse_error,
                "inference_ms": round(t.inference_ms, 1),
                "total_ms": round(t.total_ms, 1),
            }
            for t, s in zip(traces, dataset)
        ],
    }

    if out_path:
        Path(out_path).write_text(json.dumps(report, indent=2))
        print(f"\nResults written to {out_path}")

    return report


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--smoke", action="store_true", help="Run only 3 scenarios")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--out", default=None, help="JSON output path")
    args = parser.parse_args()

    report = run_qwen_benchmark(seed=args.seed, smoke=args.smoke, out_path=args.out)

    print(f"\n{'='*60}")
    print("BENCHMARK COMPLETE")
    print(f"  Real-agent (Qwen E_local): F1={report['conditions']['E_qwen_local']['f1']:.3f}")
    print(f"  Scripted baseline (D AIGov): F1={report['conditions']['D_aigov_evidence']['f1']:.3f}")
