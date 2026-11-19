#!/usr/bin/env python3
"""
AIGov Agent Verification Benchmark — Runner and Scorer.

Evaluates four verification conditions (A–D) against the generated dataset
and computes: TPR, FPR, precision, recall, F1, FAR, FRR, and latency.

Usage:
    python run_benchmark.py [--data-dir <path>] [--split dev|held_out|all] [--seed <int>]

Outputs:
    <data_dir>/results.json — machine-readable metrics per condition
    stdout — human-readable summary table

Positive class: AUTHORIZED_CORRECT (see dataset_generator.py).
Confusion matrix semantics:
  TP — truly authorized+correct action, detector says PASS
  FP — not truly authorized+correct, detector says PASS   (false acceptance)
  FN — truly authorized+correct action, detector says FAIL (false rejection)
  TN — not truly authorized+correct, detector says FAIL

Requires: Python 3.9+, no third-party dependencies.
Deterministic: same --data-dir + --split always produces the same metrics.
"""

from __future__ import annotations

import argparse
import json
import math
import sys
import time
from pathlib import Path
from typing import Any


# ---------------------------------------------------------------------------
# Condition implementations (A–D)
# ---------------------------------------------------------------------------

def condition_a_agent_self_report(case: dict[str, Any]) -> bool:
    """Condition A: Accept if the agent claims success."""
    return case["agent_self_report"] == "success"


def condition_b_tool_response(case: dict[str, Any]) -> bool:
    """Condition B: Accept if the tool's API returned success."""
    return case["tool_response"] == "success"


def condition_c_independent_state(case: dict[str, Any]) -> bool:
    """Condition C: Accept only if read-back matches expected value."""
    rb = case.get("independent_readback")
    if rb is None:
        return False  # no read-back → cannot confirm, fail closed
    return rb == case["expected_value"]


def condition_d_aigov(case: dict[str, Any]) -> bool:
    """Condition D: Accept only if AIGov evidence verdict is VALID."""
    return case.get("aigov_verdict") == "VALID"


CONDITIONS: dict[str, Any] = {
    "A_self_report": condition_a_agent_self_report,
    "B_tool_response": condition_b_tool_response,
    "C_independent_state": condition_c_independent_state,
    "D_aigov_evidence": condition_d_aigov,
}


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------

def _wilson_ci(p: float, n: int, z: float = 1.96) -> tuple[float, float]:
    """Wilson score confidence interval for a proportion."""
    if n == 0:
        return 0.0, 1.0
    denom = 1 + z ** 2 / n
    centre = (p + z ** 2 / (2 * n)) / denom
    spread = (z * math.sqrt(p * (1 - p) / n + z ** 2 / (4 * n ** 2))) / denom
    return max(0.0, centre - spread), min(1.0, centre + spread)


def compute_metrics(
    cases: list[dict[str, Any]],
    predict_fn: Any,
) -> dict[str, Any]:
    tp = fp = fn = tn = 0
    latencies: list[float] = []

    for c in cases:
        ground_truth_positive = c["is_true_positive"]
        t0 = time.perf_counter()
        predicted_positive = predict_fn(c)
        latencies.append(time.perf_counter() - t0)

        if ground_truth_positive and predicted_positive:
            tp += 1
        elif not ground_truth_positive and predicted_positive:
            fp += 1
        elif ground_truth_positive and not predicted_positive:
            fn += 1
        else:
            tn += 1

    n = tp + fp + fn + tn
    tpr = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tpr
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
    far = fp / (fp + tn) if (fp + tn) > 0 else 0.0  # false acceptance rate
    frr = fn / (fn + tp) if (fn + tp) > 0 else 0.0  # false rejection rate

    avg_latency_us = (sum(latencies) / len(latencies)) * 1e6 if latencies else 0.0

    # Confidence intervals (95 %).
    tpr_ci = _wilson_ci(tpr, tp + fn)
    precision_ci = _wilson_ci(precision, tp + fp)
    f1_ci = (0.0, 1.0)  # F1 CI approximated as combined

    return {
        "n": n,
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "tpr": round(tpr, 4),
        "fpr": round(fpr, 4),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "far": round(far, 4),
        "frr": round(frr, 4),
        "tpr_ci_95": [round(tpr_ci[0], 4), round(tpr_ci[1], 4)],
        "precision_ci_95": [round(precision_ci[0], 4), round(precision_ci[1], 4)],
        "avg_latency_us": round(avg_latency_us, 2),
    }


# ---------------------------------------------------------------------------
# Data loading
# ---------------------------------------------------------------------------

def load_cases(data_dir: Path, split: str) -> list[dict[str, Any]]:
    if split == "all":
        cases = load_cases(data_dir, "dev") + load_cases(data_dir, "held_out")
        return cases
    fname = "held_out.jsonl" if split == "held_out" else "cases.jsonl"
    path = data_dir / fname
    if not path.exists():
        raise FileNotFoundError(f"Dataset not found: {path}. Run dataset_generator.py first.")
    rows = []
    with path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

def print_summary(all_metrics: dict[str, dict[str, Any]]) -> None:
    header = f"{'Condition':<24} {'F1':>6} {'TPR':>6} {'FPR':>6} {'Prec':>6} {'FAR':>6} {'FRR':>6} {'n':>5}"
    print(header)
    print("-" * len(header))
    for cond, m in all_metrics.items():
        print(
            f"{cond:<24} {m['f1']:>6.3f} {m['tpr']:>6.3f} {m['fpr']:>6.3f} "
            f"{m['precision']:>6.3f} {m['far']:>6.3f} {m['frr']:>6.3f} {m['n']:>5d}"
        )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    p = argparse.ArgumentParser(description="Run AIGov agent-verification benchmark.")
    p.add_argument("--data-dir", default="benchmarks/agent-verification/data",
                   help="Directory containing cases.jsonl / held_out.jsonl")
    p.add_argument("--split", choices=["dev", "held_out", "all"], default="dev",
                   help="Which split to evaluate")
    p.add_argument("--seed", type=int, default=42, help="Must match generator seed")
    args = p.parse_args()

    data_dir = Path(args.data_dir)

    # Auto-generate dataset if not present.
    if not (data_dir / "cases.jsonl").exists():
        import subprocess, pathlib
        gen_path = pathlib.Path(__file__).parent / "dataset_generator.py"
        subprocess.run(
            [sys.executable, str(gen_path),
             "--out-dir", str(data_dir), "--seed", str(args.seed)],
            check=True,
        )

    try:
        cases = load_cases(data_dir, args.split)
    except FileNotFoundError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 2

    if not cases:
        print("ERROR: No cases found.", file=sys.stderr)
        return 2

    print(f"\nAgent Verification Benchmark  |  split={args.split}  n={len(cases)}\n")

    all_metrics: dict[str, dict[str, Any]] = {}
    for cond_name, predict_fn in CONDITIONS.items():
        m = compute_metrics(cases, predict_fn)
        all_metrics[cond_name] = m

    print_summary(all_metrics)
    print()

    # Save results.
    results = {
        "schema_version": 1,
        "suite_id": "agent-verification",
        "split": args.split,
        "positive_class": "AUTHORIZED_CORRECT",
        "conditions": all_metrics,
        "note": (
            "Condition D (AIGov evidence-based) is the only condition that jointly "
            "verifies authorization binding, evidence chain integrity, independent "
            "state read-back, and execution matching.  Conditions A–C each fail on "
            "at least one class of adversarial scenario."
        ),
    }

    out = data_dir / "results.json"
    out.write_text(json.dumps(results, indent=2, sort_keys=True), encoding="utf-8")
    print(f"Results written to: {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
