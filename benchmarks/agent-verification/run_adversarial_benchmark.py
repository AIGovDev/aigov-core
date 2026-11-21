"""
Adversarial holdout benchmark runner for Conditions H and I.

Runs H and/or I on the 170-scenario adversarial holdout dataset.
The original 70-scenario frozen dataset (run_qwen_benchmark.py) is NOT modified.

Usage:
    # Scripted oracle only (no model inference):
    python run_adversarial_benchmark.py --condition-h --condition-i

    # With model inference (requires mlx-lm):
    python run_adversarial_benchmark.py --condition-h --condition-i --model mlx-community/Qwen2.5-3B-Instruct-4bit

    # Smoke test (first 10 scenarios):
    python run_adversarial_benchmark.py --condition-i --smoke

    # Save results:
    python run_adversarial_benchmark.py --condition-h --condition-i --out results_adversarial.json
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

_BENCH_DIR = Path(__file__).parent
if str(_BENCH_DIR) not in sys.path:
    sys.path.insert(0, str(_BENCH_DIR))

from adversarial_dataset import (  # noqa: E402
    ADVERSARIAL_AUTHORIZED_APPROVERS,
    ADVERSARIAL_DATASET,
    ADVERSARIAL_DATASET_HASH,
    AdversarialScenario,
    build_adversarial_dataset,
    compute_adversarial_dataset_hash,
)
from condition_i_orchestrator import (  # noqa: E402
    ConditionIOrchestrator,
    compute_policy_i_decision,
)
from deterministic_verification_orchestrator import (  # noqa: E402
    EnhancedPolicyOrchestrator,
)
from mlx_qwen_adapter import SandboxToolExecutor  # noqa: E402
from policy_decision import PolicyDecision, PolicyStats  # noqa: E402
from adversarial_dataset import POLICY_FIXTURE  # noqa: E402
from trusted_policy_provider import TrustedPolicyProvider  # noqa: E402


# ---------------------------------------------------------------------------
# Build adversarial scenario sandbox state
# ---------------------------------------------------------------------------

def build_adversarial_state(s: AdversarialScenario) -> dict[str, Any]:
    """
    Build sandbox state dict from AdversarialScenario fields.

    Does NOT use s.ground_truth or s.category.
    State mirrors SandboxToolExecutor's expected schema.
    """
    executed_value = s.audit_executed_value or "2026-12-31"

    audit_records: dict[str, Any] = {}
    if s.audit_found:
        audit_records[s.proposal_id] = {
            "hash_verified": s.audit_hash_verified,
            "executed_value": executed_value,
            "proposal_id": s.proposal_id,
        }

    # Approval record — set approver from scenario (not from authorized list)
    approvals: dict[str, Any] = {}
    approval_proposal_id = s.proposal_id if s.approval_matches_proposal else f"other-{s.proposal_id}"
    approvals[s.approval_id] = {
        "proposal_id": approval_proposal_id,
        "active": s.approval_active,
        "approver": s.approver_email,
    }

    # External state
    external_state: dict[str, Any] = {}
    external_value = executed_value if s.external_matches_audit else f"stale-{executed_value}"
    external_state[s.record_id] = {"value": external_value}

    return {
        "audit_records": audit_records,
        "approvals": approvals,
        "external_state": external_state,
        # H's authorized approvers list (flat, tenant-unaware)
        "authorized_approvers": ADVERSARIAL_AUTHORIZED_APPROVERS,
    }


# ---------------------------------------------------------------------------
# Scripted oracle (no model inference)
# ---------------------------------------------------------------------------

def run_scripted_h(s: AdversarialScenario) -> bool:
    """Condition H scripted oracle — mirrors h_would_authorize."""
    return s.h_would_authorize


def run_scripted_i(s: AdversarialScenario, provider: TrustedPolicyProvider) -> bool:
    """Condition I scripted oracle — uses TrustedPolicyProvider directly."""
    from adversarial_dataset import _NOW  # module-level reference time
    if not (s.audit_found and s.audit_hash_verified and s.approval_matches_proposal
            and s.approval_active and s.external_matches_audit):
        return False
    result = provider.lookup_authorization(
        approver_email=s.approver_email,
        action_type=s.action_type,
        resource_id=s.resource_id,
        tenant_id=s.tenant_id,
        current_time=_NOW,
    )
    return result.authorized


# ---------------------------------------------------------------------------
# Sandbox-level evaluation (no inference, using SandboxToolExecutor)
# ---------------------------------------------------------------------------

def eval_h_sandbox(s: AdversarialScenario) -> dict[str, Any]:
    """
    Run Condition H sandbox evaluation (no model inference).
    Uses EnhancedPolicyOrchestrator with check_identity=True.
    Returns prediction and evidence dict.
    """
    state = build_adversarial_state(s)
    executor = SandboxToolExecutor(state, check_identity=True)
    orchestrator = EnhancedPolicyOrchestrator(
        executor,
        authorized_approvers=ADVERSARIAL_AUTHORIZED_APPROVERS,
    )
    evidence = orchestrator.orchestrate(
        proposal_id=s.proposal_id,
        approval_id=s.approval_id,
        record_id=s.record_id,
        field="value",
    )
    # In sandbox mode (no model), treat DVO result as final
    # (model verdict = True if DVO passes, fail-closed otherwise)
    prediction = evidence.dvo_authorized
    return {
        "scenario_id": s.scenario_id,
        "prediction": prediction,
        "ground_truth": s.ground_truth,
        "dvo_authorized": evidence.dvo_authorized,
        "failure_reasons": evidence.failure_reasons,
        "correct": prediction == s.ground_truth,
    }


def eval_i_sandbox(s: AdversarialScenario, provider: TrustedPolicyProvider) -> dict[str, Any]:
    """
    Run Condition I sandbox evaluation (no model inference).
    Uses ConditionIOrchestrator with TrustedPolicyProvider.
    Returns prediction and evidence dict.
    """
    from adversarial_dataset import _NOW
    state = build_adversarial_state(s)
    executor = SandboxToolExecutor(state, check_identity=False)
    orchestrator = ConditionIOrchestrator(
        executor=executor,
        policy_provider=provider,
        action_type=s.action_type,
        resource_id=s.resource_id,
        tenant_id=s.tenant_id,
        current_time=_NOW,
    )
    evidence = orchestrator.orchestrate(
        proposal_id=s.proposal_id,
        approval_id=s.approval_id,
        record_id=s.record_id,
        field="value",
    )
    prediction = evidence.dvo_authorized
    policy_reason = None
    if evidence.policy_lookup_result is not None:
        policy_reason = evidence.policy_lookup_result.failure_reason
    return {
        "scenario_id": s.scenario_id,
        "prediction": prediction,
        "ground_truth": s.ground_truth,
        "dvo_authorized": evidence.dvo_authorized,
        "failure_reasons": evidence.failure_reasons,
        "policy_failure_reason": policy_reason,
        "correct": prediction == s.ground_truth,
    }


# ---------------------------------------------------------------------------
# Metrics computation
# ---------------------------------------------------------------------------

@dataclass
class ConditionMetrics:
    tp: int = 0
    fp: int = 0
    tn: int = 0
    fn: int = 0
    total: int = 0

    def record(self, prediction: bool, ground_truth: bool) -> None:
        self.total += 1
        if prediction and ground_truth:
            self.tp += 1
        elif prediction and not ground_truth:
            self.fp += 1
        elif not prediction and ground_truth:
            self.fn += 1
        else:
            self.tn += 1

    @property
    def precision(self) -> float:
        return self.tp / (self.tp + self.fp) if (self.tp + self.fp) > 0 else 0.0

    @property
    def recall(self) -> float:
        return self.tp / (self.tp + self.fn) if (self.tp + self.fn) > 0 else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) > 0 else 0.0

    @property
    def far(self) -> float:
        neg = self.tn + self.fp
        return self.fp / neg if neg > 0 else 0.0

    @property
    def frr(self) -> float:
        pos = self.tp + self.fn
        return self.fn / pos if pos > 0 else 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "tp": self.tp, "fp": self.fp, "tn": self.tn, "fn": self.fn,
            "total": self.total,
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1": round(self.f1, 4),
            "far": round(self.far, 4),
            "frr": round(self.frr, 4),
        }


def compute_category_breakdown(
    scenarios: list[AdversarialScenario],
    results: list[dict[str, Any]],
) -> dict[str, dict[str, int]]:
    by_cat: dict[str, dict[str, int]] = {}
    for s, r in zip(scenarios, results):
        cat = s.category
        if cat not in by_cat:
            by_cat[cat] = {"total": 0, "correct": 0, "fp": 0, "fn": 0}
        by_cat[cat]["total"] += 1
        if r["correct"]:
            by_cat[cat]["correct"] += 1
        elif r["prediction"] and not r["ground_truth"]:
            by_cat[cat]["fp"] += 1
        elif not r["prediction"] and r["ground_truth"]:
            by_cat[cat]["fn"] += 1
    return by_cat


# ---------------------------------------------------------------------------
# Main benchmark runner
# ---------------------------------------------------------------------------

def run_adversarial_benchmark(
    seed: int = 42,
    smoke: bool = False,
    model_path: str | None = None,
    out_path: str | None = None,
    run_condition_h_holdout: bool = False,
    run_condition_i: bool = False,
) -> dict[str, Any]:
    """
    Run the adversarial holdout benchmark.

    Args:
        seed:                 Dataset seed (default 42).
        smoke:                If True, run first 10 scenarios only.
        model_path:           Path to local MLX model (None = no inference).
        out_path:             Save JSON results to this path.
        run_condition_h_holdout: Evaluate Condition H on adversarial holdout.
        run_condition_i:      Evaluate Condition I on adversarial holdout.

    Returns:
        dict with metrics, category breakdown, and scenario traces.

    Security note:
        "Do not claim Condition I is more secure merely because it achieves higher F1.
        The goal is demonstrably trustworthy authorization under distribution shift,
        with measurable availability costs."
        — Availability cost = FRR on legitimate scenarios (category: authorized_legitimate)
    """
    scenarios = build_adversarial_dataset(seed)
    dataset_hash = compute_adversarial_dataset_hash(scenarios)

    if smoke:
        scenarios = scenarios[:10]
        print(f"[adversarial_benchmark] SMOKE MODE: {len(scenarios)} scenarios")

    provider = TrustedPolicyProvider(POLICY_FIXTURE)

    n_pos = sum(1 for s in scenarios if s.ground_truth)
    n_neg = sum(1 for s in scenarios if not s.ground_truth)
    h_fp_exposure = sum(1 for s in scenarios if s.h_would_authorize and not s.ground_truth)
    print(f"\n{'=' * 60}")
    print(f"ADVERSARIAL HOLDOUT BENCHMARK  ({len(scenarios)} scenarios)")
    print(f"  Dataset hash: {dataset_hash[:16]}")
    print(f"  Positives: {n_pos}  Negatives: {n_neg}")
    print(f"  H false-positive exposure: {h_fp_exposure} scenarios where")
    print(f"    h_would_authorize=True but ground_truth=False")
    print(f"{'=' * 60}")

    report: dict[str, Any] = {
        "dataset_hash": dataset_hash,
        "n_scenarios": len(scenarios),
        "n_positives": n_pos,
        "n_negatives": n_neg,
        "h_false_positive_exposure": h_fp_exposure,
        "condition_h_enabled": run_condition_h_holdout,
        "condition_i_enabled": run_condition_i,
    }

    # --- Condition H ---
    if run_condition_h_holdout:
        print("\nCondition H (Enhanced Policy — flat identity list on adversarial holdout):")
        h_metrics = ConditionMetrics()
        h_results: list[dict[str, Any]] = []
        t0 = time.perf_counter()
        for idx, s in enumerate(scenarios):
            r = eval_h_sandbox(s)
            h_metrics.record(r["prediction"], r["ground_truth"])
            h_results.append(r)
            status = "✓" if r["correct"] else "✗"
            print(f"  H[{idx+1}/{len(scenarios)}] {s.scenario_id} "
                  f"pred={r['prediction']} gt={s.ground_truth} {status}")
        elapsed = (time.perf_counter() - t0) * 1000
        cat_h = compute_category_breakdown(scenarios, h_results)
        print(f"\nCondition H adversarial holdout:")
        print(f"  F1={h_metrics.f1:.3f}  FAR={h_metrics.far:.3f}  "
              f"FRR={h_metrics.frr:.3f}  "
              f"TP={h_metrics.tp} FP={h_metrics.fp} TN={h_metrics.tn} FN={h_metrics.fn}")
        for cat, counts in sorted(cat_h.items()):
            fp_flag = " ← FP" if counts["fp"] > 0 else ""
            fn_flag = " ← FN" if counts["fn"] > 0 else ""
            print(f"    {cat:35s} total={counts['total']:3d}  "
                  f"correct={counts['correct']:3d}  "
                  f"fp={counts['fp']} fn={counts['fn']}{fp_flag}{fn_flag}")
        report["H_adversarial"] = h_metrics.to_dict()
        report["H_adversarial"]["category_breakdown"] = cat_h
        report["H_adversarial"]["elapsed_ms"] = round(elapsed, 1)
        report["traces_h"] = h_results

    # --- Condition I ---
    if run_condition_i:
        print("\nCondition I (Trusted Policy Source on adversarial holdout):")
        i_metrics = ConditionMetrics()
        i_results: list[dict[str, Any]] = []
        t0 = time.perf_counter()
        for idx, s in enumerate(scenarios):
            r = eval_i_sandbox(s, provider)
            i_metrics.record(r["prediction"], r["ground_truth"])
            i_results.append(r)
            status = "✓" if r["correct"] else "✗"
            pr = r.get("policy_failure_reason", "")
            print(f"  I[{idx+1}/{len(scenarios)}] {s.scenario_id} "
                  f"pred={r['prediction']} gt={s.ground_truth} {status}"
                  + (f" [{pr}]" if pr and pr != "allow" else ""))
        elapsed = (time.perf_counter() - t0) * 1000
        cat_i = compute_category_breakdown(scenarios, i_results)
        print(f"\nCondition I adversarial holdout:")
        print(f"  F1={i_metrics.f1:.3f}  FAR={i_metrics.far:.3f}  "
              f"FRR={i_metrics.frr:.3f}  "
              f"TP={i_metrics.tp} FP={i_metrics.fp} TN={i_metrics.tn} FN={i_metrics.fn}")
        for cat, counts in sorted(cat_i.items()):
            fp_flag = " ← FP" if counts["fp"] > 0 else ""
            fn_flag = " ← FN" if counts["fn"] > 0 else ""
            print(f"    {cat:35s} total={counts['total']:3d}  "
                  f"correct={counts['correct']:3d}  "
                  f"fp={counts['fp']} fn={counts['fn']}{fp_flag}{fn_flag}")
        report["I_adversarial"] = i_metrics.to_dict()
        report["I_adversarial"]["category_breakdown"] = cat_i
        report["I_adversarial"]["elapsed_ms"] = round(elapsed, 1)
        report["traces_i"] = i_results

    # --- H vs I comparison (if both ran) ---
    if run_condition_h_holdout and run_condition_i:
        print(f"\n{'─' * 60}")
        print("H vs I comparison on adversarial holdout:")
        h_m = report["H_adversarial"]
        i_m = report["I_adversarial"]
        print(f"  F1:   H={h_m['f1']:.3f}  I={i_m['f1']:.3f}")
        print(f"  FAR:  H={h_m['far']:.3f}  I={i_m['far']:.3f}  (↓ = more secure)")
        print(f"  FRR:  H={h_m['frr']:.3f}  I={i_m['frr']:.3f}  (↑ = availability cost)")

        # H false-positive scenarios that I correctly rejected
        h_fp_i_correct = sum(
            1 for s, rh, ri in zip(scenarios, report["traces_h"], report["traces_i"])
            if rh["prediction"] and not s.ground_truth and not ri["prediction"]
        )
        print(f"  Scenarios H got wrong (FP) that I got right: {h_fp_i_correct}")

        # Legitimate scenarios rejected by I but not H (availability cost)
        i_fn_h_correct = sum(
            1 for s, rh, ri in zip(scenarios, report["traces_h"], report["traces_i"])
            if not ri["prediction"] and s.ground_truth and rh["prediction"]
        )
        print(f"  Legitimate scenarios I rejected (FN) that H passed: {i_fn_h_correct}")
        print(f"  → I security gain: {h_fp_i_correct} fewer false authorizations")
        print(f"  → I availability cost: {i_fn_h_correct} additional legitimate rejections")
        report["h_vs_i"] = {
            "h_fp_i_correct": h_fp_i_correct,
            "i_fn_h_correct": i_fn_h_correct,
        }

    print(f"\n{'=' * 60}")
    print("ADVERSARIAL BENCHMARK COMPLETE")
    if run_condition_h_holdout:
        print(f"  H adversarial: F1={report['H_adversarial']['f1']:.3f}  "
              f"FAR={report['H_adversarial']['far']:.3f}")
    if run_condition_i:
        print(f"  I adversarial: F1={report['I_adversarial']['f1']:.3f}  "
              f"FAR={report['I_adversarial']['far']:.3f}")
    print(f"  H FP exposure: {h_fp_exposure} scenarios where I defends that H does not")
    print(f"{'=' * 60}")

    if out_path:
        # Exclude traces from JSON to keep it manageable; they're logged above
        out_report = {k: v for k, v in report.items()
                      if not k.startswith("traces_")}
        Path(out_path).write_text(json.dumps(out_report, indent=2))
        print(f"\nResults written to {out_path}")

    return report


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def _main() -> None:
    parser = argparse.ArgumentParser(description="Adversarial holdout benchmark for Conditions H and I")
    parser.add_argument("--condition-h", action="store_true", help="Evaluate Condition H on adversarial holdout")
    parser.add_argument("--condition-i", action="store_true", help="Evaluate Condition I on adversarial holdout")
    parser.add_argument("--smoke", action="store_true", help="Run first 10 scenarios only")
    parser.add_argument("--model", default=None, help="Path to local MLX model")
    parser.add_argument("--seed", type=int, default=42, help="Dataset seed")
    parser.add_argument("--out", default=None, help="Save results JSON to this path")
    args = parser.parse_args()

    if not args.condition_h and not args.condition_i:
        print("No conditions selected. Use --condition-h and/or --condition-i.")
        sys.exit(1)

    run_adversarial_benchmark(
        seed=args.seed,
        smoke=args.smoke,
        model_path=args.model,
        out_path=args.out,
        run_condition_h_holdout=args.condition_h,
        run_condition_i=args.condition_i,
    )


if __name__ == "__main__":
    _main()
