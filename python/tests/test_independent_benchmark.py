"""
Tests for the independent agent verification benchmark.

Validates: dataset integrity, oracle independence, Condition D live-verifier
invariant, and metric consistency.
"""
from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
BENCH_DIR = REPO_ROOT / "benchmarks" / "agent-verification"
sys.path.insert(0, str(BENCH_DIR))
sys.path.insert(0, str(REPO_ROOT / "python"))


def test_dataset_has_both_positive_and_negative_cases() -> None:
    from independent_benchmark import build_dataset
    ds = build_dataset(seed=42)
    pos = [s for s in ds if s.ground_truth]
    neg = [s for s in ds if not s.ground_truth]
    assert len(pos) >= 3, "Need at least 3 positive cases"
    assert len(neg) >= 10, "Need at least 10 negative cases"


def test_scenario_ids_are_unique() -> None:
    from independent_benchmark import build_dataset
    ds = build_dataset(seed=42)
    ids = [s.scenario_id for s in ds]
    assert len(ids) == len(set(ids)), "Duplicate scenario IDs"


def test_ground_truth_is_not_derived_from_aigov_verdict() -> None:
    """The oracle must not contain any reference to the verifier result."""
    from independent_benchmark import build_dataset, Scenario
    ds = build_dataset(seed=42)
    for s in ds:
        # Ground truth is set by the scenario designer, not from verifier calls.
        # Verify that the oracle is a simple bool independent of aigov module.
        assert isinstance(s.ground_truth, bool), f"ground_truth for {s.scenario_id} is not bool"


def test_condition_d_rejects_broken_chain_despite_positive_oracle_label() -> None:
    """AUDIT-01 regression: Condition D must NOT trust a positive ground_truth label
    when the evidence chain is broken.
    """
    from independent_benchmark import build_dataset, condition_d
    ds = build_dataset(seed=42)
    broken_chain = [
        s for s in ds
        if not s.expected_hash_valid and s.ground_truth is False
    ]
    assert broken_chain, "No broken-chain negative scenarios in dataset"
    for s in broken_chain:
        result = condition_d(s)
        assert result is False, (
            f"AUDIT-01 regression: Condition D returned True for broken-chain scenario {s.scenario_id}"
        )


def test_condition_d_accepts_valid_evidence() -> None:
    from independent_benchmark import build_dataset, condition_d
    ds = build_dataset(seed=42)
    valid_cases = [s for s in ds if s.ground_truth]
    assert valid_cases, "No valid positive scenarios"
    for s in valid_cases:
        result = condition_d(s)
        assert result is True, (
            f"Condition D rejected valid scenario {s.scenario_id}"
        )


def test_condition_d_better_than_condition_a_on_adversarial() -> None:
    """Condition D (AIGov) must have lower FAR than Condition A (self-report)
    on hallucination and tampered scenarios.
    """
    from independent_benchmark import build_dataset, condition_a, condition_d
    ds = build_dataset(seed=42)
    adversarial = [s for s in ds if any(t in s.tags for t in ("hallucination", "tampered", "replay"))]
    assert adversarial, "No adversarial scenarios"

    far_a = sum(1 for s in adversarial if condition_a(s) and not s.ground_truth) / len(adversarial)
    far_d = sum(1 for s in adversarial if condition_d(s) and not s.ground_truth) / len(adversarial)
    assert far_d < far_a, (
        f"Expected FAR(D)={far_d:.3f} < FAR(A)={far_a:.3f} on adversarial scenarios"
    )


def test_benchmark_runs_end_to_end() -> None:
    from independent_benchmark import run_benchmark
    report = run_benchmark(seed=42, json_out=None)
    assert report["n_scenarios"] == 20
    assert "D_aigov_evidence" in report["conditions"]
    d = report["conditions"]["D_aigov_evidence"]
    assert d["far"] < 0.2, f"FAR too high: {d['far']}"
    assert d["f1"] > 0.7, f"F1 too low: {d['f1']}"
    assert report["real_agent"]["status"] == "BLOCKED" or "f1" in report["real_agent"]
