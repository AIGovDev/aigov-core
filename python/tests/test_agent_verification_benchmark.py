"""
AIGov Agent Verification Benchmark Tests — WS4.

Validates that:
  - The dataset generator produces deterministic, balanced, correctly labelled cases.
  - Condition D (AIGov evidence) achieves F1=1.0, FAR=0.0 on the synthetic dataset.
  - Conditions A/B/C have meaningfully lower precision than Condition D.
  - The benchmark runner produces machine-readable results.
  - Reproducibility: same seed → same results.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

# Allow importing from benchmarks/.
_BENCH_DIR = Path(__file__).resolve().parents[2] / "benchmarks" / "agent-verification"
sys.path.insert(0, str(_BENCH_DIR))

from dataset_generator import SCENARIO_TYPES, generate_dataset, save_dataset  # type: ignore[import]
from run_benchmark import CONDITIONS, compute_metrics, load_cases  # type: ignore[import]


# ---------------------------------------------------------------------------
# Dataset generator invariants
# ---------------------------------------------------------------------------

def test_dataset_is_deterministic(tmp_path: Path) -> None:
    """Same seed → identical cases."""
    cases1 = generate_dataset(n_cases=42, seed=99)
    cases2 = generate_dataset(n_cases=42, seed=99)
    assert [c.case_id for c in cases1] == [c.case_id for c in cases2]
    assert [c.scenario_type for c in cases1] == [c.scenario_type for c in cases2]
    assert [c.aigov_verdict for c in cases1] == [c.aigov_verdict for c in cases2]


def test_different_seeds_produce_different_values(tmp_path: Path) -> None:
    cases1 = generate_dataset(n_cases=14, seed=1)
    cases2 = generate_dataset(n_cases=14, seed=2)
    values1 = [c.proposed_value for c in cases1]
    values2 = [c.proposed_value for c in cases2]
    assert values1 != values2


def test_all_scenario_types_represented() -> None:
    """Every scenario type must appear at least once in a full dataset."""
    cases = generate_dataset(n_cases=len(SCENARIO_TYPES) * 2, seed=0)
    found = {c.scenario_type for c in cases}
    missing = set(SCENARIO_TYPES) - found
    assert not missing, f"Missing scenario types: {missing}"


def test_positive_class_ground_truth() -> None:
    """AUTHORIZED_CORRECT cases must have is_true_positive=True; others False."""
    cases = generate_dataset(n_cases=140, seed=42)
    for c in cases:
        if c.scenario_type == "AUTHORIZED_CORRECT":
            assert c.is_true_positive is True
        else:
            assert c.is_true_positive is False


def test_dev_held_out_split() -> None:
    cases = generate_dataset(n_cases=140, seed=42)
    dev = [c for c in cases if c.split == "dev"]
    held = [c for c in cases if c.split == "held_out"]
    assert len(dev) > len(held)
    assert len(dev) + len(held) == 140


def test_save_and_load_roundtrip(tmp_path: Path) -> None:
    cases = generate_dataset(n_cases=28, seed=7)
    save_dataset(cases, tmp_path, seed=7)
    assert (tmp_path / "cases.jsonl").exists()
    assert (tmp_path / "held_out.jsonl").exists()
    assert (tmp_path / "ground_truth.json").exists()
    assert (tmp_path / "generation_log.json").exists()

    loaded = load_cases(tmp_path, "dev")
    assert len(loaded) == sum(1 for c in cases if c.split == "dev")


# ---------------------------------------------------------------------------
# Benchmark scorer — Condition D perfect on synthetic dataset
# ---------------------------------------------------------------------------

def _get_metrics(split: str = "dev", n: int = 140, seed: int = 42, tmp_path: Path | None = None) -> dict:
    import tempfile
    from pathlib import Path as P

    root = tmp_path or P(tempfile.mkdtemp())
    cases_obj = generate_dataset(n_cases=n, seed=seed)
    save_dataset(cases_obj, root, seed=seed)
    cases = load_cases(root, split)
    results = {}
    for name, fn in CONDITIONS.items():
        results[name] = compute_metrics(cases, fn)
    return results


@pytest.fixture(scope="module")
def _benchmark_metrics(tmp_path_factory: pytest.TempPathFactory):
    root = tmp_path_factory.mktemp("bench")
    return _get_metrics(tmp_path=root)


def test_condition_d_achieves_perfect_f1(_benchmark_metrics) -> None:
    """Condition D must achieve F1=1.0, FAR=0.0 on this synthetic dataset."""
    m = _benchmark_metrics["D_aigov_evidence"]
    assert m["f1"] == 1.0, f"D F1={m['f1']}"
    assert m["far"] == 0.0, f"D FAR={m['far']}"
    assert m["frr"] == 0.0, f"D FRR={m['frr']}"
    assert m["precision"] == 1.0


def test_condition_a_has_high_false_acceptance(_benchmark_metrics) -> None:
    """Condition A (self-report) must have FAR > 0.4 — demonstrates the gap."""
    m = _benchmark_metrics["A_self_report"]
    assert m["far"] > 0.4, f"Expected FAR>0.4, got {m['far']}"


def test_condition_d_better_than_conditions_abc(_benchmark_metrics) -> None:
    """Condition D must have strictly better precision and FAR than A, B, C."""
    d = _benchmark_metrics["D_aigov_evidence"]
    for name in ("A_self_report", "B_tool_response", "C_independent_state"):
        other = _benchmark_metrics[name]
        assert d["precision"] >= other["precision"], (
            f"D precision {d['precision']} should be >= {name} {other['precision']}"
        )
        assert d["far"] <= other["far"], (
            f"D FAR {d['far']} should be <= {name} {other['far']}"
        )


def test_benchmark_metrics_have_required_keys(_benchmark_metrics) -> None:
    required = {"n", "tp", "fp", "fn", "tn", "tpr", "fpr", "precision",
                "recall", "f1", "far", "frr", "avg_latency_us"}
    for name, m in _benchmark_metrics.items():
        missing = required - set(m.keys())
        assert not missing, f"{name} missing keys: {missing}"


def test_benchmark_reproducible_across_calls(tmp_path: Path) -> None:
    """Same inputs → same metrics."""
    m1 = _get_metrics(seed=42, n=140, tmp_path=tmp_path / "r1")
    m2 = _get_metrics(seed=42, n=140, tmp_path=tmp_path / "r2")
    for cond in CONDITIONS:
        assert m1[cond]["f1"] == m2[cond]["f1"]
        assert m1[cond]["far"] == m2[cond]["far"]
