#!/usr/bin/env python3
"""Deterministic policy coverage / control maturity / gap risk scoring.

Formulas are this script's own documented choice, grounded in the
descriptions in docs/policy-intelligence/{policy-coverage,control-maturity,
governance-gap-analysis}.md (0-4 maturity ordinal normalized to 0-100;
gap severities weighted none=0..critical=100; coverage from
reviewed/enforced ratios against registered_policies_count) — the docs
specify the shape of each score, not the exact weighting.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_INPUT = ROOT / "examples/policy-intelligence/sample-governance-control-snapshot.json"

GAP_SEVERITY_WEIGHT = {"none": 0, "low": 25, "medium": 50, "high": 75, "critical": 100}


def _clamp(v: float) -> float:
    return max(0.0, min(100.0, v))


def coverage_score(snapshot: dict) -> tuple[float, list[str]]:
    findings = []
    inv = snapshot.get("policy_inventory", {}) or {}
    registered = inv.get("registered_policies_count", 0)
    if not registered:
        return 0.0, ["coverage:no_registered_policies"]
    reviewed_ratio = inv.get("reviewed_policies_count", 0) / registered
    enforced_ratio = inv.get("enforced_in_ci_count", 0) / registered
    if reviewed_ratio < 1.0:
        findings.append("coverage:unreviewed_policies_present")
    if enforced_ratio < 1.0:
        findings.append("coverage:unenforced_policies_present")
    score = 50 * reviewed_ratio + 50 * enforced_ratio
    return _clamp(score), findings


def maturity_score(snapshot: dict) -> tuple[float, list[str]]:
    findings = []
    controls = snapshot.get("controls", []) or []
    if not controls:
        return 0.0, ["maturity:no_controls"]
    avg = sum(c.get("maturity_level", 0) for c in controls) / len(controls)
    low_maturity = [c.get("control_id") for c in controls if c.get("maturity_level", 0) <= 1]
    if low_maturity:
        findings.append(f"maturity:low_maturity_controls:{len(low_maturity)}")
    return _clamp(avg / 4 * 100), findings


def gap_risk_score(snapshot: dict) -> tuple[float, list[str]]:
    """Higher = more remediation work outstanding (matches governance-gap-analysis.md's framing)."""
    findings = []
    controls = snapshot.get("controls", []) or []
    if not controls:
        return 0.0, ["gap:no_controls"]
    weights = [GAP_SEVERITY_WEIGHT.get(c.get("gap_severity"), 0) for c in controls]
    avg = sum(weights) / len(controls)
    high_severity = [c.get("control_id") for c in controls if c.get("gap_severity") in ("high", "critical")]
    if high_severity:
        findings.append(f"gap:high_or_critical_severity_controls:{len(high_severity)}")
    unevidenced = [c.get("control_id") for c in controls if not c.get("evidence_attached")]
    if unevidenced:
        findings.append(f"gap:controls_missing_evidence:{len(unevidenced)}")
    return _clamp(avg), findings


def governance_process_score(snapshot: dict) -> tuple[float, list[str]]:
    findings = []
    process = snapshot.get("governance_process", {}) or {}
    score = 0.0
    reviews = process.get("quarterly_reviews_done_last_year", 0)
    score += min(reviews, 4) / 4 * 40
    if reviews < 4:
        findings.append("process:fewer_than_4_quarterly_reviews")
    if process.get("exception_process_documented"):
        score += 30
    else:
        findings.append("process:exception_process_not_documented")
    if process.get("segregation_of_duties"):
        score += 30
    else:
        findings.append("process:segregation_of_duties_not_in_place")
    return _clamp(score), findings


def compute(snapshot: dict) -> dict:
    cov, f1 = coverage_score(snapshot)
    mat, f2 = maturity_score(snapshot)
    gap, f3 = gap_risk_score(snapshot)
    proc, f4 = governance_process_score(snapshot)

    # gap_risk_score is a "bad is high" scale; invert it when folding into the overall portfolio score.
    portfolio_score = round((cov + mat + (100 - gap) + proc) / 4, 2)

    findings = sorted(f1 + f2 + f3 + f4)

    return {
        "ok": True,
        "coverage_score": round(cov, 2),
        "control_maturity_score": round(mat, 2),
        "gap_risk_score": round(gap, 2),
        "governance_process_score": round(proc, 2),
        "portfolio_score": portfolio_score,
        "findings": findings,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT)
    args = parser.parse_args()

    if not args.input.exists():
        print(json.dumps({"ok": False, "error": f"missing input: {args.input}"}, sort_keys=True))
        return 1

    snapshot = json.loads(args.input.read_text(encoding="utf-8"))
    result = compute(snapshot)
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
