#!/usr/bin/env python3
"""Deterministic health, readiness, evidence, and diagnostics scoring.

Reads a single operational snapshot (docs/observability/diagnostic-snapshots.md)
and produces four 0-100 sub-scores, a weighted health_score, a risk_level
(docs/observability/operational-risk.md), and a sorted list of findings.

This module exposes `compute_score()` so generate_operational_intelligence_report.py
can reuse the same scoring logic instead of re-implementing it.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_INPUT = ROOT / "examples/observability/sample-operational-snapshot.json"
MANIFEST_PATH = ROOT / "docs/observability/observability-manifest.json"

DEFAULT_WEIGHTS = {"diagnostics": 25, "evidence_flow": 25, "readiness": 20, "runtime_health": 30}


def _clamp(value: float, lo: float = 0.0, hi: float = 100.0) -> float:
    return max(lo, min(hi, value))


def _score_runtime_health(rh: dict[str, Any]) -> tuple[float, list[str]]:
    findings: list[str] = []
    score = 100.0

    error_rate = rh.get("error_rate_percent", 0)
    penalty = min(error_rate * 4, 60)
    if penalty:
        score -= penalty
        findings.append(f"runtime_health:error_rate_percent_above_threshold:{error_rate}")

    incidents = rh.get("open_incidents_count", 0)
    penalty = min(incidents * 10, 40)
    if penalty:
        score -= penalty
        findings.append(f"runtime_health:open_incidents_present:{incidents}")

    uptime = rh.get("audit_service_uptime_minutes", 0)
    if uptime < 60:
        score -= 20
        findings.append(f"runtime_health:uptime_below_60_minutes:{uptime}")

    return _clamp(score), findings


def _score_readiness(readiness: dict[str, Any]) -> tuple[float, list[str]]:
    findings: list[str] = []
    signals = ("audit_ready_endpoint_status", "migration_state_consistent", "policy_pack_load_status")
    true_count = 0
    for signal in signals:
        value = readiness.get(signal)
        if value is True:
            true_count += 1
        else:
            findings.append(f"readiness:{signal}_not_true:{value!r}")
    score = (true_count / len(signals)) * 100
    return _clamp(score), findings


def _score_evidence_flow(ef: dict[str, Any]) -> tuple[float, list[str]]:
    findings: list[str] = []
    score = 100.0

    latency = ef.get("evidence_arrival_latency_p95_seconds", 0)
    penalty = min(latency * 2, 30)
    if penalty:
        score -= penalty
        findings.append(f"evidence_flow:latency_p95_seconds_elevated:{latency}")

    success_rate = ef.get("evidence_arrival_success_rate_percent", 100)
    penalty = min(100 - success_rate, 40)
    if penalty:
        score -= penalty
        findings.append(f"evidence_flow:success_rate_below_100:{success_rate}")

    dist = ef.get("compliance_summary_decision_distribution", {}) or {}
    total = sum(dist.get(k, 0) for k in ("valid", "invalid", "blocked"))
    if total > 0:
        non_valid = total - dist.get("valid", 0)
        non_valid_ratio_pct = (non_valid / total) * 100
        penalty = min(non_valid_ratio_pct, 30)
        if penalty >= 1:
            score -= penalty
            findings.append(f"evidence_flow:non_valid_decision_ratio_percent:{round(non_valid_ratio_pct)}")

    return _clamp(score), findings


def _score_diagnostics(diag: dict[str, Any]) -> tuple[float, list[str]]:
    findings: list[str] = []
    score = 100.0

    failure_count = diag.get("failure_count", 0)
    if failure_count:
        score -= min(failure_count * 20, 80)

    warning_count = diag.get("warning_count", 0)
    if warning_count:
        score -= min(warning_count * 10, 40)

    for check in diag.get("checks", []) or []:
        if isinstance(check, dict) and check.get("ok") is False:
            findings.append(f"diagnostics:failed_check:{check.get('name', 'unknown')}")

    return _clamp(score), findings


def compute_score(snapshot: dict[str, Any], manifest: dict[str, Any] | None = None) -> dict[str, Any]:
    weights = (manifest or {}).get("score_weights") or DEFAULT_WEIGHTS

    rh_score, rh_findings = _score_runtime_health(snapshot.get("runtime_health", {}) or {})
    rd_score, rd_findings = _score_readiness(snapshot.get("readiness", {}) or {})
    ef_score, ef_findings = _score_evidence_flow(snapshot.get("evidence_flow", {}) or {})
    dg_score, dg_findings = _score_diagnostics(snapshot.get("diagnostics", {}) or {})

    sub_scores = {
        "diagnostics": round(dg_score, 2),
        "evidence_flow": round(ef_score, 2),
        "readiness": round(rd_score, 2),
        "runtime_health": round(rh_score, 2),
    }

    health_score = round(
        sum(sub_scores[k] * weights.get(k, 0) for k in sub_scores) / 100.0,
        2,
    )

    readiness = snapshot.get("readiness", {}) or {}
    all_readiness_true = all(
        readiness.get(s) is True
        for s in ("audit_ready_endpoint_status", "migration_state_consistent", "policy_pack_load_status")
    )
    all_sub_scores_ge = lambda threshold: all(v >= threshold for v in sub_scores.values())  # noqa: E731

    if health_score >= 85 and all_sub_scores_ge(75) and all_readiness_true:
        risk_level = "low"
    elif health_score >= 70 and all_sub_scores_ge(60):
        risk_level = "medium"
    elif health_score >= 50:
        risk_level = "high"
    else:
        risk_level = "critical"

    findings = sorted(rh_findings + rd_findings + ef_findings + dg_findings)

    return {
        "ok": True,
        "health_score": health_score,
        "sub_scores": sub_scores,
        "risk_level": risk_level,
        "weights": {k: weights.get(k, 0) for k in ("diagnostics", "evidence_flow", "readiness", "runtime_health")},
        "findings": findings,
        "snapshot_id": snapshot.get("snapshot_id"),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT)
    parser.add_argument("--manifest", type=Path, default=MANIFEST_PATH)
    args = parser.parse_args()

    if not args.input.exists():
        print(json.dumps({"ok": False, "error": f"missing snapshot input: {args.input}"}, sort_keys=True))
        return 1

    snapshot = json.loads(args.input.read_text(encoding="utf-8"))
    manifest = json.loads(args.manifest.read_text(encoding="utf-8")) if args.manifest.exists() else None

    result = compute_score(snapshot, manifest)
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
