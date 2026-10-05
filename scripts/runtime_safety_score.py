#!/usr/bin/env python3
"""Deterministic guardrail/escalation/human-oversight/override-readiness scoring.

Sub-score formulas are this script's own documented choice (same situation
as operational_health_score.py and agent_governance_score.py) — the
manifest specifies score_weights and signal names, not exact penalty
formulas.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_INPUT = ROOT / "examples/runtime-safety/sample-runtime-safety-snapshot.json"
MANIFEST_PATH = ROOT / "docs/runtime-safety/runtime-safety-manifest.json"
DEFAULT_WEIGHTS = {"escalation": 25, "guardrail": 30, "human_oversight": 25, "override_readiness": 20}


def _clamp(v: float) -> float:
    return max(0.0, min(100.0, v))


def score_guardrail(g: dict) -> tuple[float, list[str]]:
    findings = []
    score = 100.0
    latency = g.get("guardrail_latency_p95_ms", 0)
    if latency > 100:
        penalty = min((latency - 100) / 10, 50)
        score -= penalty
        findings.append(f"guardrail:latency_p95_ms_elevated:{latency}")
    return _clamp(score), findings


def score_escalation(e: dict) -> tuple[float, list[str]]:
    findings = []
    score = 100.0
    breaches = e.get("sla_breaches_observed", 0)
    if breaches:
        score -= min(breaches * 25, 60)
        findings.append(f"escalation:sla_breaches_observed:{breaches}")
    pending = e.get("pending_human_review_count", 0)
    if pending:
        score -= min(pending * 10, 30)
        findings.append(f"escalation:pending_human_review_backlog:{pending}")
    wait = e.get("median_queue_wait_minutes", 0)
    if wait > 30:
        score -= min((wait - 30) / 2, 20)
        findings.append(f"escalation:median_queue_wait_elevated_minutes:{wait}")
    return _clamp(score), findings


def score_human_oversight(h: dict) -> tuple[float, list[str]]:
    findings = []
    coverage = h.get("human_review_coverage_percent", 0)
    attribution = h.get("attribution_chain_complete_percent", 0)
    supervisors = h.get("active_supervisors_count", 0)
    score = 0.5 * coverage + 0.4 * attribution
    if supervisors >= 1:
        score += 10
    else:
        findings.append("human_oversight:no_active_supervisors")
    if coverage < 100:
        findings.append("human_oversight:review_coverage_below_100")
    if attribution < 100:
        findings.append("human_oversight:attribution_chain_incomplete")
    return _clamp(score), findings


def score_override_readiness(o: dict) -> tuple[float, list[str]]:
    findings = []
    score = 0.0
    if o.get("override_playbook_version_present"):
        score += 30
    else:
        findings.append("override_readiness:no_playbook_registered")
    if o.get("rollback_procedure_documented"):
        score += 30
    else:
        findings.append("override_readiness:rollback_procedure_undocumented")
    drill_days = o.get("emergency_break_glass_last_drill_days_ago", 9999)
    if drill_days <= 90:
        score += 25
    else:
        findings.append(f"override_readiness:break_glass_drill_stale_days:{drill_days}")
    export_latency = o.get("audit_trail_export_latency_p95_seconds", 9999)
    if export_latency <= 60:
        score += 15
    else:
        findings.append(f"override_readiness:audit_export_latency_elevated_seconds:{export_latency}")
    return _clamp(score), findings


def compute(snapshot: dict, manifest: dict | None = None) -> dict:
    weights = (manifest or {}).get("score_weights") or DEFAULT_WEIGHTS

    gd_score, gd_findings = score_guardrail(snapshot.get("guardrails", {}) or {})
    es_score, es_findings = score_escalation(snapshot.get("escalation", {}) or {})
    ho_score, ho_findings = score_human_oversight(snapshot.get("human_oversight", {}) or {})
    or_score, or_findings = score_override_readiness(snapshot.get("override_readiness", {}) or {})

    diagnostics = snapshot.get("diagnostics", {}) or {}
    diag_findings = [
        f"diagnostics:failed_check:{c.get('name', 'unknown')}"
        for c in diagnostics.get("checks", []) or []
        if isinstance(c, dict) and c.get("ok") is False
    ]

    sub_scores = {
        "escalation": round(es_score, 2),
        "guardrail": round(gd_score, 2),
        "human_oversight": round(ho_score, 2),
        "override_readiness": round(or_score, 2),
    }

    composite = round(sum(sub_scores[k] * weights.get(k, 0) for k in sub_scores) / 100.0, 2)

    all_ge = lambda t: all(v >= t for v in sub_scores.values())
    if composite >= 85 and all_ge(75):
        risk_level = "low"
    elif composite >= 70 and all_ge(60):
        risk_level = "medium"
    elif composite >= 50:
        risk_level = "high"
    else:
        risk_level = "critical"

    findings = sorted(gd_findings + es_findings + ho_findings + or_findings + diag_findings)

    return {
        "ok": True,
        "composite_score": composite,
        "sub_scores": sub_scores,
        "risk_level": risk_level,
        "weights": {k: weights.get(k, 0) for k in ("escalation", "guardrail", "human_oversight", "override_readiness")},
        "findings": findings,
        "snapshot_id": snapshot.get("snapshot_id"),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT)
    parser.add_argument("--manifest", type=Path, default=MANIFEST_PATH)
    args = parser.parse_args()

    if not args.input.exists():
        print(json.dumps({"ok": False, "error": f"missing input: {args.input}"}, sort_keys=True))
        return 1

    snapshot = json.loads(args.input.read_text(encoding="utf-8"))
    manifest = json.loads(args.manifest.read_text(encoding="utf-8")) if args.manifest.exists() else None
    result = compute(snapshot, manifest)
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
