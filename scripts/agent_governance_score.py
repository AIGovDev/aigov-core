#!/usr/bin/env python3
"""Deterministic delegation/approval-chain/override/auditability scoring for an agent delegation snapshot.

Sub-score formulas are this script's own documented choice — the manifest
specifies score_weights and the snapshot schema but not exact per-signal
penalty formulas (same situation as operational_health_score.py).
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_INPUT = ROOT / "examples/agent-governance/sample-agent-delegation-snapshot.json"
MANIFEST_PATH = ROOT / "docs/agent-governance/agent-governance-manifest.json"
DEFAULT_WEIGHTS = {"approval_chain": 30, "auditability": 20, "delegation": 30, "override": 20}


def _clamp(v: float) -> float:
    return max(0.0, min(100.0, v))


def score_approval_chain(d: dict) -> tuple[float, list[str]]:
    findings = []
    score = 100.0
    if d.get("human_in_loop_required") and not d.get("human_in_loop_observed"):
        score -= 50
        findings.append("approval_chain:human_in_loop_required_but_not_observed")
    required = d.get("required_approvals", 0)
    recorded = d.get("recorded_approvals", 0)
    if recorded < required:
        score -= 30
        findings.append("approval_chain:recorded_approvals_below_required")
    stale = d.get("stale_pending_approvals", 0)
    if stale:
        score -= min(stale * 10, 20)
        findings.append(f"approval_chain:stale_pending_approvals:{stale}")
    return _clamp(score), findings


def score_auditability(d: dict) -> tuple[float, list[str]]:
    findings = []
    rate = d.get("correlation_ids_present_rate_percent", 0)
    score = float(rate) * 0.4
    for key, weight in (
        ("decision_artifacts_exported", 20),
        ("delegation_edges_logged", 20),
        ("retention_policy_acknowledged", 20),
    ):
        if d.get(key):
            score += weight
        else:
            findings.append(f"auditability:{key}_false")
    return _clamp(score), findings


def score_delegation(d: dict) -> tuple[float, list[str]]:
    findings = []
    score = 100.0
    if d.get("cross_tenant_delegation_observed"):
        score -= 50
        findings.append("delegation:cross_tenant_delegation_observed")
    depth = d.get("max_delegation_depth_observed", 0)
    if depth > 3:
        score -= min((depth - 3) * 10, 30)
        findings.append(f"delegation:max_delegation_depth_observed_elevated:{depth}")
    if not d.get("delegation_scopes"):
        score -= 20
        findings.append("delegation:no_delegation_scopes_declared")
    return _clamp(score), findings


def score_override(d: dict) -> tuple[float, list[str]]:
    findings = []
    score = 100.0
    undocumented = d.get("undocumented_override_events", 0)
    if undocumented:
        score -= min(undocumented * 40, 80)
        findings.append(f"override:undocumented_override_events:{undocumented}")
    if d.get("emergency_break_glass_used") and undocumented == 0:
        score -= 10
        findings.append("override:emergency_break_glass_used")
    return _clamp(score), findings


def compute(snapshot: dict, manifest: dict | None = None) -> dict:
    weights = (manifest or {}).get("score_weights") or DEFAULT_WEIGHTS

    ac_score, ac_findings = score_approval_chain(snapshot.get("approval_chain", {}) or {})
    au_score, au_findings = score_auditability(snapshot.get("auditability", {}) or {})
    dl_score, dl_findings = score_delegation(snapshot.get("delegation", {}) or {})
    ov_score, ov_findings = score_override(snapshot.get("override_governance", {}) or {})

    sub_scores = {
        "approval_chain": round(ac_score, 2),
        "auditability": round(au_score, 2),
        "delegation": round(dl_score, 2),
        "override": round(ov_score, 2),
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

    findings = sorted(ac_findings + au_findings + dl_findings + ov_findings)

    recommendation_by_prefix = {
        "approval_chain:human_in_loop_required_but_not_observed": "Ensure required human-in-the-loop approval is actually observed before high-impact actions.",
        "approval_chain:recorded_approvals_below_required": "Record all required approvals before promoting the delegation.",
        "approval_chain:stale_pending_approvals": "Resolve stale pending approvals.",
        "auditability:decision_artifacts_exported_false": "Export decision artifacts for audit review.",
        "auditability:delegation_edges_logged_false": "Log all delegation edges for traceability.",
        "auditability:retention_policy_acknowledged_false": "Acknowledge the retention policy for this snapshot.",
        "delegation:cross_tenant_delegation_observed": "Investigate and remediate cross-tenant delegation immediately.",
        "delegation:max_delegation_depth_observed_elevated": "Review why delegation depth exceeds the expected bound.",
        "delegation:no_delegation_scopes_declared": "Declare explicit delegation_scopes for every delegate.",
        "override:undocumented_override_events": "Document every override event with justification.",
        "override:emergency_break_glass_used": "Confirm break-glass usage was properly documented and reviewed.",
    }

    def _recommendation_for(finding: str) -> str:
        for prefix, text in recommendation_by_prefix.items():
            if finding == prefix or finding.startswith(prefix + ":"):
                return text
        return finding

    recommendations = sorted({_recommendation_for(f) for f in findings})

    return {
        "ok": True,
        "composite_score": composite,
        "sub_scores": sub_scores,
        "risk_level": risk_level,
        "weights": {k: weights.get(k, 0) for k in ("approval_chain", "auditability", "delegation", "override")},
        "findings": findings,
        "recommendations": recommendations,
        "snapshot_id": snapshot.get("snapshot_id"),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT)
    parser.add_argument("--manifest", type=Path, default=MANIFEST_PATH)
    parser.add_argument("--json", action="store_true")
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
