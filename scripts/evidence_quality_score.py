#!/usr/bin/env python3
"""Deterministic 0-100 evidence-quality scoring for a dataset provenance snapshot.

Per docs/evidence-quality/evidence-quality-scoring.md: fail-closed on schema
(invalid snapshots return ok:false, zero scores, risk_level: high). Scoring
weights below (provenance/lineage/retention each one third of the composite)
are this script's own documented choice — the doc specifies dimensions and
fail-closed behavior but not exact weights.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(Path(__file__).resolve().parent))

from validate_dataset_provenance_snapshot import (
    validate as validate_snapshot,
)

DEFAULT_INPUT = ROOT / "examples/evidence-quality/sample-dataset-provenance-snapshot.json"

VALID_RELATIONS = {"derived_from", "merged_with", "copied_from", "sampled_from", "aggregated_from"}
VALID_CLASSIFICATIONS = {"public", "internal", "confidential", "restricted"}


def _clamp(v: float) -> int:
    return max(0, min(100, round(v)))


def score_provenance(snapshot: dict) -> tuple[int, list[str]]:
    findings = []
    sources = snapshot.get("sources", []) or []
    if not sources:
        return 0, ["provenance:no_sources"]

    registered_frac = sum(1 for s in sources if s.get("registered") is True) / len(sources)
    checksum_frac = sum(1 for s in sources if s.get("checksum_sha256")) / len(sources)
    governance = snapshot.get("governance") or {}
    governance_ok = bool(governance.get("approval_id")) and bool(governance.get("approval_timestamp_utc"))

    if registered_frac < 1.0:
        findings.append("provenance:unregistered_sources_present")
    if checksum_frac < 1.0:
        findings.append("provenance:sources_missing_checksum")
    if not governance_ok:
        findings.append("provenance:governance_block_incomplete")

    score = 40 * registered_frac + 30 * checksum_frac + 30 * (1.0 if governance_ok else 0.0)
    return _clamp(score), findings


def score_lineage(snapshot: dict) -> tuple[int, list[str]]:
    findings = []
    edges = snapshot.get("lineage_edges", []) or []
    transformations = snapshot.get("transformations", []) or []

    if not edges:
        edges_score = 0.0
        findings.append("lineage:no_lineage_edges")
    else:
        valid_edges = sum(1 for e in edges if e.get("relation") in VALID_RELATIONS and e.get("from_dataset_id"))
        edges_score = 50 * (valid_edges / len(edges))
        if valid_edges < len(edges):
            findings.append("lineage:edge_with_invalid_relation")

    if not transformations:
        transformations_score = 0.0
        findings.append("lineage:no_transformations_declared")
    else:
        valid_tr = sum(1 for t in transformations if t.get("id") and t.get("kind") and t.get("code_reference"))
        transformations_score = 50 * (valid_tr / len(transformations))
        if valid_tr < len(transformations):
            findings.append("lineage:transformation_missing_code_reference")

    return _clamp(edges_score + transformations_score), findings


def score_retention(snapshot: dict) -> tuple[int, list[str]]:
    findings = []
    retention = snapshot.get("retention") or {}
    if not retention:
        return 0, ["retention:missing_retention_block"]

    score = 0.0
    classification = retention.get("classification")
    if classification in VALID_CLASSIFICATIONS:
        score += 40
    else:
        findings.append("retention:invalid_classification")

    days = retention.get("retention_days")
    if isinstance(days, int) and 1 <= days <= 36500:
        score += 30
    else:
        findings.append("retention:retention_days_out_of_bounds")

    legal_hold = retention.get("legal_hold")
    if legal_hold is True and not retention.get("policy_reference"):
        findings.append("retention:legal_hold_missing_policy_reference")
    else:
        score += 30

    return _clamp(score), findings


def compute(snapshot: dict) -> dict:
    schema_errors = validate_snapshot(snapshot)
    if schema_errors:
        return {
            "ok": False,
            "schema_errors": sorted(schema_errors),
            "provenance_score": 0,
            "lineage_score": 0,
            "retention_score": 0,
            "evidence_quality_score": 0,
            "risk_level": "high",
            "findings": ["schema:invalid_snapshot"],
            "recommendations": ["Fix schema validation errors before requesting a quality score."],
        }

    provenance_score, f1 = score_provenance(snapshot)
    lineage_score, f2 = score_lineage(snapshot)
    retention_score, f3 = score_retention(snapshot)

    composite = round((provenance_score + lineage_score + retention_score) / 3)
    risk_level = "low" if composite >= 80 else "medium" if composite >= 50 else "high"

    findings = sorted(set(f1 + f2 + f3))
    recommendations = sorted(
        {
            "provenance:unregistered_sources_present": "Register all dataset sources before publishing the snapshot.",
            "provenance:sources_missing_checksum": "Add checksum_sha256 for every source where feasible.",
            "provenance:governance_block_incomplete": "Attach an approval_id and approval_timestamp_utc.",
            "lineage:no_lineage_edges": "Declare at least one lineage_edges entry with a controlled relation.",
            "lineage:edge_with_invalid_relation": "Use only the controlled relation vocabulary for lineage_edges.",
            "lineage:no_transformations_declared": "Declare transformations with id, kind, and code_reference.",
            "lineage:transformation_missing_code_reference": "Add a code_reference to every transformation.",
            "retention:invalid_classification": "Set retention.classification to a valid enum value.",
            "retention:retention_days_out_of_bounds": "Set retention.retention_days between 1 and 36500.",
            "retention:legal_hold_missing_policy_reference": "Add a policy_reference when legal_hold is true.",
            "retention:missing_retention_block": "Add a retention object to the snapshot.",
        }.get(f, f)
        for f in findings
    )

    return {
        "ok": True,
        "provenance_score": provenance_score,
        "lineage_score": lineage_score,
        "retention_score": retention_score,
        "evidence_quality_score": composite,
        "risk_level": risk_level,
        "findings": findings,
        "recommendations": recommendations,
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
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
