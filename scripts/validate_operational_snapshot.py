#!/usr/bin/env python3
"""Schema validation for a single operational snapshot payload.

See docs/observability/diagnostic-snapshots.md for the authoritative schema
description this validator enforces.
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


def _load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def validate(snapshot: dict[str, Any], manifest: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    schema = manifest.get("snapshot_schema", {})

    for key in schema.get("required_keys", []):
        if key not in snapshot:
            errors.append(f"missing required key: {key}")

    if not isinstance(snapshot.get("schema_version"), int) or snapshot.get("schema_version", 0) < 0:
        errors.append("schema_version must be a non-negative integer")
    if not isinstance(snapshot.get("snapshot_id"), str) or not snapshot.get("snapshot_id"):
        errors.append("snapshot_id must be a non-empty string")
    if not isinstance(snapshot.get("captured_at"), str) or not snapshot.get("captured_at"):
        errors.append("captured_at must be a non-empty ISO-8601 string")
    if not isinstance(snapshot.get("environment"), str) or not snapshot.get("environment"):
        errors.append("environment must be a non-empty string")
    if not isinstance(snapshot.get("window_minutes"), int) or snapshot.get("window_minutes", 0) <= 0:
        errors.append("window_minutes must be a positive integer")

    for collection in schema.get("required_collections", []):
        if not isinstance(snapshot.get(collection), dict):
            errors.append(f"collection '{collection}' must be present and an object")

    runtime_health = snapshot.get("runtime_health", {})
    if isinstance(runtime_health, dict):
        for key in ("audit_service_uptime_minutes", "error_rate_percent", "open_incidents_count"):
            if not isinstance(runtime_health.get(key), int) or runtime_health.get(key, -1) < 0:
                errors.append(f"runtime_health.{key} must be a non-negative integer")
        pct = runtime_health.get("error_rate_percent")
        if isinstance(pct, int) and not (0 <= pct <= 100):
            errors.append("runtime_health.error_rate_percent must be in [0, 100]")

    readiness = snapshot.get("readiness", {})
    if isinstance(readiness, dict):
        for key in ("audit_ready_endpoint_status", "migration_state_consistent", "policy_pack_load_status"):
            if key not in readiness:
                errors.append(f"readiness.{key} is missing (treated as a critical readiness gap)")
            elif not isinstance(readiness.get(key), bool):
                errors.append(f"readiness.{key} must be a boolean")

    evidence_flow = snapshot.get("evidence_flow", {})
    if isinstance(evidence_flow, dict):
        for key in ("evidence_arrival_latency_p95_seconds", "submissions_observed"):
            if not isinstance(evidence_flow.get(key), int) or evidence_flow.get(key, -1) < 0:
                errors.append(f"evidence_flow.{key} must be a non-negative integer")
        rate = evidence_flow.get("evidence_arrival_success_rate_percent")
        if not isinstance(rate, int) or not (0 <= rate <= 100):
            errors.append("evidence_flow.evidence_arrival_success_rate_percent must be an integer in [0, 100]")
        dist = evidence_flow.get("compliance_summary_decision_distribution")
        if not isinstance(dist, dict) or not all(k in dist for k in ("valid", "invalid", "blocked")):
            errors.append("evidence_flow.compliance_summary_decision_distribution must have valid/invalid/blocked")

    diagnostics = snapshot.get("diagnostics", {})
    if isinstance(diagnostics, dict):
        checks = diagnostics.get("checks", [])
        if not isinstance(checks, list):
            errors.append("diagnostics.checks must be a list")
            checks = []
        for check in checks:
            if not isinstance(check, dict) or not all(k in check for k in ("name", "ok", "detail")):
                errors.append(f"diagnostics.checks entry missing name/ok/detail: {check!r}")
        observed_failures = sum(1 for c in checks if isinstance(c, dict) and c.get("ok") is False)
        if diagnostics.get("failure_count") != observed_failures:
            errors.append(
                f"diagnostics.failure_count ({diagnostics.get('failure_count')!r}) "
                f"does not match ok:false count in checks ({observed_failures})"
            )
        summary = diagnostics.get("summary", "")
        if not isinstance(summary, str) or len(summary) < 24:
            errors.append("diagnostics.summary must be a string of at least 24 characters")

    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT)
    parser.add_argument("--manifest", type=Path, default=MANIFEST_PATH)
    parser.add_argument("--json", action="store_true", help="emit a single JSON object on stdout")
    args = parser.parse_args()

    if not args.input.exists():
        errors = [f"missing snapshot input: {args.input}"]
        snapshot_path = str(args.input)
    else:
        snapshot = _load(args.input)
        manifest = _load(args.manifest) if args.manifest.exists() else {}
        errors = validate(snapshot, manifest)
        snapshot_path = str(args.input)

    ok = not errors

    if args.json:
        print(json.dumps({"ok": ok, "input": snapshot_path, "errors": errors}, sort_keys=True))
    else:
        if ok:
            print("validate_operational_snapshot: OK")
        else:
            print("validate_operational_snapshot: FAILED", file=sys.stderr)
            for err in errors:
                print(f"  - {err}", file=sys.stderr)

    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
