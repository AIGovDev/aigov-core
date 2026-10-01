#!/usr/bin/env python3
"""Schema validation for a single agent delegation snapshot payload."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_INPUT = ROOT / "examples/agent-governance/sample-agent-delegation-snapshot.json"
MANIFEST_PATH = ROOT / "docs/agent-governance/agent-governance-manifest.json"


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def validate(snapshot: dict, manifest: dict) -> list[str]:
    errors: list[str] = []
    schema = manifest.get("snapshot_schema", {})

    for key in schema.get("required_keys", []):
        if key not in snapshot:
            errors.append(f"missing required key: {key}")

    if not isinstance(snapshot.get("schema_version"), int):
        errors.append("schema_version must be an integer")
    if not isinstance(snapshot.get("snapshot_id"), str) or not snapshot.get("snapshot_id"):
        errors.append("snapshot_id must be a non-empty string")
    if not isinstance(snapshot.get("captured_at"), str) or not snapshot.get("captured_at"):
        errors.append("captured_at must be a non-empty ISO-8601 string")
    if not isinstance(snapshot.get("environment"), str) or not snapshot.get("environment"):
        errors.append("environment must be a non-empty string")

    for collection in schema.get("required_collections", []):
        if not isinstance(snapshot.get(collection), dict):
            errors.append(f"collection '{collection}' must be present and an object")

    delegation = snapshot.get("delegation", {})
    if isinstance(delegation, dict):
        if not isinstance(delegation.get("delegator_agent_id"), str) or not delegation.get("delegator_agent_id"):
            errors.append("delegation.delegator_agent_id must be a non-empty string")
        if not isinstance(delegation.get("delegate_agent_ids"), list) or not delegation.get("delegate_agent_ids"):
            errors.append("delegation.delegate_agent_ids must be a non-empty array")
        if not isinstance(delegation.get("max_delegation_depth_observed"), int):
            errors.append("delegation.max_delegation_depth_observed must be an integer")

    approval_chain = snapshot.get("approval_chain", {})
    if isinstance(approval_chain, dict):
        for key in ("required_approvals", "recorded_approvals", "stale_pending_approvals"):
            if not isinstance(approval_chain.get(key), int) or approval_chain.get(key, -1) < 0:
                errors.append(f"approval_chain.{key} must be a non-negative integer")

    auditability = snapshot.get("auditability", {})
    if isinstance(auditability, dict):
        rate = auditability.get("correlation_ids_present_rate_percent")
        if not isinstance(rate, int) or not (0 <= rate <= 100):
            errors.append("auditability.correlation_ids_present_rate_percent must be an integer in [0, 100]")

    override_governance = snapshot.get("override_governance", {})
    if isinstance(override_governance, dict):
        for key in ("override_events_observed", "undocumented_override_events"):
            if not isinstance(override_governance.get(key), int) or override_governance.get(key, -1) < 0:
                errors.append(f"override_governance.{key} must be a non-negative integer")

    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT)
    parser.add_argument("--manifest", type=Path, default=MANIFEST_PATH)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    if not args.input.exists():
        errors = [f"missing snapshot input: {args.input}"]
    else:
        snapshot = _load(args.input)
        manifest = _load(args.manifest) if args.manifest.exists() else {}
        errors = validate(snapshot, manifest)

    ok = not errors

    if args.json:
        print(json.dumps({"ok": ok, "input": str(args.input), "errors": errors}, sort_keys=True))
    else:
        print(f"validate_agent_delegation_snapshot: {'OK' if ok else 'FAILED'}")
        for err in errors:
            print(f"  - {err}", file=sys.stderr)

    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
