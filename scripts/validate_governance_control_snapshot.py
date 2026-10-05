#!/usr/bin/env python3
"""Schema validation for a governance control snapshot (docs/policy-intelligence/)."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_INPUT = ROOT / "examples/policy-intelligence/sample-governance-control-snapshot.json"

VALID_GAP_SEVERITIES = {"none", "low", "medium", "high", "critical"}


def validate(snapshot: dict) -> list[str]:
    errors: list[str] = []

    for key in ("org_id", "snapshot_version"):
        if not isinstance(snapshot.get(key), str) or not snapshot.get(key, "").strip():
            errors.append(f"{key} must be a non-empty string")

    inventory = snapshot.get("policy_inventory")
    if not isinstance(inventory, dict):
        errors.append("policy_inventory must be an object")
    else:
        for key in ("registered_policies_count", "reviewed_policies_count", "enforced_in_ci_count"):
            if not isinstance(inventory.get(key), int) or inventory.get(key, -1) < 0:
                errors.append(f"policy_inventory.{key} must be a non-negative integer")
        registered = inventory.get("registered_policies_count", 0)
        reviewed = inventory.get("reviewed_policies_count", 0)
        enforced = inventory.get("enforced_in_ci_count", 0)
        if isinstance(registered, int) and isinstance(reviewed, int) and reviewed > registered:
            errors.append("policy_inventory.reviewed_policies_count cannot exceed registered_policies_count")
        if isinstance(registered, int) and isinstance(enforced, int) and enforced > registered:
            errors.append("policy_inventory.enforced_in_ci_count cannot exceed registered_policies_count")

    process = snapshot.get("governance_process")
    if not isinstance(process, dict):
        errors.append("governance_process must be an object")
    else:
        if not isinstance(process.get("quarterly_reviews_done_last_year"), int) or process.get(
            "quarterly_reviews_done_last_year", -1
        ) < 0:
            errors.append("governance_process.quarterly_reviews_done_last_year must be a non-negative integer")
        for key in ("exception_process_documented", "segregation_of_duties"):
            if not isinstance(process.get(key), bool):
                errors.append(f"governance_process.{key} must be a boolean")

    controls = snapshot.get("controls")
    if not isinstance(controls, list) or not controls:
        errors.append("controls must be a non-empty array")
        controls = []
    seen_ids: set[str] = set()
    for i, control in enumerate(controls):
        if not isinstance(control, dict):
            errors.append(f"controls[{i}] must be an object")
            continue
        control_id = control.get("control_id")
        if not isinstance(control_id, str) or not control_id.strip():
            errors.append(f"controls[{i}].control_id must be a non-empty string")
        elif control_id in seen_ids:
            errors.append(f"duplicate control_id: {control_id}")
        else:
            seen_ids.add(control_id)
        maturity = control.get("maturity_level")
        if not isinstance(maturity, int) or not (0 <= maturity <= 4):
            errors.append(f"controls[{i}] ({control_id}).maturity_level must be an integer in [0, 4]")
        severity = control.get("gap_severity")
        if severity not in VALID_GAP_SEVERITIES:
            errors.append(f"controls[{i}] ({control_id}).gap_severity must be one of {sorted(VALID_GAP_SEVERITIES)}")
        if not isinstance(control.get("evidence_attached"), bool):
            errors.append(f"controls[{i}] ({control_id}).evidence_attached must be a boolean")

    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    if not args.input.exists():
        errors = [f"missing input: {args.input}"]
    else:
        errors = validate(json.loads(args.input.read_text(encoding="utf-8")))

    ok = not errors

    if args.json:
        print(json.dumps({"ok": ok, "input": str(args.input), "errors": errors}, sort_keys=True))
    else:
        print(f"validate_governance_control_snapshot: {'OK' if ok else 'FAILED'}")
        for err in errors:
            print(f"  - {err}", file=sys.stderr)

    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
