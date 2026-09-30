#!/usr/bin/env python3
"""Validate a dataset provenance snapshot against docs/evidence-quality/dataset-provenance.md.

Required concepts: dataset_id, dataset_version identify the dataset; sources[]
list URIs with a registered boolean and an optional 64-hex checksum_sha256;
governance{approval_id, approval_timestamp_utc} cites an offline approval
record.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_INPUT = ROOT / "examples/evidence-quality/sample-dataset-provenance-snapshot.json"

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def validate(snapshot: dict) -> list[str]:
    errors: list[str] = []

    for key in ("dataset_id", "dataset_version"):
        if not isinstance(snapshot.get(key), str) or not snapshot.get(key, "").strip():
            errors.append(f"{key} must be a non-empty string")

    sources = snapshot.get("sources")
    if not isinstance(sources, list) or not sources:
        errors.append("sources must be a non-empty array")
        sources = []
    for i, source in enumerate(sources):
        if not isinstance(source, dict):
            errors.append(f"sources[{i}] must be an object")
            continue
        if not isinstance(source.get("uri"), str) or not source.get("uri", "").strip():
            errors.append(f"sources[{i}].uri must be a non-empty string")
        if not isinstance(source.get("registered"), bool):
            errors.append(f"sources[{i}].registered must be a boolean")
        checksum = source.get("checksum_sha256")
        if checksum is not None and not SHA256_RE.match(str(checksum)):
            errors.append(f"sources[{i}].checksum_sha256 must be a 64-character lowercase hex string when present")

    governance = snapshot.get("governance")
    if not isinstance(governance, dict):
        errors.append("governance must be an object")
    else:
        for key in ("approval_id", "approval_timestamp_utc"):
            if not isinstance(governance.get(key), str) or not governance.get(key, "").strip():
                errors.append(f"governance.{key} must be a non-empty string")

    retention = snapshot.get("retention")
    if retention is not None:
        if not isinstance(retention, dict):
            errors.append("retention must be an object when present")
        else:
            legal_hold = retention.get("legal_hold")
            if legal_hold is True and not isinstance(retention.get("retention_days"), int):
                errors.append("retention.retention_days is required (int) when retention.legal_hold is true")

    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", nargs="?", type=Path, default=DEFAULT_INPUT)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    if not args.input.exists():
        errors = [f"missing input: {args.input}"]
    else:
        errors = validate(_load(args.input))

    ok = not errors

    if args.json:
        print(json.dumps({"ok": ok, "input": str(args.input), "errors": errors}, sort_keys=True))
    else:
        if ok:
            print(f"validate_dataset_provenance_snapshot: OK ({args.input})")
        else:
            print(f"validate_dataset_provenance_snapshot: FAILED ({args.input})", file=sys.stderr)
            for err in errors:
                print(f"  - {err}", file=sys.stderr)

    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
