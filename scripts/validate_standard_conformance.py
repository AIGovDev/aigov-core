#!/usr/bin/env python3
"""CLI wrapper for aigov_py.standards.validator.validate_conformance.

Thin wrapper only — the real, authoritative validation logic already
exists and is tested (python/aigov_py/standards/validator.py, exercised
by python/tests/test_standards_conformance.py). See
docs/standards/conformance.md for the output contract this mirrors.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "python"))

from aigov_py.standards.validator import validate_conformance


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path", type=Path, help="Path to the JSON document to validate.")
    parser.add_argument("--artifact-type", default=None, help="Override the inferred artifact_type; must match inference.")
    parser.add_argument("--json", action="store_true", help="Emit one JSON object on stdout with sorted keys.")
    args = parser.parse_args()

    if not args.path.exists():
        if args.json:
            print(json.dumps({"ok": False, "error": f"missing input: {args.path}"}, sort_keys=True))
        else:
            print(f"error: missing input: {args.path}", file=sys.stderr)
        return 1

    data = json.loads(args.path.read_text(encoding="utf-8"))
    report = validate_conformance(data, artifact_type=args.artifact_type)

    if args.json:
        print(json.dumps(report.as_dict(), sort_keys=True))
    else:
        print(f"validate_standard_conformance: {'OK' if report.ok else 'FAILED'}")
        print(f"  artifact_type={report.artifact_type} version={report.version}")
        if report.digest:
            print(f"  digest={report.digest}")
        for check in report.checks:
            status = "ok" if check.get("ok") else "FAIL"
            print(f"  [{status}] {check.get('id')}: {check.get('detail')}")
        for failure in report.failures:
            print(f"  FAILURE [{failure.get('code')}] {failure.get('path')}: {failure.get('message')}", file=sys.stderr)

    return 0 if report.ok else 1


if __name__ == "__main__":
    sys.exit(main())
