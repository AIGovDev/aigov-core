#!/usr/bin/env python3
"""Validate a public-launch readiness snapshot without network access."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from public_launch_lib import (
    DEFAULT_INPUT,
    evaluate_snapshot,
    failure_payload,
    json_text,
    load_snapshot,
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT, help="Snapshot JSON path")
    parser.add_argument("--json", action="store_true", help="Emit deterministic JSON")
    args = parser.parse_args()

    snapshot, errors = load_snapshot(args.input)
    payload = evaluate_snapshot(snapshot) if snapshot is not None else failure_payload(errors)
    if args.json:
        print(json_text(payload))
    elif payload["ok"]:
        print(f"public_launch_check: PASS ({payload['checks_passed']}/{payload['checks_total']})")
    else:
        print("public_launch_check: NOT READY", file=sys.stderr)
        for error in payload["errors"]:
            print(f"- {error}", file=sys.stderr)
        for check in payload["checks"]:
            if not check["passed"]:
                print(f"- failed: {check['name']}", file=sys.stderr)
    return 0 if payload["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
