#!/usr/bin/env python3
"""Render a Markdown report for a public-launch readiness snapshot."""

from __future__ import annotations

import argparse
from pathlib import Path

from public_launch_lib import (
    DEFAULT_INPUT,
    evaluate_snapshot,
    failure_payload,
    load_snapshot,
    report_text,
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT, help="Snapshot JSON path")
    args = parser.parse_args()
    snapshot, errors = load_snapshot(args.input)
    if snapshot is None:
        print(report_text(failure_payload(errors)), end="")
        return 1
    payload = evaluate_snapshot(snapshot)
    print(report_text(payload), end="")
    return 0 if payload["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
