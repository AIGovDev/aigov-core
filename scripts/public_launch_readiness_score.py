#!/usr/bin/env python3
"""Emit a deterministic checklist score for a supplied readiness snapshot."""

from __future__ import annotations

import argparse
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
    args = parser.parse_args()
    snapshot, errors = load_snapshot(args.input)
    payload = evaluate_snapshot(snapshot) if snapshot is not None else failure_payload(errors)
    print(json_text(payload))
    return 0 if payload["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
