#!/usr/bin/env python3
"""Deterministic Markdown governance control report from a control snapshot."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(Path(__file__).resolve().parent))

from policy_coverage_score import compute

DEFAULT_INPUT = ROOT / "examples/policy-intelligence/sample-governance-control-snapshot.json"


def render(snapshot: dict) -> str:
    score = compute(snapshot)
    lines: list[str] = []

    lines.append("# Governance control report")
    lines.append("")
    lines.append(f"- `org_id`: {snapshot.get('org_id')}")
    lines.append(f"- `snapshot_version`: {snapshot.get('snapshot_version')}")
    lines.append("")

    lines.append("## Scores")
    lines.append("")
    lines.append("| Metric | Value |")
    lines.append("|---|---|")
    lines.append(f"| coverage_score | {score['coverage_score']} |")
    lines.append(f"| control_maturity_score | {score['control_maturity_score']} |")
    lines.append(f"| gap_risk_score | {score['gap_risk_score']} |")
    lines.append(f"| governance_process_score | {score['governance_process_score']} |")
    lines.append(f"| **portfolio_score** | **{score['portfolio_score']}** |")
    lines.append("")

    inv = snapshot.get("policy_inventory", {}) or {}
    lines.append("## Policy inventory")
    lines.append("")
    for key in sorted(inv):
        lines.append(f"- `{key}`: {inv[key]}")
    lines.append("")

    process = snapshot.get("governance_process", {}) or {}
    lines.append("## Governance process")
    lines.append("")
    for key in sorted(process):
        lines.append(f"- `{key}`: {process[key]}")
    lines.append("")

    lines.append("## Controls")
    lines.append("")
    lines.append("| control_id | maturity_level | gap_severity | evidence_attached |")
    lines.append("|---|---|---|---|")
    for c in sorted(snapshot.get("controls", []), key=lambda c: c.get("control_id", "")):
        lines.append(
            f"| {c.get('control_id')} | {c.get('maturity_level')} | {c.get('gap_severity')} | {c.get('evidence_attached')} |"
        )
    lines.append("")

    lines.append("## Findings")
    lines.append("")
    if score["findings"]:
        for f in score["findings"]:
            lines.append(f"- `{f}`")
    else:
        lines.append("- none")
    lines.append("")

    return "\n".join(line.rstrip() for line in lines).rstrip("\n") + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT)
    parser.add_argument("--out", type=Path, default=None)
    args = parser.parse_args()

    if not args.input.exists():
        print(f"error: missing input: {args.input}", file=sys.stderr)
        return 1

    snapshot = json.loads(args.input.read_text(encoding="utf-8"))
    report = render(snapshot)

    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(report, encoding="utf-8")
    else:
        sys.stdout.write(report)

    return 0


if __name__ == "__main__":
    sys.exit(main())
