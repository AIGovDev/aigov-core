#!/usr/bin/env python3
"""Deterministic Markdown multi-agent governance report from a delegation snapshot."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(Path(__file__).resolve().parent))

from agent_governance_score import compute

DEFAULT_INPUT = ROOT / "examples/agent-governance/sample-agent-delegation-snapshot.json"
MANIFEST_PATH = ROOT / "docs/agent-governance/agent-governance-manifest.json"


def render(snapshot: dict, manifest: dict) -> str:
    score = compute(snapshot, manifest)
    lines: list[str] = []

    lines.append("# Multi-agent governance report")
    lines.append("")
    lines.append(f"- `snapshot_id`: {snapshot.get('snapshot_id')}")
    lines.append(f"- `captured_at`: {snapshot.get('captured_at')}")
    lines.append(f"- `environment`: {snapshot.get('environment')}")
    lines.append("")

    lines.append("## Scores")
    lines.append("")
    lines.append(f"- `composite_score`: {score['composite_score']}")
    lines.append(f"- `risk_level`: {score['risk_level']}")
    for key in sorted(score["sub_scores"]):
        lines.append(f"- `sub_scores.{key}`: {score['sub_scores'][key]}")
    lines.append("")

    delegation = snapshot.get("delegation", {}) or {}
    lines.append("## Delegation")
    lines.append("")
    lines.append(f"- delegator: `{delegation.get('delegator_agent_id')}`")
    for agent_id in sorted(delegation.get("delegate_agent_ids", [])):
        lines.append(f"  - delegate: `{agent_id}`")
    for scope in sorted(delegation.get("delegation_scopes", [])):
        lines.append(f"  - scope: `{scope}`")
    lines.append(f"- max_delegation_depth_observed: {delegation.get('max_delegation_depth_observed')}")
    lines.append(f"- cross_tenant_delegation_observed: {delegation.get('cross_tenant_delegation_observed')}")
    lines.append("")

    approval_chain = snapshot.get("approval_chain", {}) or {}
    lines.append("## Approval chain")
    lines.append("")
    for key in sorted(approval_chain):
        lines.append(f"- `{key}`: {approval_chain[key]}")
    lines.append("")

    override_governance = snapshot.get("override_governance", {}) or {}
    lines.append("## Override governance")
    lines.append("")
    for key in sorted(override_governance):
        lines.append(f"- `{key}`: {override_governance[key]}")
    lines.append("")

    auditability = snapshot.get("auditability", {}) or {}
    lines.append("## Auditability")
    lines.append("")
    for key in sorted(auditability):
        lines.append(f"- `{key}`: {auditability[key]}")
    lines.append("")

    lines.append("## Findings")
    lines.append("")
    if score["findings"]:
        for f in score["findings"]:
            lines.append(f"- `{f}`")
    else:
        lines.append("- none")
    lines.append("")

    lines.append("## Recommendations")
    lines.append("")
    if score["recommendations"]:
        for r in score["recommendations"]:
            lines.append(f"- {r}")
    else:
        lines.append("- none")
    lines.append("")

    return "\n".join(line.rstrip() for line in lines).rstrip("\n") + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT)
    parser.add_argument("--manifest", type=Path, default=MANIFEST_PATH)
    parser.add_argument("--out", type=Path, default=None)
    args = parser.parse_args()

    if not args.input.exists():
        print(f"error: missing input: {args.input}", file=sys.stderr)
        return 1

    snapshot = json.loads(args.input.read_text(encoding="utf-8"))
    manifest = json.loads(args.manifest.read_text(encoding="utf-8")) if args.manifest.exists() else {}
    report = render(snapshot, manifest)

    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(report, encoding="utf-8")
    else:
        sys.stdout.write(report)

    return 0


if __name__ == "__main__":
    sys.exit(main())
