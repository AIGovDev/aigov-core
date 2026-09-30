#!/usr/bin/env python3
"""Deterministic Markdown dataset governance report from a provenance snapshot.

Sections: identifiers, scores table, owners, sources, lineage bullets,
retention bullets, findings, recommendations, lineage risk narrative. Lists
sorted so diffs stay stable. See docs/evidence-quality/dataset-governance-report.md.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(Path(__file__).resolve().parent))

from evidence_quality_score import compute

DEFAULT_INPUT = ROOT / "examples/evidence-quality/sample-dataset-provenance-snapshot.json"


def render(snapshot: dict) -> str:
    score = compute(snapshot)
    lines: list[str] = []

    lines.append("# Dataset governance report")
    lines.append("")
    lines.append(f"- `dataset_id`: {snapshot.get('dataset_id')}")
    lines.append(f"- `dataset_version`: {snapshot.get('dataset_version')}")
    lines.append(f"- `snapshot_timestamp_utc`: {snapshot.get('snapshot_timestamp_utc')}")
    lines.append("")

    lines.append("## Scores")
    lines.append("")
    lines.append("| Dimension | Score |")
    lines.append("|---|---|")
    lines.append(f"| provenance | {score['provenance_score']} |")
    lines.append(f"| lineage | {score['lineage_score']} |")
    lines.append(f"| retention | {score['retention_score']} |")
    lines.append(f"| **evidence_quality_score** | **{score['evidence_quality_score']}** |")
    lines.append(f"| risk_level | {score['risk_level']} |")
    lines.append("")

    lines.append("## Owners")
    lines.append("")
    for owner in sorted(snapshot.get("owners", []), key=lambda o: o.get("id", "")):
        lines.append(f"- `{owner.get('id')}` — {owner.get('role')}")
    lines.append("")

    lines.append("## Sources")
    lines.append("")
    for source in sorted(snapshot.get("sources", []), key=lambda s: s.get("uri", "")):
        checksum = source.get("checksum_sha256", "(none)")
        lines.append(f"- `{source.get('uri')}` (type={source.get('type')}, registered={source.get('registered')}, checksum={checksum})")
    lines.append("")

    lines.append("## Lineage")
    lines.append("")
    for edge in sorted(snapshot.get("lineage_edges", []), key=lambda e: e.get("from_dataset_id", "")):
        lines.append(f"- {edge.get('relation')} `{edge.get('from_dataset_id')}`")
    for tr in sorted(snapshot.get("transformations", []), key=lambda t: t.get("id", "")):
        lines.append(f"- transformation `{tr.get('id')}` ({tr.get('kind')}): {tr.get('code_reference')}")
    lines.append("")

    lines.append("## Retention")
    lines.append("")
    retention = snapshot.get("retention", {}) or {}
    lines.append(f"- classification: {retention.get('classification')}")
    lines.append(f"- retention_days: {retention.get('retention_days')}")
    lines.append(f"- legal_hold: {retention.get('legal_hold')}")
    if retention.get("policy_reference"):
        lines.append(f"- policy_reference: {retention.get('policy_reference')}")
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

    lines.append("## Lineage risk narrative")
    lines.append("")
    if any(f.startswith("lineage:") for f in score["findings"]):
        lines.append(
            "Undocumented or incomplete lineage was detected. Missing parents or code references reduce "
            "the ability to reconstruct how this dataset was produced; prioritize the lineage findings above."
        )
    else:
        lines.append("No lineage gaps detected in this snapshot's declared edges and transformations.")
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
        args.out.write_text(report, encoding="utf-8", newline="\n")
    else:
        sys.stdout.write(report)

    return 0


if __name__ == "__main__":
    sys.exit(main())
