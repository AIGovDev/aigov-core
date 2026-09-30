#!/usr/bin/env python3
"""Deterministic Markdown operational intelligence report from a single snapshot.

See docs/observability/operational-intelligence-report.md for the report
structure this generator produces. Reuses operational_health_score.compute_score
so scoring logic lives in exactly one place.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(Path(__file__).resolve().parent))

from operational_health_score import compute_score

DEFAULT_INPUT = ROOT / "examples/observability/sample-operational-snapshot.json"
MANIFEST_PATH = ROOT / "docs/observability/observability-manifest.json"


def _load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def render(snapshot: dict[str, Any], manifest: dict[str, Any], input_path: Path, manifest_path: Path) -> str:
    score = compute_score(snapshot, manifest)

    lines: list[str] = []
    lines.append("# Operational intelligence report")
    lines.append("")

    lines.append("## Snapshot metadata")
    lines.append("")
    lines.append(f"- `snapshot_id`: {snapshot.get('snapshot_id')}")
    lines.append(f"- `captured_at`: {snapshot.get('captured_at')}")
    lines.append(f"- `environment`: {snapshot.get('environment')}")
    lines.append(f"- `window_minutes`: {snapshot.get('window_minutes')}")
    lines.append(f"- `schema_version`: {snapshot.get('schema_version')}")
    lines.append("")

    lines.append("## Scores")
    lines.append("")
    lines.append(f"- `health_score`: {score['health_score']}")
    lines.append(f"- `risk_level`: {score['risk_level']}")
    lines.append(f"- `ok`: {score['ok']}")
    for key in sorted(score["sub_scores"]):
        lines.append(f"- `sub_scores.{key}`: {score['sub_scores'][key]}")
    for key in sorted(score["weights"]):
        lines.append(f"- `weights.{key}`: {score['weights'][key]}")
    lines.append("")

    rh = snapshot.get("runtime_health", {}) or {}
    lines.append("## Runtime health")
    lines.append("")
    for key in sorted(rh):
        lines.append(f"- `{key}`: {rh[key]}")
    lines.append("")

    readiness = snapshot.get("readiness", {}) or {}
    lines.append("## Readiness")
    lines.append("")
    for key in sorted(readiness):
        lines.append(f"- `{key}`: {readiness[key]}")
    lines.append("")

    ef = snapshot.get("evidence_flow", {}) or {}
    lines.append("## Evidence flow")
    lines.append("")
    for key in sorted(ef):
        if key == "compliance_summary_decision_distribution":
            dist = ef[key] or {}
            lines.append(f"- `{key}`:")
            for dkey in sorted(dist):
                lines.append(f"  - `{dkey}`: {dist[dkey]}")
        else:
            lines.append(f"- `{key}`: {ef[key]}")
    lines.append("")

    diag = snapshot.get("diagnostics", {}) or {}
    lines.append("## Diagnostics")
    lines.append("")
    lines.append(f"- `failure_count`: {diag.get('failure_count')}")
    lines.append(f"- `warning_count`: {diag.get('warning_count')}")
    lines.append(f"- `summary`: {diag.get('summary')}")
    checks = sorted(diag.get("checks", []) or [], key=lambda c: c.get("name", ""))
    for check in checks:
        status = "ok" if check.get("ok") else "FAIL"
        lines.append(f"  - [{status}] `{check.get('name')}` — {check.get('detail')}")
    lines.append("")

    lines.append("## Findings")
    lines.append("")
    if score["findings"]:
        for finding in score["findings"]:
            lines.append(f"- `{finding}`")
    else:
        lines.append("- none")
    lines.append("")

    lines.append("## Report metadata")
    lines.append("")
    try:
        input_rel = input_path.resolve().relative_to(ROOT)
    except ValueError:
        input_rel = input_path
    try:
        manifest_rel = manifest_path.resolve().relative_to(ROOT)
    except ValueError:
        manifest_rel = manifest_path
    lines.append(f"- snapshot: `{input_rel}`")
    lines.append(f"- manifest: `{manifest_rel}`")
    lines.append("")

    return "\n".join(line.rstrip() for line in lines).rstrip("\n") + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT)
    parser.add_argument("--manifest", type=Path, default=MANIFEST_PATH)
    parser.add_argument("--out", type=Path, default=None)
    args = parser.parse_args()

    if not args.input.exists():
        print(f"error: missing snapshot input: {args.input}", file=sys.stderr)
        return 1

    snapshot = _load(args.input)
    manifest = _load(args.manifest) if args.manifest.exists() else {}

    report = render(snapshot, manifest, args.input, args.manifest)

    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(report, encoding="utf-8")
    else:
        sys.stdout.write(report)

    return 0


if __name__ == "__main__":
    sys.exit(main())
