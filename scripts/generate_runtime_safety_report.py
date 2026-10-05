#!/usr/bin/env python3
"""Deterministic Markdown human oversight / runtime safety report from a snapshot."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(Path(__file__).resolve().parent))

from runtime_safety_score import compute

DEFAULT_INPUT = ROOT / "examples/runtime-safety/sample-runtime-safety-snapshot.json"
MANIFEST_PATH = ROOT / "docs/runtime-safety/runtime-safety-manifest.json"


def render(snapshot: dict, manifest: dict) -> str:
    score = compute(snapshot, manifest)
    lines: list[str] = []

    lines.append("# Runtime safety report")
    lines.append("")
    lines.append(f"- `snapshot_id`: {snapshot.get('snapshot_id')}")
    lines.append(f"- `captured_at`: {snapshot.get('captured_at')}")
    lines.append(f"- `environment`: {snapshot.get('environment')}")
    lines.append(f"- `window_minutes`: {snapshot.get('window_minutes')}")
    lines.append("")

    lines.append("## Scores")
    lines.append("")
    lines.append(f"- `composite_score`: {score['composite_score']}")
    lines.append(f"- `risk_level`: {score['risk_level']}")
    for key in sorted(score["sub_scores"]):
        lines.append(f"- `sub_scores.{key}`: {score['sub_scores'][key]}")
    lines.append("")

    for section, title in (
        ("guardrails", "Guardrails"),
        ("escalation", "Escalation"),
        ("human_oversight", "Human oversight"),
        ("override_readiness", "Override readiness"),
    ):
        data = snapshot.get(section, {}) or {}
        lines.append(f"## {title}")
        lines.append("")
        for key in sorted(data):
            lines.append(f"- `{key}`: {data[key]}")
        lines.append("")

    diagnostics = snapshot.get("diagnostics", {}) or {}
    lines.append("## Diagnostics")
    lines.append("")
    lines.append(f"- `failure_count`: {diagnostics.get('failure_count')}")
    lines.append(f"- `warning_count`: {diagnostics.get('warning_count')}")
    lines.append(f"- `summary`: {diagnostics.get('summary')}")
    for check in sorted(diagnostics.get("checks", []) or [], key=lambda c: c.get("name", "")):
        status = "ok" if check.get("ok") else "FAIL"
        lines.append(f"  - [{status}] `{check.get('name')}` — {check.get('detail')}")
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
