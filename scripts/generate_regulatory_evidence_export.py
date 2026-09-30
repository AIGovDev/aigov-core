#!/usr/bin/env python3
"""Deterministic regulator-facing Markdown bundle from the regulatory evidence manifest.

Per docs/regulatory/regulatory-evidence-manifest.json's operational_probes
entry: builds a Markdown export from the manifest and the AI Act obligations
index. This is technical scaffolding only — see the manifest's own
non_goals: it does not assert legal conformity, CE marking, or Notified
Body outcomes, and does not replace counsel review.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = ROOT / "docs/regulatory/regulatory-evidence-manifest.json"
OBLIGATIONS_PATH = ROOT / "docs/regulatory/ai-act-obligations.json"


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def render(manifest: dict, obligations: dict) -> str:
    lines: list[str] = []
    lines.append("# Regulatory evidence export")
    lines.append("")
    lines.append(
        "> Technical scaffolding only. Does not assert legal conformity, CE marking, or Notified Body outcomes "
        "— see `non_goals` in the source manifest."
    )
    lines.append("")

    lines.append("## Scope")
    lines.append("")
    scope = manifest.get("ai_act_mapping_scope", {})
    lines.append(f"{scope.get('summary', '')}")
    lines.append("")

    lines.append("## Evidence themes")
    lines.append("")
    for theme in sorted(manifest.get("evidence_themes", []), key=lambda t: t.get("id", "")):
        lines.append(f"### {theme.get('id')}")
        lines.append("")
        lines.append(theme.get("summary", ""))
        lines.append("")
        lines.append(f"Guide: `{theme.get('guide')}`")
        lines.append("")

    lines.append("## AI Act obligations index")
    lines.append("")
    for ob in sorted(obligations.get("obligations", []), key=lambda o: o.get("id", "")):
        lines.append(f"### {ob.get('article_reference')} — {ob.get('title')}")
        lines.append("")
        lines.append(f"- `id`: {ob.get('id')}")
        lines.append(f"- `category`: {ob.get('category')}")
        lines.append(f"- summary: {ob.get('summary')}")
        lines.append(f"- GovAI mapping: {ob.get('govai_mapping')}")
        for ep in ob.get("evidence_paths", []):
            lines.append(f"- evidence path: `{ep}`")
        lines.append("")

    lines.append("## Non-goals")
    lines.append("")
    for item in manifest.get("non_goals", []):
        lines.append(f"- {item}")
    lines.append("")

    lines.append("## Export metadata")
    lines.append("")
    lines.append(f"- manifest: `{MANIFEST_PATH.relative_to(ROOT)}`")
    lines.append(f"- obligations index: `{OBLIGATIONS_PATH.relative_to(ROOT)}`")
    lines.append("")

    return "\n".join(line.rstrip() for line in lines).rstrip("\n") + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=MANIFEST_PATH)
    parser.add_argument("--obligations", type=Path, default=OBLIGATIONS_PATH)
    parser.add_argument("--out", type=Path, default=None)
    args = parser.parse_args()

    if not args.manifest.exists():
        print(f"error: missing manifest: {args.manifest}", file=sys.stderr)
        return 1
    if not args.obligations.exists():
        print(f"error: missing obligations index: {args.obligations}", file=sys.stderr)
        return 1

    export = render(_load(args.manifest), _load(args.obligations))

    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(export, encoding="utf-8")
    else:
        sys.stdout.write(export)

    return 0


if __name__ == "__main__":
    sys.exit(main())
