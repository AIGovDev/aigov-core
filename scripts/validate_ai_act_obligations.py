#!/usr/bin/env python3
"""Schema and path validation for docs/regulatory/ai-act-obligations.json."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OBLIGATIONS_PATH = ROOT / "docs/regulatory/ai-act-obligations.json"

REQUIRED_OBLIGATION_FIELDS = (
    "article_reference",
    "category",
    "evidence_paths",
    "govai_mapping",
    "id",
    "summary",
    "title",
)


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def validate(obligations_path: Path) -> list[str]:
    errors: list[str] = []

    if not obligations_path.exists():
        return [f"missing: {obligations_path}"]

    data = _load(obligations_path)

    for key in ("obligations", "summary", "version"):
        if key not in data:
            errors.append(f"missing top-level key: {key}")

    obligations = data.get("obligations", [])
    seen_ids: set[str] = set()
    for i, ob in enumerate(obligations):
        for field in REQUIRED_OBLIGATION_FIELDS:
            if field not in ob:
                errors.append(f"obligations[{i}] ({ob.get('id', '?')}) missing field: {field}")
        ob_id = ob.get("id")
        if ob_id:
            if ob_id in seen_ids:
                errors.append(f"duplicate obligation id: {ob_id}")
            seen_ids.add(ob_id)
        for evidence_path in ob.get("evidence_paths", []):
            if not (ROOT / evidence_path).exists():
                errors.append(f"obligations[{i}] ({ob_id}).evidence_paths missing on disk: {evidence_path}")

    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--obligations", type=Path, default=OBLIGATIONS_PATH)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    errors = validate(args.obligations)
    ok = not errors

    if args.json:
        print(json.dumps({"ok": ok, "obligations": str(args.obligations), "errors": errors}, sort_keys=True))
    else:
        if ok:
            print("validate_ai_act_obligations: OK")
        else:
            print("validate_ai_act_obligations: FAILED", file=sys.stderr)
            for err in errors:
                print(f"  - {err}", file=sys.stderr)

    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
