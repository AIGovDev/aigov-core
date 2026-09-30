#!/usr/bin/env python3
"""Validate a single policy pack directory against marketplace/policy-pack-format.md.

Usage: python3 scripts/validate_policy_pack.py examples/marketplace/<pack-id>
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "python"))


def validate(pack_dir: Path) -> list[str]:
    errors: list[str] = []

    if not pack_dir.is_dir():
        return [f"not a directory: {pack_dir}"]

    readme = pack_dir / "README.md"
    if not readme.exists():
        errors.append("missing README.md")

    module_path = pack_dir / "policy-module.json"
    if not module_path.exists():
        errors.append("missing policy-module.json")
        return errors

    try:
        data = json.loads(module_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        return errors + [f"policy-module.json is not valid JSON: {e}"]

    from aigov_py.standards.policy_module import (
        validate_governance_policy_module_document,
    )

    result = validate_governance_policy_module_document(data)
    if not result.ok:
        for issue in result.issues:
            errors.append(f"policy-module.json: [{issue.code}] {issue.path}: {issue.message}")

    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pack_dir", type=Path)
    parser.add_argument("--json", action="store_true", help="emit a single JSON object on stdout")
    args = parser.parse_args()

    errors = validate(args.pack_dir)
    ok = not errors

    if args.json:
        print(json.dumps({"ok": ok, "pack_dir": str(args.pack_dir), "errors": errors}, sort_keys=True))
    else:
        if ok:
            print(f"validate_policy_pack: OK ({args.pack_dir})")
        else:
            print(f"validate_policy_pack: FAILED ({args.pack_dir})", file=sys.stderr)
            for err in errors:
                print(f"  - {err}", file=sys.stderr)

    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
