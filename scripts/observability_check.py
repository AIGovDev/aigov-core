#!/usr/bin/env python3
"""Aggregated observability diagnostics: manifest, snapshot, Makefile wiring, docs paths.

Runs the manifest validator, the sample-snapshot validator, and checks that
every `required_checks` entry from the manifest exists as a real Makefile
target, then reports one combined ok/errors payload.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(Path(__file__).resolve().parent))

from validate_observability_manifest import MANIFEST_PATH, validate as validate_manifest  # noqa: E402
from validate_operational_snapshot import (  # noqa: E402
    DEFAULT_INPUT as DEFAULT_SNAPSHOT,
    validate as validate_snapshot,
)

MAKEFILE_PATH = ROOT / "Makefile"
TARGET_RE = re.compile(r"^([A-Za-z0-9_.-]+):", re.MULTILINE)


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _makefile_targets() -> set[str]:
    text = MAKEFILE_PATH.read_text(encoding="utf-8")
    return set(TARGET_RE.findall(text))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=MANIFEST_PATH)
    parser.add_argument("--snapshot", type=Path, default=DEFAULT_SNAPSHOT)
    parser.add_argument("--json", action="store_true", help="emit a single JSON object on stdout")
    args = parser.parse_args()

    errors: list[str] = []

    manifest_errors = validate_manifest(args.manifest)
    errors.extend(f"manifest: {e}" for e in manifest_errors)

    manifest = _load(args.manifest) if args.manifest.exists() else {}

    if args.snapshot.exists():
        snapshot = _load(args.snapshot)
        snapshot_errors = validate_snapshot(snapshot, manifest)
        errors.extend(f"snapshot: {e}" for e in snapshot_errors)
    else:
        errors.append(f"snapshot: missing input: {args.snapshot}")

    required_checks = manifest.get("required_checks", [])
    targets = _makefile_targets()
    for check in required_checks:
        if not check.startswith("make "):
            continue
        target = check[len("make ") :].strip()
        if target not in targets:
            errors.append(f"makefile: required_checks target not defined: {target}")

    ok = not errors

    if args.json:
        print(
            json.dumps(
                {
                    "ok": ok,
                    "manifest": str(args.manifest),
                    "snapshot": str(args.snapshot),
                    "errors": errors,
                },
                sort_keys=True,
            )
        )
    else:
        if ok:
            print("observability_check: OK")
        else:
            print("observability_check: FAILED", file=sys.stderr)
            for err in errors:
                print(f"  - {err}", file=sys.stderr)

    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
