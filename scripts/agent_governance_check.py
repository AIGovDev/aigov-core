#!/usr/bin/env python3
"""Aggregated agent governance diagnostics: manifest, snapshot, Makefile wiring, docs."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(Path(__file__).resolve().parent))

from validate_agent_delegation_snapshot import (
    DEFAULT_INPUT as DEFAULT_SNAPSHOT,
)
from validate_agent_delegation_snapshot import (
    validate as validate_snapshot,
)
from validate_agent_governance_manifest import MANIFEST_PATH
from validate_agent_governance_manifest import validate as validate_manifest

REQUIRED_MAKEFILE_TARGETS = (
    "agent-governance",
    "agent-governance-manifest",
    "agent-delegation-snapshot",
    "agent-governance-score",
    "agent-governance-report",
    "agent-governance-check",
)


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _makefile_targets() -> set[str]:
    text = (ROOT / "Makefile").read_text(encoding="utf-8")
    return set(re.findall(r"^([A-Za-z0-9_.-]+):", text, re.MULTILINE))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    errors: list[str] = []

    manifest_errors = validate_manifest(MANIFEST_PATH)
    errors.extend(f"manifest: {e}" for e in manifest_errors)

    manifest = _load(MANIFEST_PATH) if MANIFEST_PATH.exists() else {}

    if DEFAULT_SNAPSHOT.exists():
        snapshot = _load(DEFAULT_SNAPSHOT)
        snapshot_errors = validate_snapshot(snapshot, manifest)
        errors.extend(f"snapshot: {e}" for e in snapshot_errors)
    else:
        errors.append(f"snapshot: missing input: {DEFAULT_SNAPSHOT}")

    targets = _makefile_targets()
    for target in REQUIRED_MAKEFILE_TARGETS:
        if target not in targets:
            errors.append(f"makefile: required target not defined: {target}")

    ok = not errors

    if args.json:
        print(json.dumps({"ok": ok, "errors": errors}, sort_keys=True))
    else:
        print(f"agent_governance_check: {'OK' if ok else 'FAILED'}")
        for err in errors:
            print(f"  - {err}", file=sys.stderr)

    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
