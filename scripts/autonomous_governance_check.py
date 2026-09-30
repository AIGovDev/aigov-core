#!/usr/bin/env python3
"""Validate the autonomous/ JSON bundle, manifest cross-references, and wiring.

Per docs/autonomous/validation-tooling.md: validates the autonomous/ JSON
bundle against autonomous/autonomous-governance-schema.json's per-entity
required_fields, checks documentation and example paths, and (with
--multi-agent) additionally validates the sample multi-agent coordination
file against the role models it references.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BUNDLE_DIR = ROOT / "autonomous"
MANIFEST_PATH = BUNDLE_DIR / "autonomous-governance-manifest.json"
SCHEMA_PATH = BUNDLE_DIR / "autonomous-governance-schema.json"
SAMPLE_MULTI_AGENT = ROOT / "examples/autonomous/sample-multi-agent-coordination.json"

REQUIRED_MAKEFILE_TARGETS = ("autonomous-governance-check", "multi-agent-governance-check")

REQUIRED_DOC_PATHS = (
    "docs/autonomous/README.md",
    "docs/agent-governance/README.md",
    "docs/autonomous/role-models.md",
    "docs/autonomous/delegation-and-approval-boundaries.md",
    "docs/autonomous/autonomy-limits-and-interventions.md",
    "docs/autonomous/multi-agent-coordination.md",
    "docs/autonomous/validation-tooling.md",
)

REQUIRED_EXAMPLE_PATHS = (
    "examples/autonomous/README.md",
    "examples/autonomous/run-autonomous-governance-check.sh",
    "examples/autonomous/run-multi-agent-governance-check.sh",
    "examples/autonomous/sample-multi-agent-coordination.json",
)

# entity key in the schema -> (manifest artefact key, filename)
ENTITY_TO_ARTEFACT_KEY = {
    "approval_boundaries": "approval_boundaries",
    "autonomy_limits": "autonomy_limits",
    "delegation_boundaries": "delegation_boundaries",
    "intervention_points": "intervention_points",
    "role_models": "role_models",
}


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _makefile_targets() -> set[str]:
    import re

    text = (ROOT / "Makefile").read_text(encoding="utf-8")
    return set(re.findall(r"^([A-Za-z0-9_.-]+):", text, re.MULTILINE))


def validate(multi_agent: bool) -> list[str]:
    errors: list[str] = []

    if not MANIFEST_PATH.exists():
        return [f"missing: {MANIFEST_PATH.relative_to(ROOT)}"]
    if not SCHEMA_PATH.exists():
        return [f"missing: {SCHEMA_PATH.relative_to(ROOT)}"]

    manifest = _load(MANIFEST_PATH)
    schema = _load(SCHEMA_PATH)

    for key in ("artifact_version", "bundle_id", "artefacts"):
        if key not in manifest:
            errors.append(f"manifest missing key: {key}")

    manifest_check = schema.get("entities", {}).get("manifest", {})
    for field in manifest_check.get("required_fields", []):
        if field not in manifest:
            errors.append(f"manifest missing required_field per schema: {field}")

    artefacts = manifest.get("artefacts", {})
    for entity_key, artefact_key in ENTITY_TO_ARTEFACT_KEY.items():
        rel_path = artefacts.get(artefact_key)
        if not rel_path:
            errors.append(f"manifest.artefacts missing entry: {artefact_key}")
            continue
        path = ROOT / rel_path
        if not path.exists():
            errors.append(f"artefact path missing on disk: {rel_path}")
            continue
        data = _load(path)
        required_fields = schema.get("entities", {}).get(entity_key, {}).get("required_fields", [])
        for field in required_fields:
            if field not in data:
                errors.append(f"{rel_path}: missing required field {field!r} (per schema entity {entity_key!r})")

    for rel_path in REQUIRED_DOC_PATHS:
        if not (ROOT / rel_path).exists():
            errors.append(f"missing documentation path: {rel_path}")

    for rel_path in REQUIRED_EXAMPLE_PATHS:
        if not (ROOT / rel_path).exists():
            errors.append(f"missing example path: {rel_path}")

    targets = _makefile_targets()
    for target in REQUIRED_MAKEFILE_TARGETS:
        if target not in targets:
            errors.append(f"Makefile target not defined: {target}")

    if multi_agent:
        if not SAMPLE_MULTI_AGENT.exists():
            errors.append(f"missing: {SAMPLE_MULTI_AGENT.relative_to(ROOT)}")
        else:
            sample = _load(SAMPLE_MULTI_AGENT)
            role_models_path = ROOT / artefacts.get("role_models", "")
            known_roles: set[str] = set()
            if role_models_path.exists():
                known_roles = {r.get("role_id") for r in _load(role_models_path).get("roles", [])}
            for agent in sample.get("agents", []):
                role_ref = agent.get("role_ref")
                if role_ref not in known_roles:
                    errors.append(
                        f"sample-multi-agent-coordination.json: agent {agent.get('agent_id')!r} "
                        f"references unknown role_ref {role_ref!r}"
                    )
            for edge in sample.get("delegation_graph", []):
                agent_ids = {a.get("agent_id") for a in sample.get("agents", [])}
                if edge.get("from") not in agent_ids:
                    errors.append(f"sample-multi-agent-coordination.json: delegation_graph 'from' unknown agent: {edge.get('from')!r}")
                if edge.get("to") not in agent_ids:
                    errors.append(f"sample-multi-agent-coordination.json: delegation_graph 'to' unknown agent: {edge.get('to')!r}")

    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--multi-agent", action="store_true")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    errors = validate(args.multi_agent)
    ok = not errors

    if args.json:
        print(json.dumps({"ok": ok, "multi_agent": args.multi_agent, "errors": errors}, sort_keys=True))
    else:
        if ok:
            print("autonomous_governance_check: OK")
        else:
            print("autonomous_governance_check: FAILED", file=sys.stderr)
            for err in errors:
                print(f"  - {err}", file=sys.stderr)

    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
