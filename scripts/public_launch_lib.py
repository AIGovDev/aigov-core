"""Shared validation for the local public-launch readiness snapshot."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_INPUT = ROOT / "examples/launch/sample-standardization-readiness-snapshot.json"

BOOLEAN_FIELDS = (
    ("documentation.index_linked", "documentation", "index_linked"),
    ("documentation.launch_docs_complete", "documentation", "launch_docs_complete"),
    ("documentation.readme_public_section", "documentation", "readme_public_section"),
    ("ecosystem.ci_artifacts_defined", "ecosystem", "ci_artifacts_defined"),
    ("ecosystem.example_scripts_present", "ecosystem", "example_scripts_present"),
    ("ecosystem.make_targets_defined", "ecosystem", "make_targets_defined"),
    ("certification.disclaimer_acknowledged", "certification", "disclaimer_acknowledged"),
    (
        "certification.human_approval_gate_documented",
        "certification",
        "human_approval_gate_documented",
    ),
)
STANDARDIZATION_FIELDS = (
    ("standardization.interchange_conformance", "interchange_conformance"),
    ("standardization.policy_pack_examples", "policy_pack_examples"),
    ("standardization.registry_alignment", "registry_alignment"),
)
ALLOWED_STATES = {"ready", "partial", "blocked", "not_started"}
SCOPE = (
    "snapshot checklist only; not adoption metrics, certification, "
    "or proof of production readiness"
)


def _object(value: Any, path: str, errors: list[str]) -> dict[str, Any]:
    if not isinstance(value, dict):
        errors.append(f"{path}: expected an object")
        return {}
    return value


def evaluate_snapshot(snapshot: Any) -> dict[str, Any]:
    """Validate and score explicit snapshot fields; no network or repo writes."""
    errors: list[str] = []
    if not isinstance(snapshot, dict):
        snapshot = {}
        errors.append("$: expected an object")

    if snapshot.get("schema_version") != 1:
        errors.append("schema_version: expected 1")
    snapshot_id = snapshot.get("snapshot_id")
    if not isinstance(snapshot_id, str) or not snapshot_id.strip():
        errors.append("snapshot_id: expected a non-empty string")
    captured_at = snapshot.get("captured_at")
    if not isinstance(captured_at, str) or not captured_at.strip():
        errors.append("captured_at: expected a non-empty ISO-8601 string")

    groups = {
        name: _object(snapshot.get(name), name, errors)
        for name in ("documentation", "ecosystem", "certification", "standardization", "risks")
    }

    checks: list[dict[str, Any]] = []
    if not errors:
        for name, group, field in BOOLEAN_FIELDS:
            value = groups[group].get(field)
            if not isinstance(value, bool):
                errors.append(f"{name}: expected a boolean")
            else:
                checks.append({"name": name, "passed": value})

        for name, field in STANDARDIZATION_FIELDS:
            value = groups["standardization"].get(field)
            if not isinstance(value, str) or value not in ALLOWED_STATES:
                errors.append(f"{name}: expected one of {', '.join(sorted(ALLOWED_STATES))}")
            else:
                checks.append({"name": name, "passed": value == "ready", "state": value})

        for field in ("open_blocking_issues", "open_warnings"):
            value = groups["risks"].get(field)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                errors.append(f"risks.{field}: expected a non-negative integer")
            else:
                checks.append({"name": f"risks.{field}", "passed": value == 0, "count": value})

    passed = sum(check["passed"] for check in checks)
    total = len(checks)
    score = round(100 * passed / total) if total else 0
    return {
        "ok": not errors and passed == total,
        "snapshot_id": snapshot_id if isinstance(snapshot_id, str) else None,
        "captured_at": captured_at if isinstance(captured_at, str) else None,
        "score": score,
        "checks_passed": passed,
        "checks_total": total,
        "checks": checks,
        "errors": errors,
        "scope": SCOPE,
    }


def load_snapshot(path: Path) -> tuple[dict[str, Any] | None, list[str]]:
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        return None, [f"cannot read {path}: {exc}"]
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        return None, [f"invalid JSON at line {exc.lineno}, column {exc.colno}: {exc.msg}"]
    if not isinstance(value, dict):
        return None, ["$: expected a JSON object"]
    return value, []


def json_text(payload: dict[str, Any]) -> str:
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def failure_payload(errors: list[str]) -> dict[str, Any]:
    return {
        "ok": False,
        "snapshot_id": None,
        "captured_at": None,
        "score": 0,
        "checks_passed": 0,
        "checks_total": 0,
        "checks": [],
        "errors": errors,
        "scope": SCOPE,
    }


def report_text(payload: dict[str, Any]) -> str:
    lines = [
        "# Public launch snapshot report",
        "",
        f"- Snapshot: `{payload.get('snapshot_id') or 'unknown'}`",
        f"- Captured at: `{payload.get('captured_at') or 'unknown'}`",
        f"- Checklist: {payload['checks_passed']}/{payload['checks_total']} ({payload['score']}%)",
        f"- Result: {'PASS' if payload['ok'] else 'NOT READY'}",
        f"- Scope: {payload['scope']}",
        "",
        "## Checks",
        "",
        "| Check | Result | Detail |",
        "|---|---|---|",
    ]
    for check in payload["checks"]:
        detail = check.get("state", check.get("count", ""))
        lines.append(f"| `{check['name']}` | {'PASS' if check['passed'] else 'FAIL'} | {detail} |")
    for error in payload["errors"]:
        lines.append(f"| Input validation | FAIL | {error} |")
    lines.extend(
        [
            "",
            "This report summarizes only the supplied snapshot; it does not "
            "independently verify its claims.",
            "",
        ]
    )
    return "\n".join(lines)
