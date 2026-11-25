"""The customer-facing pilot report. Written from the run's own records, not from expectations.

Authorization and execution are reported separately throughout: a decision that allows a call is not proof that the
call ran, and only an executor receipt says it did.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from pilot_config import TENANT
from pilot_workflow import PilotRun, Step

LIMITATIONS = [
    "Synthetic data only. The records, identities, and tools are invented for this pilot.",
    (
        "Identities and approver names are static configuration. There is no identity provider, so the approver identity "
        "is only as strong as the credential that was issued for it."
    ),
    "API keys are bearer secrets for this pilot. They are generated per run and removed at the end.",
    (
        "Core's policy-signing key and its execution-authorization key are environment secrets in this pilot. A deployment "
        "must hold them in a managed key store and rotate the pinned authorization key."
    ),
    (
        "The executor in this pilot is a local process with a local SQLite store. Executors on several hosts need a shared "
        "store with the same atomic reservation."
    ),
    (
        "Revocation stops an authorization that the executor has not yet checked. It does not stop a side effect that has "
        "started, and it does not undo a completed one."
    ),
    (
        "Exactly-once execution across external systems is not claimed. A crash between a side effect and its receipt leaves "
        "a reservation with no receipt, which an operator must reconcile."
    ),
    "The approval window is a demonstration value (30 seconds). A production policy would set minutes.",
    (
        "This pilot does not certify the system and does not establish compliance with any regulation, including the EU AI "
        "Act. It shows how a policy decision, a human approval, and an execution receipt are recorded and checked."
    ),
    "Latency is from one machine and one run. It is not a capacity claim.",
]


def _yn(ok: bool) -> str:
    return "pass" if ok else "FAIL"


def _step_block(s: Step) -> list[str]:
    lines = [
        f"### Step {s.step}: {s.title}",
        "",
        (f"- Requested action: `{s.requested_action}` with `{_short(s.arguments)}`"),
    ]
    lines.append(
        f"- Core decision: **{s.core_decision or 'n/a'}**, reason `{s.core_reason or 'n/a'}`"
    )
    if s.approval_event_id:
        lines.append(f"- Approval reference: `{s.approval_event_id}`")
    if s.authorization_id:
        lines.append(
            f"- Execution authorization: `{s.authorization_id}` (expires `{s.authorization_expires_at}`)"
        )
    if s.executor_reason is None:
        lines.append("- Execution: not attempted by the executor at this step")
    else:
        lines.append(
            f"- Execution: {'ran' if s.executed else 'did not run'}; executor reason `{s.executor_reason}`"
        )
    lines.append(
        f"- Execution receipt recorded: {'yes' if s.receipt_recorded else 'no'}"
    )
    if s.core_record_hash:
        lines.append(
            f"- Core record: event `{s.core_event_id}`, record hash `{s.core_record_hash}`"
        )
    if s.timings_ms:
        parts = ", ".join(f"{k} {v:.1f}" for k, v in s.timings_ms.items())
        lines.append(f"- Timings (ms): {parts}")
    lines.append("")
    lines.append("| Check | Result | Detail |")
    lines.append("|---|---|---|")
    for c in s.checks:
        lines.append(f"| {c['name']} | {_yn(c['ok'])} | {c['detail'] or ''} |")
    lines.append("")
    return lines


def _short(args: dict[str, Any]) -> str:
    text = ", ".join(f"{k}={v}" for k, v in args.items())
    return text if len(text) <= 90 else text[:87] + "..."


def write_report(
    out_dir: Path, run: PilotRun, running: Any, timings: dict[str, float]
) -> Path:
    total_checks = sum(len(s.checks) for s in run.steps)
    passed = sum(1 for s in run.steps for c in s.checks if c["ok"])
    evidence_ok = all(c["ok"] for c in run.evidence_checks)
    accepted = sum(1 for a in run.acceptance if a["ok"])
    lines = [
        "# AIGov Core customer pilot report",
        "",
        (
            "Synthetic data. This report describes one run of the pilot on the local machine. It is not a certification and "
            "does not establish compliance with any regulation."
        ),
        "",
        "## Summary",
        "",
        f"- Run: `{run.run_id}` (tenant `{TENANT}`)",
        f"- Started (UTC): {run.started_utc}; finished (UTC): {run.finished_utc}",
        f"- Core: {running.mode}, at {running.core_url}",
        f"- Policy revision stamped by Core: `{run.policy_revision or 'n/a'}`",
        f"- Step checks passed: {passed} of {total_checks}",
        f"- Acceptance criteria met: {accepted} of {len(run.acceptance)}",
        (
            f"- Evidence verification: {'pass' if evidence_ok else 'FAIL'} "
            f"({len(run.evidence_checks)} checks)"
        ),
        "",
        "## Startup and timing",
        "",
        "| Measure | Value |",
        "|---|---|",
    ]
    for k, v in timings.items():
        lines.append(f"| {k.replace('_', ' ')} | {v} |")
    lines.append(f"| workflow total (ms) | {run.timings_ms['workflow_total_ms']} |")
    lines.append("")
    lines.append("## Acceptance criteria")
    lines.append("")
    lines.append("| Criterion | Result | Evidence in this run |")
    lines.append("|---|---|---|")
    for a in run.acceptance:
        lines.append(f"| {a['criterion']} | {_yn(a['ok'])} | {a['evidence']} |")
    lines.append("")
    lines.append("## Workflow")
    lines.append("")
    for s in run.steps:
        lines.extend(_step_block(s))
    lines.append("## Authorization and execution, kept apart")
    lines.append("")
    lines.append(
        "A Core decision of ALLOW gives an authorization. It does not show that anything ran. The executor's "
        "receipt is the only record that a call ran, and each receipt names the authorization it used."
    )
    lines.append("")
    lines.append("| Authorization | Executed | Receipt |")
    lines.append("|---|---|---|")
    for s in run.steps:
        if s.authorization_id:
            lines.append(
                f"| `{s.authorization_id}` ({s.requested_action}) | {'yes' if s.executed else 'no'} | "
                f"{'yes' if s.receipt_recorded else 'no'} |"
            )
    lines.append("")
    lines.append("## Evidence verification")
    lines.append("")
    lines.append(
        f"Core's ledger for this run: {run.export_summary.get('events', 0)} events, "
        f"{run.export_summary.get('authorizations_issued', 0)} authorizations issued, "
        f"{run.export_summary.get('receipts', 0)} receipts. Event types: "
        f"{', '.join(run.export_summary.get('event_types', []))}."
    )
    lines.append("")
    lines.append("| Check | Result | Detail |")
    lines.append("|---|---|---|")
    for c in run.evidence_checks:
        lines.append(f"| {c['name']} | {_yn(c['ok'])} | {c['detail']} |")
    lines.append("")
    lines.append(
        "The export and the authorizations are in `evidence/`. The offline checks use only those files and the "
        "pinned authorization public key, so a reviewer can rerun them without access to Core."
    )
    lines.append("")
    lines.append("## Limitations")
    lines.append("")
    for item in LIMITATIONS:
        lines.append(f"- {item}")
    lines.append("")
    path = out_dir / "pilot-report.md"
    path.write_text("\n".join(lines), encoding="utf-8")
    return path
