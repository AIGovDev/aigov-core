#!/usr/bin/env python3
"""
AIGov Agent Action Verification — Interactive CLI Demo.

Demonstrates:
  1. Agent proposal generation
  2. Human approval binding
  3. Actual target-system execution
  4. Independent read-back
  5. Evidence generation
  6. AIGov verification
  7. Deliberate tampering and detection

Usage:
    python benchmarks/agent-verification/demo.py

No credentials, no network, no paid APIs required.
"""

from __future__ import annotations

import sys
from pathlib import Path

# Allow running from repo root.
repo_root = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(repo_root / "python"))

from aigov_py.agent_action_verification import (
    AgentProposal,
    ApprovalGate,
    EvidencePackage,
    EvidenceRecorder,
    ExecutionResult,
    ProcurementRecord,
    SyntheticProcurementApp,
    VerificationVerdict,
    run_agent_action_scenario,
    verify_evidence,
)


def _sep(title: str = "") -> None:
    w = 70
    if title:
        print(f"\n{'─' * 3} {title} {'─' * (w - len(title) - 5)}")
    else:
        print("─" * w)


def _ok(msg: str) -> None:
    print(f"  ✔  {msg}")


def _fail(msg: str) -> None:
    print(f"  ✘  {msg}")


def _info(msg: str) -> None:
    print(f"     {msg}")


def main() -> None:
    print("\nAIGov Agent Action Verification Demo")
    print("====================================")

    _sep("Step 1 — Initial target-system state")
    initial = "2027-06-30T17:00:00+02:00"
    proposed = "2027-07-02T17:00:00+02:00"
    _info(f"Record:   proc-2026-001 | Procurement contract deadline")
    _info(f"Before:   deadline = {initial}")

    _sep("Step 2 — Agent generates a proposed action")
    _info(f"Agent:    procurement-agent-v1")
    _info(f"Proposes: deadline → {proposed}")
    _info(f"Reason:   Supplier requested extension due to supply chain delay.")

    _sep("Step 3 — Approval gate (simulated human approval)")
    _info("Approver: compliance-officer")
    _info("Approval is bound to the exact canonical payload digest.")
    _info("(In production, approval requires a human to review and sign.)")

    _sep("Step 4-9 — Execute, read back, record evidence, verify")
    pkg, result, gate = run_agent_action_scenario(
        initial_deadline=initial,
        proposed_deadline=proposed,
    )
    assert pkg is not None

    _info(f"Execution ID:  {pkg.execution.execution_id[:16]}…")
    _info(f"Payload digest: {pkg.proposal.payload_digest[:30]}…")
    _info(f"Chain digest:   {pkg.chain_digest[:30]}…")
    _info(f"Read-back:      deadline = {pkg.execution.readback_value}")

    _sep("Verification result")
    checks = result.checks
    for check, verdict in checks.items():
        (  _ok if verdict == "PASS" else _fail)(f"{check}: {verdict}")
    print()
    if result.verdict == VerificationVerdict.VALID:
        _ok(f"VERDICT: {result.verdict.value}")
    else:
        _fail(f"VERDICT: {result.verdict.value}")

    _sep("Step 10 — Tamper simulation: post-execution readback modification")
    _info("Adversary modifies evidence.readback_value after recording.")
    import dataclasses
    tampered_pkg = EvidencePackage(
        evidence_id=pkg.evidence_id,
        proposal=pkg.proposal,
        approval=pkg.approval,
        execution=dataclasses.replace(pkg.execution, readback_value="2099-01-01T00:00:00Z"),
        chain_digest=pkg.chain_digest,  # original digest — will mismatch tampered content
    )
    tampered_result = verify_evidence(tampered_pkg)
    _info(f"Tampered readback_value = {tampered_pkg.execution.readback_value}")
    _ok(f"chain_integrity: {tampered_result.checks['chain_integrity']}")  # FAIL
    if tampered_result.verdict == VerificationVerdict.TAMPERED:
        _ok(f"VERDICT: {tampered_result.verdict.value}  ← tampering detected")
    else:
        _fail(f"VERDICT: {tampered_result.verdict.value}  (unexpected)")

    _sep("Comparison — four verification conditions")
    _info(
        f"{'Condition':<30}  {'Accepts?':>8}  {'Note'}"
    )
    _info(
        f"{'A: agent self-report':<30}  {'YES (risk)':>8}  "
        "Agent always claims success"
    )
    _info(
        f"{'B: tool response':<30}  {'YES (risk)':>8}  "
        "Tool API says OK even if state is wrong"
    )
    _info(
        f"{'C: independent state':<30}  {'YES':>8}  "
        "Passes only if read-back matches expected"
    )
    _info(
        f"{'D: AIGov evidence':<30}  {'YES':>8}  "
        "Approval binding + chain + state + execution match"
    )
    _info("")
    _info("For the tampered scenario:")
    _info(
        f"  {'A: agent self-report':<28}  {'YES (miss)':>10}  "
        "Cannot detect post-recording tampering"
    )
    _info(
        f"  {'D: AIGov evidence':<28}  {'NO (detect)':>10}  "
        f"chain_integrity=FAIL → TAMPERED"
    )

    _sep()
    print("\nDemo complete.  All steps executed locally — no network required.\n")


if __name__ == "__main__":
    main()
