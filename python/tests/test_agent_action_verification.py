"""
AIGov Agent Action Verification Tests — WS3.

Covers all 14 security/failure scenarios specified in the task plus the
canonical happy-path execution.  Tests are stdlib-only (no live network).

Scenarios tested:
  AAV-01  Valid authorized execution
  AAV-02  Approval payload mismatch (post-approval mutation)
  AAV-03  Action mutation after approval (cross-paired digest)
  AAV-04  Replay of an approval token
  AAV-05  Missing approval
  AAV-06  Tampered evidence (chain_digest mismatch)
  AAV-07  Missing read-back evidence
  AAV-08  Partial execution failure
  AAV-09  Duplicate execution (idempotency guard)
  AAV-10  Post-execution overwrite detected via read-back mismatch
  AAV-11  Wrong tenant rejection
  AAV-12  Broken evidence chain
  AAV-13  Verifier distinguishes proposal/approved/executed/observed states
  AAV-14  Deterministic canonical payload across repeated calls
"""

from __future__ import annotations

import hashlib
import json
import uuid
from typing import Any

import pytest

from aigov_py.agent_action_verification import (
    AgentProposal,
    ApprovalGate,
    EvidencePackage,
    EvidenceRecorder,
    ExecutionResult,
    HumanApproval,
    ProcurementRecord,
    SyntheticProcurementApp,
    VerificationVerdict,
    _compute_chain_digest,
    run_agent_action_scenario,
    verify_evidence,
)

_TENANT = "tenant-test"
_AGENT = "proc-agent-v1"
_APPROVER = "compliance-officer"
_RECORD_ID = "proc-2026-001"
_INITIAL = "2027-06-30T17:00:00+02:00"
_PROPOSED = "2027-07-02T17:00:00+02:00"


def _base_proposal(**kwargs: Any) -> AgentProposal:
    return AgentProposal(
        proposal_id=str(uuid.uuid4()),
        agent_id=_AGENT,
        tenant_id=_TENANT,
        record_id=_RECORD_ID,
        field="deadline",
        proposed_value=_PROPOSED,
        rationale="Supplier delay.",
        **kwargs,
    )


def _base_execution(
    *,
    executed_value: str = _PROPOSED,
    readback: str | None = _PROPOSED,
    success: bool = True,
) -> ExecutionResult:
    return ExecutionResult(
        execution_id=str(uuid.uuid4()),
        executed_field="deadline",
        executed_value=executed_value,
        readback_value=readback,
        success=success,
    )


def _make_package(
    proposal: AgentProposal | None = None,
    execution: ExecutionResult | None = None,
    approval: HumanApproval | None = None,
) -> EvidencePackage:
    p = proposal or _base_proposal()
    gate = ApprovalGate()
    a = approval or gate.issue(approver_id=_APPROVER, proposal=p)
    e = execution or _base_execution()
    return EvidencePackage(
        evidence_id=str(uuid.uuid4()),
        proposal=p,
        approval=a,
        execution=e,
    )


# ---------------------------------------------------------------------------
# AAV-01: Valid authorized execution (happy path)
# ---------------------------------------------------------------------------

def test_aav_01_valid_execution_returns_valid_verdict() -> None:
    pkg, result, gate = run_agent_action_scenario()
    assert pkg is not None
    assert result.verdict == VerificationVerdict.VALID
    assert all(v == "PASS" for v in result.checks.values())


def test_aav_01_full_execution_chain_steps_all_present() -> None:
    """Verify all 10 execution chain steps produce observable artefacts."""
    post_calls: list[dict[str, Any]] = []

    def post_fn(d: dict[str, Any]) -> dict[str, Any]:
        post_calls.append(d)
        return {"ok": True, "record_hash": "mocked"}

    pkg, result, _ = run_agent_action_scenario(post_fn=post_fn)
    assert pkg is not None
    # Step 7-8: evidence was posted.
    assert len(post_calls) == 1
    posted = post_calls[0]
    assert posted["event_type"] == "agent_action_executed"
    assert posted["proposal_id"] == pkg.proposal.proposal_id
    assert posted["approval_id"] == pkg.approval.approval_id
    assert posted["chain_digest"] == pkg.chain_digest
    # Step 6: independent read-back present.
    assert pkg.execution.readback_value == _PROPOSED
    # Step 9: verification passed.
    assert result.verdict == VerificationVerdict.VALID


def test_aav_01_readback_matches_executed_value() -> None:
    pkg, result, _ = run_agent_action_scenario()
    assert pkg is not None
    assert pkg.execution.readback_value == pkg.execution.executed_value


# ---------------------------------------------------------------------------
# AAV-02: Approval payload mismatch (post-approval mutation)
# ---------------------------------------------------------------------------

def test_aav_02_payload_mismatch_gives_unauthorized() -> None:
    _, result, _ = run_agent_action_scenario(
        approval_payload_override="sha256:" + "b" * 64,
    )
    assert result.verdict == VerificationVerdict.UNAUTHORIZED


def test_aav_02_approval_bound_check_fails_on_mismatch() -> None:
    proposal = _base_proposal()
    gate = ApprovalGate()
    approval = gate.issue(approver_id=_APPROVER, proposal=proposal)
    # Tamper: change approved digest after issuance.
    import dataclasses
    tampered_approval = dataclasses.replace(
        approval,
        approved_payload_digest="sha256:" + "00" * 32,
    )
    pkg = _make_package(proposal=proposal, approval=tampered_approval)
    result = verify_evidence(pkg)
    assert result.checks["approval_bound"] == "FAIL"
    assert result.verdict in (VerificationVerdict.UNAUTHORIZED, VerificationVerdict.TAMPERED,
                               VerificationVerdict.INVALID)


# ---------------------------------------------------------------------------
# AAV-03: Action mutation after approval (cross-paired digest)
# ---------------------------------------------------------------------------

def test_aav_03_cross_paired_proposal_gives_unauthorized() -> None:
    _, result, _ = run_agent_action_scenario(simulate_cross_pair=True)
    assert result.verdict == VerificationVerdict.UNAUTHORIZED


# ---------------------------------------------------------------------------
# AAV-04: Replay of an approval token
# ---------------------------------------------------------------------------

def test_aav_04_replayed_approval_gives_replay_verdict() -> None:
    _, result, _ = run_agent_action_scenario(simulate_replay=True)
    assert result.verdict == VerificationVerdict.REPLAY


def test_aav_04_approval_gate_rejects_second_consume() -> None:
    proposal = _base_proposal()
    gate = ApprovalGate()
    approval = gate.issue(approver_id=_APPROVER, proposal=proposal)
    assert gate.validate(approval, proposal=proposal) is None
    gate.consume(approval.approval_id)
    err = gate.validate(approval, proposal=proposal)
    assert err == "REPLAY"


# ---------------------------------------------------------------------------
# AAV-05: Missing approval
# ---------------------------------------------------------------------------

def test_aav_05_missing_approval_gives_missing_approval_verdict() -> None:
    _, result, _ = run_agent_action_scenario(simulate_missing_approval=True)
    assert result.verdict == VerificationVerdict.MISSING_APPROVAL


def test_aav_05_unknown_approval_id_rejected_by_gate() -> None:
    proposal = _base_proposal()
    gate = ApprovalGate()
    fake_approval = HumanApproval(
        approval_id=str(uuid.uuid4()),
        approver_id=_APPROVER,
        proposal_id=proposal.proposal_id,
        approved_payload_digest=proposal.payload_digest,
    )
    err = gate.validate(fake_approval, proposal=proposal)
    assert err == "UNKNOWN_APPROVAL"


# ---------------------------------------------------------------------------
# AAV-06: Tampered evidence (chain_digest mismatch)
# ---------------------------------------------------------------------------

def test_aav_06_tampered_readback_detected() -> None:
    pkg, _, _ = run_agent_action_scenario()
    assert pkg is not None
    # Silently change readback after recording — chain_digest will not match.
    import dataclasses
    pkg.execution = dataclasses.replace(pkg.execution, readback_value="2099-01-01T00:00:00Z")
    result = verify_evidence(pkg)
    assert result.verdict == VerificationVerdict.TAMPERED
    assert result.checks["chain_integrity"] == "FAIL"


def test_aav_06_tampered_proposed_value_detected() -> None:
    pkg, _, _ = run_agent_action_scenario()
    assert pkg is not None
    import dataclasses
    # Mutate executed_value after recording.
    pkg.execution = dataclasses.replace(pkg.execution, executed_value="2099-12-31T00:00:00Z")
    result = verify_evidence(pkg)
    assert result.verdict == VerificationVerdict.TAMPERED


# ---------------------------------------------------------------------------
# AAV-07: Missing read-back evidence
# ---------------------------------------------------------------------------

def test_aav_07_missing_readback_flagged() -> None:
    _, result, _ = run_agent_action_scenario(simulate_missing_readback=True)
    assert result.verdict in (
        VerificationVerdict.MISSING_READBACK,
        VerificationVerdict.INVALID,
    )
    assert result.checks.get("readback_match") == "FAIL"


# ---------------------------------------------------------------------------
# AAV-08: Partial execution failure
# ---------------------------------------------------------------------------

def test_aav_08_failed_execution_propagated_in_evidence() -> None:
    proposal = _base_proposal()
    gate = ApprovalGate()
    approval = gate.issue(approver_id=_APPROVER, proposal=proposal)
    execution = _base_execution(success=False, readback=_INITIAL)
    pkg = _make_package(proposal=proposal, approval=approval, execution=execution)
    # Read-back shows original value → executed_value != readback_value → INVALID.
    result = verify_evidence(pkg)
    assert result.checks["readback_match"] == "FAIL"
    assert result.verdict in (VerificationVerdict.INVALID, VerificationVerdict.TAMPERED)


# ---------------------------------------------------------------------------
# AAV-09: Duplicate execution (idempotency guard in target app)
# ---------------------------------------------------------------------------

def test_aav_09_duplicate_execution_id_rejected() -> None:
    app = SyntheticProcurementApp()
    app.seed(ProcurementRecord(record_id="r1", description="test", deadline_iso=_INITIAL))
    eid = "exec-dup-1"
    assert app.apply(execution_id=eid, record_id="r1", field="deadline", value=_PROPOSED)
    assert not app.apply(execution_id=eid, record_id="r1", field="deadline", value=_PROPOSED)
    # State should still be the first applied value.
    assert app.read("r1").deadline_iso == _PROPOSED


# ---------------------------------------------------------------------------
# AAV-10: Post-execution overwrite detected via read-back mismatch
# ---------------------------------------------------------------------------

def test_aav_10_post_execution_overwrite_detected() -> None:
    app = SyntheticProcurementApp()
    app.seed(ProcurementRecord(record_id=_RECORD_ID, description="test", deadline_iso=_INITIAL))
    execution_id = "exec-overwrite-1"
    app.apply(execution_id=execution_id, record_id=_RECORD_ID, field="deadline", value=_PROPOSED)
    # Overwrite with a different value (different execution_id).
    app.apply(execution_id="exec-overwrite-2", record_id=_RECORD_ID, field="deadline", value="2099-01-01T00:00:00Z")
    # Read-back shows the overwrite.
    actual = app.read(_RECORD_ID)
    assert actual.deadline_iso == "2099-01-01T00:00:00Z"
    # An evidence package recording the first execution but reading back the overwritten value
    # will show a mismatch.
    proposal = _base_proposal()
    gate = ApprovalGate()
    approval = gate.issue(approver_id=_APPROVER, proposal=proposal)
    execution = ExecutionResult(
        execution_id=execution_id,
        executed_field="deadline",
        executed_value=_PROPOSED,
        readback_value="2099-01-01T00:00:00Z",  # post-execution overwrite observed
        success=True,
    )
    pkg = EvidencePackage(
        evidence_id=str(uuid.uuid4()),
        proposal=proposal,
        approval=approval,
        execution=execution,
    )
    result = verify_evidence(pkg, expected_field_value=_PROPOSED)
    # readback_match: FAIL (overwrite), expected_state: FAIL.
    assert result.checks["expected_state"] == "FAIL"


# ---------------------------------------------------------------------------
# AAV-11: Wrong tenant rejection
# ---------------------------------------------------------------------------

def test_aav_11_cross_tenant_proposal_produces_mismatched_evidence() -> None:
    """A proposal from tenant A must not be validated against tenant B's gate."""
    proposal_a = AgentProposal(
        proposal_id=str(uuid.uuid4()),
        agent_id=_AGENT,
        tenant_id="tenant-A",
        record_id=_RECORD_ID,
        field="deadline",
        proposed_value=_PROPOSED,
        rationale="From tenant A.",
    )
    gate_b = ApprovalGate()
    # Gate for tenant B would refuse because it doesn't know about proposal_a.
    approval_b = HumanApproval(
        approval_id=str(uuid.uuid4()),
        approver_id=_APPROVER,
        proposal_id="different-proposal-id",
        approved_payload_digest="sha256:" + "00" * 32,
    )
    gate_b._approvals[approval_b.approval_id] = approval_b
    err = gate_b.validate(approval_b, proposal=proposal_a)
    # Digest mismatch because approval was issued for a different proposal.
    assert err in ("PAYLOAD_MISMATCH", "UNKNOWN_APPROVAL")


# ---------------------------------------------------------------------------
# AAV-12: Broken evidence chain
# ---------------------------------------------------------------------------

def test_aav_12_modified_chain_digest_detected() -> None:
    pkg, _, _ = run_agent_action_scenario()
    assert pkg is not None
    # Directly corrupt the chain_digest field.
    pkg.chain_digest = "sha256:" + "ff" * 32
    result = verify_evidence(pkg)
    assert result.checks["chain_integrity"] == "FAIL"
    assert result.verdict == VerificationVerdict.TAMPERED


# ---------------------------------------------------------------------------
# AAV-13: Verifier distinguishes proposal/approved/executed/observed states
# ---------------------------------------------------------------------------

def test_aav_13_verifier_state_quadrant_all_pass_on_valid_execution() -> None:
    """
    For a valid execution, the verifier must distinguish and validate:
    - proposed action (proposal.payload_digest)
    - approved action (approval.approved_payload_digest == proposed)
    - executed action (execution.executed_value == proposed)
    - observed final state (execution.readback_value == executed)
    """
    pkg, result, _ = run_agent_action_scenario()
    assert pkg is not None
    # Proposed == approved.
    assert pkg.proposal.payload_digest == pkg.approval.approved_payload_digest
    # Executed == proposed.
    assert pkg.execution.executed_value == pkg.proposal.proposed_value
    # Observed == executed.
    assert pkg.execution.readback_value == pkg.execution.executed_value
    # All checks pass.
    assert result.checks["approval_bound"] == "PASS"
    assert result.checks["execution_match"] == "PASS"
    assert result.checks["readback_match"] == "PASS"
    assert result.checks["chain_integrity"] == "PASS"


def test_aav_13_all_four_states_can_diverge_independently() -> None:
    """
    Confirm the four states are independently tracked and a divergence in any
    one is detectable.
    """
    proposal = _base_proposal()
    gate = ApprovalGate()
    approval = gate.issue(approver_id=_APPROVER, proposal=proposal)

    # Executed value differs from proposed — execution_match check fails.
    execution_wrong = _base_execution(
        executed_value="2099-01-01T00:00:00Z",
        readback="2099-01-01T00:00:00Z",
    )
    pkg = _make_package(proposal=proposal, approval=approval, execution=execution_wrong)
    result = verify_evidence(pkg)
    assert result.checks["execution_match"] == "FAIL"


# ---------------------------------------------------------------------------
# AAV-14: Deterministic canonical payload across repeated calls
# ---------------------------------------------------------------------------

def test_aav_14_canonical_payload_is_deterministic() -> None:
    """The canonical payload must produce the same bytes on every call."""
    proposal = _base_proposal()
    b1 = proposal.canonical_payload
    b2 = proposal.canonical_payload
    assert b1 == b2


def test_aav_14_different_proposals_have_different_digests() -> None:
    p1 = AgentProposal(
        proposal_id=str(uuid.uuid4()), agent_id=_AGENT, tenant_id=_TENANT,
        record_id=_RECORD_ID, field="deadline",
        proposed_value="2027-07-01T17:00:00+02:00", rationale="delay",
    )
    p2 = AgentProposal(
        proposal_id=str(uuid.uuid4()), agent_id=_AGENT, tenant_id=_TENANT,
        record_id=_RECORD_ID, field="deadline",
        proposed_value="2027-07-02T17:00:00+02:00", rationale="delay",
    )
    assert p1.payload_digest != p2.payload_digest


def test_aav_14_payload_digest_is_stable_sha256_format() -> None:
    proposal = _base_proposal()
    digest = proposal.payload_digest
    assert digest.startswith("sha256:")
    assert len(digest) == len("sha256:") + 64


# ---------------------------------------------------------------------------
# AAV-15: payload_intact detects substituted proposal body
# ---------------------------------------------------------------------------

def test_aav_15_payload_intact_detects_substituted_proposal() -> None:
    """Approval is bound to proposal_A but the EvidencePackage carries proposal_B.

    Before the fix, verify_evidence re-derived the digest from proposal_B and
    compared it to proposal_B's own digest (a tautology — always PASS).  After
    the fix it compares the re-derived digest of proposal_B against the digest
    that was actually approved (proposal_A's digest), which is a mismatch.
    """
    # Build two proposals with different payloads.
    proposal_a = _base_proposal()  # uses default _PROPOSED value
    proposal_b = AgentProposal(   # substituted body — different proposed_value
        proposal_id=str(uuid.uuid4()),
        agent_id=_AGENT,
        tenant_id=_TENANT,
        record_id=_RECORD_ID,
        field="deadline",
        proposed_value="2099-12-31T00:00:00Z",
        rationale="Substituted rationale.",
    )
    assert proposal_a.payload_digest != proposal_b.payload_digest

    # Approval is legitimately issued for proposal_A.
    gate = ApprovalGate()
    approval_for_a = gate.issue(approver_id=_APPROVER, proposal=proposal_a)
    assert approval_for_a.approved_payload_digest == proposal_a.payload_digest

    # Package is built with proposal_B but approval_for_A — simulating substitution.
    execution = _base_execution(executed_value="2099-12-31T00:00:00Z",
                                readback="2099-12-31T00:00:00Z")
    pkg = EvidencePackage(
        evidence_id=str(uuid.uuid4()),
        proposal=proposal_b,
        approval=approval_for_a,
        execution=execution,
    )

    result = verify_evidence(pkg)
    assert result.checks["payload_intact"] == "FAIL", (
        "payload_intact must FAIL when proposal body was substituted after approval"
    )
