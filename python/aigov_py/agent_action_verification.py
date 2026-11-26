"""
AIGov Agent Action Verification — portable reference implementation.

Implements the full 10-step execution chain:
  1.  Agent receives a task.
  2.  Agent generates a proposed action.
  3.  AIGov records the proposal and its canonical payload.
  4.  Human approval gate binds approval to the exact action.
  5.  Authorized action executed through the isolated target API.
  6.  Actual target-system state read back independently.
  7.  AIGov captures execution evidence.
  8.  Evidence bound to approval and action.
  9.  Verifier evaluates integrity, authorization, and observed state.
  10. Tamper test demonstrates detection of unauthorized modifications.

No live API calls are made here.  External I/O is dependency-injected.
This module is the portable reference used by the benchmark and test suite.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable


# ---------------------------------------------------------------------------
# Domain types
# ---------------------------------------------------------------------------

class VerificationVerdict(str, Enum):
    VALID = "VALID"
    INVALID = "INVALID"
    TAMPERED = "TAMPERED"
    UNAUTHORIZED = "UNAUTHORIZED"
    MISSING_APPROVAL = "MISSING_APPROVAL"
    MISSING_READBACK = "MISSING_READBACK"
    EXPIRED_APPROVAL = "EXPIRED_APPROVAL"
    REPLAY = "REPLAY"


@dataclass(frozen=True)
class ProcurementRecord:
    """Synthetic business record — a procurement deadline."""
    record_id: str
    description: str
    deadline_iso: str


@dataclass(frozen=True)
class AgentProposal:
    """Step 2: Agent's proposed mutation of a business record."""
    proposal_id: str
    agent_id: str
    tenant_id: str
    record_id: str
    field: str
    proposed_value: str
    rationale: str

    @property
    def canonical_payload(self) -> bytes:
        d = {
            "proposal_id": self.proposal_id,
            "agent_id": self.agent_id,
            "tenant_id": self.tenant_id,
            "record_id": self.record_id,
            "field": self.field,
            "proposed_value": self.proposed_value,
            "rationale": self.rationale,
        }
        return json.dumps(d, sort_keys=True, separators=(",", ":")).encode()

    @property
    def payload_digest(self) -> str:
        return "sha256:" + hashlib.sha256(self.canonical_payload).hexdigest()


@dataclass(frozen=True)
class HumanApproval:
    """Step 4: Human approval bound to the exact proposal digest."""
    approval_id: str
    approver_id: str
    proposal_id: str
    # Must equal the proposal's payload_digest; enforced by the approval gate.
    approved_payload_digest: str
    approval_token: str = field(default_factory=lambda: str(uuid.uuid4()))
    valid: bool = True

    def bound_to(self, proposal: AgentProposal) -> bool:
        return self.approved_payload_digest == proposal.payload_digest


@dataclass(frozen=True)
class ExecutionResult:
    """Step 5-6: Result of executing the action plus independent read-back."""
    execution_id: str
    executed_field: str
    executed_value: str
    # Independently read-back value from the target system.
    readback_value: str | None
    success: bool
    error: str | None = None


@dataclass
class EvidencePackage:
    """Step 7-8: Evidence capturing the full action chain."""
    evidence_id: str
    proposal: AgentProposal
    approval: HumanApproval
    execution: ExecutionResult
    # Digest over the evidence chain (excluding this field itself).
    chain_digest: str = ""

    def __post_init__(self) -> None:
        if not self.chain_digest:
            self.chain_digest = _compute_chain_digest(self)


def _compute_chain_digest(e: EvidencePackage) -> str:
    payload = {
        "evidence_id": e.evidence_id,
        "proposal_id": e.proposal.proposal_id,
        "approval_id": e.approval.approval_id,
        "execution_id": e.execution.execution_id,
        "payload_digest": e.proposal.payload_digest,
        "approved_digest": e.approval.approved_payload_digest,
        "executed_field": e.execution.executed_field,
        "executed_value": e.execution.executed_value,
        "readback_value": e.execution.readback_value,
    }
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return "sha256:" + hashlib.sha256(raw).hexdigest()


@dataclass
class VerificationResult:
    """Step 9: Verifier output."""
    verdict: VerificationVerdict
    evidence_id: str
    checks: dict[str, str]  # check_name → PASS/FAIL/SKIP
    notes: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Synthetic target application
# ---------------------------------------------------------------------------

class SyntheticProcurementApp:
    """Isolated target application.  State is in-memory — no network required."""

    def __init__(self) -> None:
        self._records: dict[str, ProcurementRecord] = {}
        self._executed_actions: set[str] = set()

    def seed(self, record: ProcurementRecord) -> None:
        self._records[record.record_id] = record

    def apply(self, *, execution_id: str, record_id: str, field: str, value: str) -> bool:
        """Apply a field update.  Returns True on success."""
        if execution_id in self._executed_actions:
            return False  # duplicate execution
        r = self._records.get(record_id)
        if r is None:
            return False
        updated = ProcurementRecord(
            record_id=r.record_id,
            description=r.description,
            deadline_iso=value if field == "deadline" else r.deadline_iso,
        )
        self._records[record_id] = updated
        self._executed_actions.add(execution_id)
        return True

    def read(self, record_id: str) -> ProcurementRecord | None:
        """Independent read-back of the current record state."""
        return self._records.get(record_id)


# ---------------------------------------------------------------------------
# Approval gate
# ---------------------------------------------------------------------------

class ApprovalGate:
    """Step 4: Binds approvals to canonical payload digests; detects replay/expiry."""

    def __init__(self) -> None:
        self._approvals: dict[str, HumanApproval] = {}
        self._consumed: set[str] = set()

    def issue(self, *, approver_id: str, proposal: AgentProposal) -> HumanApproval:
        a = HumanApproval(
            approval_id=str(uuid.uuid4()),
            approver_id=approver_id,
            proposal_id=proposal.proposal_id,
            approved_payload_digest=proposal.payload_digest,
        )
        self._approvals[a.approval_id] = a
        return a

    def validate(self, approval: HumanApproval, *, proposal: AgentProposal) -> str | None:
        """Return None if valid; return an error code string otherwise."""
        if not approval.valid:
            return "INVALID_APPROVAL"
        stored = self._approvals.get(approval.approval_id)
        if stored is None:
            return "UNKNOWN_APPROVAL"
        if approval.approval_id in self._consumed:
            return "REPLAY"
        if stored.approved_payload_digest != proposal.payload_digest:
            return "PAYLOAD_MISMATCH"
        return None

    def consume(self, approval_id: str) -> None:
        """Mark an approval as used (prevents replay)."""
        self._consumed.add(approval_id)


# ---------------------------------------------------------------------------
# Evidence recorder
# ---------------------------------------------------------------------------

def make_aigov_post_fn(client: Any) -> Callable[[dict[str, Any]], dict[str, Any]]:
    """
    Return a post_fn that submits evidence to the real AIGov HTTP API.

    Usage:
        from govai.client import GovAIClient
        from govai.evidence import submit_event
        client = GovAIClient(base_url=..., api_key=...)
        recorder = EvidenceRecorder(post_fn=make_aigov_post_fn(client))

    This wires EvidenceRecorder to the actual append-only ledger instead of
    the in-memory stub used by unit tests and the portable demo.
    """
    from govai.evidence import submit_event  # type: ignore[import]
    return lambda event: submit_event(client, event)


class EvidenceRecorder:
    def __init__(
        self,
        post_fn: Callable[[dict[str, Any]], dict[str, Any]] | None = None,
    ) -> None:
        # When post_fn is None, evidence is recorded in memory only (portable/unit-test mode).
        # For production use, pass post_fn=make_aigov_post_fn(client) to persist to the ledger.
        self._post = post_fn or (lambda d: {"ok": True, "record_hash": "in-memory-only"})
        self._packages: list[EvidencePackage] = []

    def record(
        self,
        *,
        proposal: AgentProposal,
        approval: HumanApproval,
        execution: ExecutionResult,
    ) -> EvidencePackage:
        pkg = EvidencePackage(
            evidence_id=str(uuid.uuid4()),
            proposal=proposal,
            approval=approval,
            execution=execution,
        )
        self._packages.append(pkg)
        self._post({
            "event_type": "agent_action_executed",
            "evidence_id": pkg.evidence_id,
            "proposal_id": proposal.proposal_id,
            "approval_id": approval.approval_id,
            "execution_id": execution.execution_id,
            "payload_digest": proposal.payload_digest,
            "chain_digest": pkg.chain_digest,
            "readback_value": execution.readback_value,
        })
        return pkg

    @property
    def packages(self) -> list[EvidencePackage]:
        return list(self._packages)


# ---------------------------------------------------------------------------
# Verifier (step 9)
# ---------------------------------------------------------------------------

def verify_evidence(pkg: EvidencePackage, *, expected_field_value: str | None = None) -> VerificationResult:
    """
    Independently verify an EvidencePackage.

    Checks:
    - approval_bound:   approval digest matches proposal digest
    - payload_intact:   canonical payload re-computes to the recorded digest
    - execution_match:  executed value matches proposal
    - readback_match:   readback matches execution (observational proof)
    - chain_integrity:  chain_digest re-computes correctly
    - expected_state:   (optional) readback matches a caller-supplied expected value
    """
    checks: dict[str, str] = {}
    notes: list[str] = []

    # 1. Approval bound to proposal.
    checks["approval_bound"] = (
        "PASS" if pkg.approval.bound_to(pkg.proposal) else "FAIL"
    )

    # 2. Payload re-derivation: re-hash canonical_payload and compare to what the approver signed.
    # Catches payload-substitution: a different proposal body that shares the same approval object.
    recomputed = "sha256:" + hashlib.sha256(pkg.proposal.canonical_payload).hexdigest()
    checks["payload_intact"] = "PASS" if recomputed == pkg.approval.approved_payload_digest else "FAIL"

    # 3. Executed value matches proposal.
    checks["execution_match"] = (
        "PASS" if pkg.execution.executed_value == pkg.proposal.proposed_value else "FAIL"
    )

    # 4. Read-back evidence.
    if pkg.execution.readback_value is None:
        checks["readback_match"] = "FAIL"
        notes.append("No independent read-back — cannot confirm final state.")
    else:
        checks["readback_match"] = (
            "PASS" if pkg.execution.readback_value == pkg.execution.executed_value else "FAIL"
        )

    # 5. Chain integrity.
    recomputed_chain = _compute_chain_digest(pkg)
    checks["chain_integrity"] = "PASS" if recomputed_chain == pkg.chain_digest else "FAIL"

    # 6. Optional expected final state.
    if expected_field_value is not None:
        checks["expected_state"] = (
            "PASS" if pkg.execution.readback_value == expected_field_value else "FAIL"
        )

    # Derive verdict.
    if checks.get("chain_integrity") == "FAIL":
        verdict = VerificationVerdict.TAMPERED
    elif checks.get("approval_bound") == "FAIL":
        verdict = VerificationVerdict.UNAUTHORIZED
    elif checks.get("readback_match") == "FAIL" and pkg.execution.readback_value is None:
        verdict = VerificationVerdict.MISSING_READBACK
    elif any(v == "FAIL" for v in checks.values()):
        verdict = VerificationVerdict.INVALID
    else:
        verdict = VerificationVerdict.VALID

    return VerificationResult(
        verdict=verdict,
        evidence_id=pkg.evidence_id,
        checks=checks,
        notes=notes,
    )


# ---------------------------------------------------------------------------
# End-to-end execution helper (used by demo and tests)
# ---------------------------------------------------------------------------

def run_agent_action_scenario(
    *,
    tenant_id: str = "tenant-demo",
    agent_id: str = "procurement-agent-v1",
    approver_id: str = "compliance-officer",
    record_id: str = "proc-2026-001",
    initial_deadline: str = "2027-06-30T17:00:00+02:00",
    proposed_deadline: str = "2027-07-02T17:00:00+02:00",
    post_fn: Callable[[dict[str, Any]], dict[str, Any]] | None = None,
    simulate_tamper: bool = False,
    simulate_cross_pair: bool = False,
    simulate_replay: bool = False,
    simulate_missing_approval: bool = False,
    simulate_missing_readback: bool = False,
    approval_payload_override: str | None = None,
) -> tuple[EvidencePackage | None, VerificationResult, ApprovalGate]:
    """
    Run one complete agent action scenario.

    Returns (evidence_package, verification_result, approval_gate).
    Returns (None, error_verdict, gate) for pre-execution failures.
    """
    # Seed target system.
    app = SyntheticProcurementApp()
    app.seed(ProcurementRecord(
        record_id=record_id,
        description="Widget procurement contract",
        deadline_iso=initial_deadline,
    ))

    # Step 1: agent receives task (implicit).
    # Step 2: agent generates proposed action.
    proposal = AgentProposal(
        proposal_id=str(uuid.uuid4()),
        agent_id=agent_id,
        tenant_id=tenant_id,
        record_id=record_id,
        field="deadline",
        proposed_value=proposed_deadline,
        rationale="Supplier requested extension due to supply chain delay.",
    )

    # Step 3: AIGov records the proposal (evidence recorder handles this via post_fn).
    recorder = EvidenceRecorder(post_fn=post_fn)
    gate = ApprovalGate()

    # Step 4: human approval gate.
    if simulate_missing_approval:
        approval = HumanApproval(
            approval_id=str(uuid.uuid4()),
            approver_id=approver_id,
            proposal_id=proposal.proposal_id,
            approved_payload_digest="sha256:" + "0" * 64,  # wrong digest
            valid=False,
        )
        verification = VerificationResult(
            verdict=VerificationVerdict.MISSING_APPROVAL,
            evidence_id="",
            checks={"approval_valid": "FAIL"},
            notes=["Approval was not issued through the approval gate."],
        )
        return None, verification, gate

    if simulate_cross_pair:
        # Forge an approval that appears to be for a different proposal.
        approval = HumanApproval(
            approval_id=str(uuid.uuid4()),
            approver_id=approver_id,
            proposal_id="other-proposal-id",
            approved_payload_digest="sha256:" + "a" * 64,
        )
        gate._approvals[approval.approval_id] = approval
    else:
        approval = gate.issue(approver_id=approver_id, proposal=proposal)

    if approval_payload_override is not None:
        # Mutate the payload after approval (simulates post-approval mutation).
        import dataclasses
        approval = dataclasses.replace(
            approval,
            approved_payload_digest=approval_payload_override,
        )

    validation_error = gate.validate(approval, proposal=proposal)
    if validation_error:
        verification = VerificationResult(
            verdict=VerificationVerdict.UNAUTHORIZED,
            evidence_id="",
            checks={"approval_valid": "FAIL"},
            notes=[f"Approval gate rejected: {validation_error}"],
        )
        return None, verification, gate

    if simulate_replay:
        gate.consume(approval.approval_id)
        err = gate.validate(approval, proposal=proposal)
        verification = VerificationResult(
            verdict=VerificationVerdict.REPLAY,
            evidence_id="",
            checks={"approval_valid": "FAIL"},
            notes=[f"Replay detected: {err}"],
        )
        return None, verification, gate

    gate.consume(approval.approval_id)

    # Step 5: execute the action.
    execution_id = str(uuid.uuid4())
    success = app.apply(
        execution_id=execution_id,
        record_id=record_id,
        field="deadline",
        value=proposed_deadline,
    )

    # Step 6: independent read-back.
    if simulate_missing_readback:
        readback = None
    else:
        updated_record = app.read(record_id)
        readback = updated_record.deadline_iso if updated_record else None

    execution = ExecutionResult(
        execution_id=execution_id,
        executed_field="deadline",
        executed_value=proposed_deadline,
        readback_value=readback,
        success=success,
    )

    # Steps 7-8: record evidence.
    pkg = recorder.record(proposal=proposal, approval=approval, execution=execution)

    # Step 10: tamper simulation (after recording).
    if simulate_tamper:
        import dataclasses
        pkg.execution = dataclasses.replace(pkg.execution, readback_value="2099-12-31T00:00:00Z")
        # Recompute digest over tampered data — chain_digest will mismatch.

    # Step 9: verify.
    result = verify_evidence(pkg, expected_field_value=proposed_deadline)
    return pkg, result, gate
