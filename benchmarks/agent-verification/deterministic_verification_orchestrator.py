"""
Deterministic Verification Orchestrator (DVO) — Condition G.

The DVO independently executes all mandatory evidence checks using
canonical, trusted scenario identifiers. It does NOT rely on the language
model to discover or call evidence tools.

Architecture
------------
The core failure of Condition F (gate-enforced, Qwen2.5-3B):
  - Gate blocks report_verdict until model calls all 3 required tools.
  - Qwen2.5-3B does not respond to gate feedback; it retries report_verdict
    instead of calling missing tools.
  - Result: max_steps exhausted → fail_closed=False → FRR=0.929.

The DVO fixes this by inverting the responsibility:
  - DVO calls all 3 tools with canonical IDs before the model runs.
  - Tool results are pre-injected into the model's conversation context.
  - Model only needs to reason from pre-existing evidence and call report_verdict.
  - DVO computes its own independent authorization decision (dvo_authorized).
  - Final verdict = dvo_authorized AND model_verdict.
  - DVO-NO always overrides a model-positive verdict (security invariant).

Security invariants
-------------------
- Canonical IDs come from the scenario definition (via the benchmark runner),
  never from model-generated arguments.
- dvo_authorized is computed from actual SandboxToolExecutor results, not from
  the model's conversation or self-report.
- A tool returning an error or unexpected result counts as evidence gathered;
  it fails the authorization check.
- Each required tool is called exactly once per scenario.
- Tool results are recorded with their actual origin (DVO, not model).
- A model-positive verdict cannot override a DVO-negative decision.

Trust boundary
--------------
  TRUSTED:  SandboxToolExecutor results, canonical scenario parameters
  UNTRUSTED: model output, model-generated tool arguments, model reasoning

Condition G outcome (hypothesis)
---------------------------------
Positive scenarios (14): DVO=YES, model sees correct evidence → model agrees → FN=0
  vs. Condition F: FN=13 (fail_closed on max_steps)

Negative scenarios correctly rejected by DVO (40): DVO=NO → G=NO → TN
Negative scenarios DVO passes through (D FPs, ~16): DVO=YES, model reasons from
  pre-injected evidence → model might reject some → G improves over D on those.

Expected: FRR→0, FAR ~ D FAR (0.286), possibly improved by model judgment.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from mlx_qwen_adapter import SandboxToolExecutor, ToolCall

# ---------------------------------------------------------------------------
# Evidence records
# ---------------------------------------------------------------------------

REQUIRED_EVIDENCE_TOOLS: frozenset[str] = frozenset({
    "check_audit_record",
    "verify_approval",
    "read_external_state",
})


@dataclass
class OrchestratorToolCall:
    """Record of a single tool call made by the DVO (not by the model)."""
    name: str
    arguments: dict[str, Any]
    result: Any
    error: str | None = None
    origin: str = "dvo"  # always "dvo" — distinguishes from model tool calls


@dataclass
class VerificationEvidence:
    """
    Independent evidence gathered and authorized by the DVO.

    dvo_authorized is the authoritative security decision:
    - True iff all 3 tools returned valid, consistent, non-expired evidence
    - False on any error, missing result, mismatch, expiry, or invalid identity
    - Final verdict = dvo_authorized AND model_verdict (DVO-NO always wins)
    """
    proposal_id: str
    approval_id: str
    record_id: str
    field: str

    audit_result: dict[str, Any]
    approval_result: dict[str, Any]
    external_result: dict[str, Any]

    dvo_authorized: bool
    failure_reasons: list[str]  # why DVO rejected (empty if authorized)
    tool_calls: list[OrchestratorToolCall] = field(default_factory=list)
    orchestration_ms: float = 0.0

    def as_injected_messages(self) -> list[dict[str, Any]]:
        """
        Return (assistant, tool) message pairs that pre-inject the evidence
        results into the model's conversation context.

        The model sees these as if it had called the tools itself, allowing
        it to reason from the evidence and call report_verdict.

        Format mirrors Qwen2.5 tool-call conversation structure so that
        apply_chat_template treats them as valid prior tool interactions.
        """
        import json
        messages: list[dict[str, Any]] = []

        for tc in self.tool_calls:
            # Assistant turn: tool call
            call_json = json.dumps({"name": tc.name, "arguments": tc.arguments})
            messages.append({
                "role": "assistant",
                "content": f"<tool_call>{call_json}</tool_call>",
            })
            # Tool response turn
            if tc.error is not None:
                result_json = json.dumps({"error": tc.error})
            else:
                result_json = json.dumps(tc.result)
            messages.append({
                "role": "tool",
                "content": result_json,
                "name": tc.name,
            })

        return messages


# ---------------------------------------------------------------------------
# Authorization logic — mirrors condition_d from independent_benchmark.py
# ---------------------------------------------------------------------------

def _compute_authorization(
    proposal_id: str,
    approval_id: str,
    record_id: str,
    field: str,
    audit_result: dict[str, Any],
    approval_result: dict[str, Any],
    external_result: dict[str, Any],
) -> tuple[bool, list[str]]:
    """
    Compute independent authorization from actual tool results.

    This is the DVO's authoritative security decision. It mirrors
    condition_d's logic (audit hash valid AND approval valid AND external state
    valid) but operates on actual SandboxToolExecutor results rather than
    scenario parameters.

    Returns (authorized: bool, failure_reasons: list[str]).

    Critical invariant:
        A tool returning an error or unexpected result fails authorization.
        A tool returning partial or inconsistent data fails authorization.
        A missing audit record fails authorization.
        An expired or mismatched approval fails authorization.
        An external state that does not match the audit record fails
        authorization (replay / stale state detection).
    """
    reasons: list[str] = []

    # Check 1: audit record present and hash verified
    audit_found = audit_result.get("found") is True
    audit_hash_ok = audit_result.get("hash_verified") is True
    if not audit_found:
        reasons.append("audit_record_not_found")
    if audit_found and not audit_hash_ok:
        reasons.append("audit_hash_verification_failed")

    # Check 2: approval valid, identity and expiry
    approval_valid = approval_result.get("valid") is True
    if not approval_valid:
        reason_detail = approval_result.get("reason", "approval_invalid")
        reasons.append(f"approval_invalid:{reason_detail}")

    # Check 3: external state present and consistent with audit record
    ext_value = external_result.get("value")
    if ext_value is None:
        reasons.append("external_state_value_missing")
    elif audit_found:
        # Verify that external state matches what was recorded in the audit ledger.
        # This detects replay attacks and stale-state attacks.
        audit_executed = audit_result.get("executed_value")
        if audit_executed is not None and ext_value != audit_executed:
            reasons.append(
                f"external_state_mismatch:"
                f"audit={audit_executed!r},external={ext_value!r}"
            )
    # If audit not found, we already flagged it above; external check is secondary.

    authorized = len(reasons) == 0
    return authorized, reasons


# ---------------------------------------------------------------------------
# Deterministic Verification Orchestrator
# ---------------------------------------------------------------------------

class DeterministicVerificationOrchestrator:
    """
    Independently executes all mandatory evidence checks using canonical IDs.

    Usage in the benchmark runner:
        # canonical IDs come from Scenario definition — never model-generated
        orchestrator = DeterministicVerificationOrchestrator(executor)
        evidence = orchestrator.orchestrate(
            proposal_id=s.proposal_id,
            approval_id=s.approval_id,
            record_id=scenario_summary["record_id"],
        )
        # pre-inject evidence into model context, then run model
        # final verdict = evidence.dvo_authorized AND model_verdict

    The executor must be constructed from the same scenario_state as the
    model's SandboxToolExecutor. The DVO's tool calls are recorded separately
    from the model's tool calls so traces remain auditable.
    """

    def __init__(self, executor: "SandboxToolExecutor") -> None:
        self._executor = executor

    def orchestrate(
        self,
        proposal_id: str,
        approval_id: str,
        record_id: str,
        field: str = "deadline",
    ) -> VerificationEvidence:
        """
        Independently call all 3 required evidence tools and compute
        the authorization decision.

        Args:
            proposal_id: Canonical proposal identifier. Must come from the
                         scenario definition, not from model output.
            approval_id: Canonical approval identifier. Same constraint.
            record_id:   Canonical external record identifier.
            field:       Field name in the external record to verify.

        Returns:
            VerificationEvidence with dvo_authorized and all tool results.
            Never raises — errors are recorded in OrchestratorToolCall.error.
        """
        t0 = time.perf_counter()
        tool_calls: list[OrchestratorToolCall] = []

        # --- Tool 1: check_audit_record ---
        audit_args = {"proposal_id": proposal_id}
        try:
            audit_result = self._executor.execute("check_audit_record", audit_args)
            audit_error = None
        except Exception as exc:
            audit_result = {"found": False, "error": str(exc)}
            audit_error = str(exc)
        tool_calls.append(OrchestratorToolCall(
            name="check_audit_record",
            arguments=audit_args,
            result=audit_result,
            error=audit_error,
        ))

        # --- Tool 2: verify_approval ---
        approval_args = {"proposal_id": proposal_id, "approval_id": approval_id}
        try:
            approval_result = self._executor.execute("verify_approval", approval_args)
            approval_error = None
        except Exception as exc:
            approval_result = {"valid": False, "error": str(exc)}
            approval_error = str(exc)
        tool_calls.append(OrchestratorToolCall(
            name="verify_approval",
            arguments=approval_args,
            result=approval_result,
            error=approval_error,
        ))

        # --- Tool 3: read_external_state ---
        external_args = {"record_id": record_id, "field": field}
        try:
            external_result = self._executor.execute("read_external_state", external_args)
            external_error = None
        except Exception as exc:
            external_result = {"value": None, "error": str(exc)}
            external_error = str(exc)
        tool_calls.append(OrchestratorToolCall(
            name="read_external_state",
            arguments=external_args,
            result=external_result,
            error=external_error,
        ))

        # --- Authorization decision ---
        dvo_authorized, failure_reasons = _compute_authorization(
            proposal_id=proposal_id,
            approval_id=approval_id,
            record_id=record_id,
            field=field,
            audit_result=audit_result,
            approval_result=approval_result,
            external_result=external_result,
        )

        orchestration_ms = (time.perf_counter() - t0) * 1000

        return VerificationEvidence(
            proposal_id=proposal_id,
            approval_id=approval_id,
            record_id=record_id,
            field=field,
            audit_result=audit_result,
            approval_result=approval_result,
            external_result=external_result,
            dvo_authorized=dvo_authorized,
            failure_reasons=failure_reasons,
            tool_calls=tool_calls,
            orchestration_ms=orchestration_ms,
        )


# ---------------------------------------------------------------------------
# DVO stats
# ---------------------------------------------------------------------------

@dataclass
class DVOStats:
    total_scenarios: int = 0
    dvo_authorized_count: int = 0
    dvo_rejected_count: int = 0
    model_rejected_on_dvo_ok: int = 0  # DVO=YES, model=NO (conservative model)
    final_accepted: int = 0            # DVO=YES AND model=YES
    final_rejected_by_dvo: int = 0     # DVO=NO (regardless of model)
    final_rejected_by_model: int = 0   # DVO=YES, model=NO
    tool_errors: int = 0
    total_orchestration_ms: float = 0.0

    def record(
        self,
        evidence: VerificationEvidence,
        model_verdict: bool | None,
        final_verdict: bool,
    ) -> None:
        self.total_scenarios += 1
        self.total_orchestration_ms += evidence.orchestration_ms

        for tc in evidence.tool_calls:
            if tc.error is not None:
                self.tool_errors += 1

        if evidence.dvo_authorized:
            self.dvo_authorized_count += 1
            if model_verdict is False or model_verdict is None:
                self.model_rejected_on_dvo_ok += 1
                self.final_rejected_by_model += 1
            else:
                self.final_accepted += 1
        else:
            self.dvo_rejected_count += 1
            self.final_rejected_by_dvo += 1
