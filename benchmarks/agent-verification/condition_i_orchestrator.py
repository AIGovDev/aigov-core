"""
Condition I Orchestrator — Trusted Policy Source.

Extends DVO-H with a TrustedPolicyProvider for authorization scope verification.
The key upgrade over Condition H:
  - H's authorized_approvers is a flat static list (no scope/tenant/expiry awareness)
  - I's TrustedPolicyProvider enforces: tenant isolation, action scope, resource scope,
    revocation, expiry, supersession, and cryptographic integrity

Authorization flow:
  1. Audit integrity check (same as G/H: audit found + hash verified)
  2. Approval validity check (same as G/H: not expired, matches proposal)
  3. Policy lookup: TrustedPolicyProvider.lookup_authorization(
         approver_email, action_type, resource_id, tenant_id, current_time
     ) → PolicyLookupResult
       - integrity_check_failed → INDETERMINATE (possible store tampering)
       - any other failure      → DENY (unauthorized)
       - "allow"                → continue to external state check
  4. External state consistency check (same as G/H: matches audit record)
  5. Model advisory (same as H: can flag REQUIRES_REVIEW, cannot grant ALLOW alone)

Trust boundary:
  TRUSTED:  SandboxToolExecutor results with canonical IDs
            TrustedPolicyProvider with HMAC-verified records
  ADVISORY: model verdict (can flag REQUIRES_REVIEW, cannot grant ALLOW)
  UNTRUSTED: model-generated tool arguments, model self-report
"""

from __future__ import annotations

import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

_BENCH_DIR = Path(__file__).parent
if str(_BENCH_DIR) not in sys.path:
    sys.path.insert(0, str(_BENCH_DIR))

from deterministic_verification_orchestrator import (  # noqa: E402
    OrchestratorToolCall,
    VerificationEvidence,
)
from policy_decision import (  # noqa: E402
    CheckResult,
    PolicyDecision,
    PolicyDecisionRecord,
    PolicyStats,
)
from trusted_policy_provider import PolicyLookupResult, TrustedPolicyProvider  # noqa: E402

if TYPE_CHECKING:
    from mlx_qwen_adapter import SandboxToolExecutor


@dataclass
class ConditionIEvidence(VerificationEvidence):
    """
    Extended VerificationEvidence that also carries the policy lookup result.

    policy_lookup_result is set after the approval check:
      - None if approval was invalid (policy lookup skipped)
      - PolicyLookupResult otherwise
    """
    policy_lookup_result: PolicyLookupResult | None = None
    action_type: str = ""
    resource_id: str = ""
    tenant_id: str = ""


class ConditionIOrchestrator:
    """
    DVO orchestrator with TrustedPolicyProvider for authorization scope.

    Usage:
        provider = TrustedPolicyProvider(POLICY_FIXTURE)
        orchestrator = ConditionIOrchestrator(
            executor=executor,
            policy_provider=provider,
            action_type="data_access",
            resource_id="db-prod-001",
            tenant_id="tenant-alpha",
        )
        evidence = orchestrator.orchestrate(proposal_id, approval_id, record_id)
        # evidence.dvo_authorized reflects policy lookup result
        # evidence.policy_lookup_result has failure_reason detail
    """

    def __init__(
        self,
        executor: "SandboxToolExecutor",
        policy_provider: TrustedPolicyProvider,
        action_type: str,
        resource_id: str,
        tenant_id: str,
        current_time: float | None = None,
    ) -> None:
        self._executor = executor
        self._policy_provider = policy_provider
        self._action_type = action_type
        self._resource_id = resource_id
        self._tenant_id = tenant_id
        self._current_time = current_time

    def orchestrate(
        self,
        proposal_id: str,
        approval_id: str,
        record_id: str,
        field: str = "value",
    ) -> ConditionIEvidence:
        """
        Independently call all 3 evidence tools + policy lookup.

        Returns ConditionIEvidence. Never raises — errors are recorded.

        dvo_authorized is True iff:
          - audit found and hash verified
          - approval valid and proposal matches
          - policy lookup returns "allow" (not integrity failure, not any DENY reason)
          - external state present and consistent with audit
        """
        t0 = time.perf_counter()
        tool_calls: list[OrchestratorToolCall] = []
        failure_reasons: list[str] = []
        policy_lookup_result: PolicyLookupResult | None = None

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

        audit_found = audit_result.get("found") is True
        audit_hash_ok = audit_result.get("hash_verified") is True
        if audit_error:
            failure_reasons.append(f"audit_tool_error:{audit_error}")
        elif not audit_found:
            failure_reasons.append("audit_record_not_found")
        elif not audit_hash_ok:
            failure_reasons.append("audit_hash_verification_failed")

        # --- Tool 2: verify_approval (without identity check — I uses policy lookup instead) ---
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

        approval_valid = approval_result.get("valid") is True
        actual_approver = approval_result.get("approver", "")
        if approval_error:
            failure_reasons.append(f"approval_tool_error:{approval_error}")
        elif not approval_valid:
            reason = approval_result.get("reason", "approval_invalid")
            failure_reasons.append(f"approval_invalid:{reason}")

        # --- Policy lookup (Step 3) ---
        # Only run if approval was structurally valid (has an approver identity)
        if approval_valid and not approval_error:
            current_time = self._current_time if self._current_time is not None else time.time()
            policy_lookup_result = self._policy_provider.lookup_authorization(
                approver_email=actual_approver,
                action_type=self._action_type,
                resource_id=self._resource_id,
                tenant_id=self._tenant_id,
                current_time=current_time,
            )
            if not policy_lookup_result.authorized:
                failure_reasons.append(f"policy_denied:{policy_lookup_result.failure_reason}")
        elif not approval_valid:
            # Approval was invalid — policy lookup skipped (redundant)
            policy_lookup_result = None

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

        ext_value = external_result.get("value")
        if external_error:
            failure_reasons.append(f"external_state_tool_error:{external_error}")
        elif ext_value is None:
            failure_reasons.append("external_state_value_missing")
        elif audit_found:
            audit_executed = audit_result.get("executed_value")
            if audit_executed is not None and ext_value != audit_executed:
                failure_reasons.append(
                    f"external_state_mismatch:"
                    f"audit={audit_executed!r},external={ext_value!r}"
                )

        dvo_authorized = len(failure_reasons) == 0
        orchestration_ms = (time.perf_counter() - t0) * 1000

        return ConditionIEvidence(
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
            policy_lookup_result=policy_lookup_result,
            action_type=self._action_type,
            resource_id=self._resource_id,
            tenant_id=self._tenant_id,
        )


def compute_policy_i_decision(
    evidence: ConditionIEvidence,
    model_verdict: bool | None,
    model_reasoning: str = "",
) -> PolicyDecisionRecord:
    """
    Compute 4-state PolicyDecisionRecord from Condition I evidence.

    Decision logic:
      INDETERMINATE   — Any tool error OR policy integrity check failed
      DENY            — Any deterministic check failed (audit/approval/policy/external)
      REQUIRES_REVIEW — All checks passed, model disagreed or no verdict
      ALLOW           — All checks passed AND model agreed

    Security invariant: policy_integrity_check_failed → INDETERMINATE (not DENY)
    because the caller cannot distinguish a legitimately rejected approval from
    a tampered policy store. Fail-closed on ambiguity.
    """
    check_results: list[CheckResult] = []

    # Reconstruct check results from evidence
    audit_ok = (
        evidence.audit_result.get("found") is True
        and evidence.audit_result.get("hash_verified") is True
        and evidence.audit_result.get("error") is None
    )
    check_results.append(CheckResult(
        "audit_record",
        audit_ok,
        "found_hash_verified" if audit_ok else "failed",
    ))

    approval_ok = evidence.approval_result.get("valid") is True
    check_results.append(CheckResult(
        "approval_valid",
        approval_ok,
        "valid" if approval_ok else evidence.approval_result.get("reason", "invalid"),
    ))

    # Policy check
    policy_ok = False
    policy_detail = "skipped"
    if evidence.policy_lookup_result is not None:
        policy_ok = evidence.policy_lookup_result.authorized
        policy_detail = evidence.policy_lookup_result.failure_reason
    check_results.append(CheckResult("policy_lookup", policy_ok, policy_detail))

    ext_value = evidence.external_result.get("value")
    audit_executed = evidence.audit_result.get("executed_value") if audit_ok else None
    ext_ok = (
        ext_value is not None
        and evidence.external_result.get("error") is None
        and (audit_executed is None or ext_value == audit_executed)
    )
    check_results.append(CheckResult(
        "external_state",
        ext_ok,
        f"consistent:{ext_value!r}" if ext_ok else "failed",
    ))

    # Determine failure category
    indeterminate_reasons: list[str] = []
    deny_reasons: list[str] = []

    for reason in evidence.failure_reasons:
        if "tool_error" in reason or reason == "policy_denied:integrity_check_failed":
            indeterminate_reasons.append(reason)
        else:
            deny_reasons.append(reason)

    if indeterminate_reasons:
        return PolicyDecisionRecord.indeterminate(
            reasons=indeterminate_reasons,
            check_results=check_results,
            orchestration_ms=evidence.orchestration_ms,
        )

    if deny_reasons:
        return PolicyDecisionRecord.deny(
            reasons=deny_reasons,
            check_results=check_results,
            orchestration_ms=evidence.orchestration_ms,
        )

    # All deterministic checks passed — advisory model assessment
    if model_verdict is True:
        return PolicyDecisionRecord.allow(
            model_verdict=True,
            model_reasoning=model_reasoning,
            check_results=check_results,
            orchestration_ms=evidence.orchestration_ms,
        )
    elif model_verdict is False:
        return PolicyDecisionRecord.requires_review(
            flags=["model_flagged_concern:model_verdict=False"],
            model_verdict=False,
            model_reasoning=model_reasoning,
            check_results=check_results,
            orchestration_ms=evidence.orchestration_ms,
        )
    else:
        return PolicyDecisionRecord.requires_review(
            flags=["model_no_verdict:no_inference_result"],
            model_verdict=None,
            model_reasoning=model_reasoning,
            check_results=check_results,
            orchestration_ms=evidence.orchestration_ms,
        )
