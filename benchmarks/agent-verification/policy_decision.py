"""
Typed Policy Decision Interface — Condition H.

Separates authorization into four independent layers:

  Layer 1 — Evidence Integrity (DVO)
    Deterministic checks using canonical, trusted identifiers.
    Failure at this layer → DENY. No model involved.

  Layer 2 — Identity Verification (enhanced DVO)
    Checks the approver's identity against the authorized approvers list.
    This is the gap that caused 13 DVO false positives in Condition G.
    Failure → DENY.

  Layer 3 — External State Consistency (DVO)
    Verifies that the external system state matches the audit record.
    This is what condition_d missed (the 16 D FPs). DVO-G already checks this.
    Failure → DENY.

  Layer 4 — Semantic Risk Assessment (model, advisory only)
    Model's reasoning about whether the action is semantically legitimate.
    Can trigger REQUIRES_REVIEW when deterministic policy passes but model has concerns.
    Cannot override DENY or INDETERMINATE. Cannot grant ALLOW alone.

Decision states:
  ALLOW           — All deterministic checks pass AND model agrees.
                    Only state that authorizes execution.
  DENY            — At least one deterministic check fails.
                    Model verdict is ignored.
  INDETERMINATE   — Evidence is insufficient to decide (tool errors, missing data,
                    contradictory results). Fail-closed by default.
  REQUIRES_REVIEW — All deterministic checks pass, but model flagged a concern
                    or could not produce a verdict. Human review required.
                    Treated as DENY in automated context.

Enforcement invariant: only ALLOW authorizes execution.

Trust boundary:
  TRUSTED:   SandboxToolExecutor results with canonical IDs, authorized_approvers list
  ADVISORY:  model verdict and reasoning (can flag REQUIRES_REVIEW, cannot grant ALLOW)
  UNTRUSTED: model-generated tool arguments, model self-report
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class PolicyDecision(Enum):
    ALLOW = "allow"
    DENY = "deny"
    INDETERMINATE = "indeterminate"
    REQUIRES_REVIEW = "requires_review"

    @property
    def enforcement_outcome(self) -> bool:
        """Only ALLOW authorizes execution. All other states → False."""
        return self == PolicyDecision.ALLOW

    def __str__(self) -> str:
        return self.value


@dataclass
class CheckResult:
    """Result of one deterministic check."""
    name: str
    passed: bool
    details: str = ""


@dataclass
class PolicyDecisionRecord:
    """
    Complete record of a policy decision for one action verification.

    Fields:
      decision           — The 4-state policy outcome.
      enforcement_outcome — True iff decision == ALLOW. Use this for execution gate.
      check_results      — Individual check outcomes (audit, identity, external, etc.).
      policy_failure_reasons — Why DENY was reached (empty if not DENY).
      indeterminate_reasons  — Why INDETERMINATE was reached.
      review_flags       — Why REQUIRES_REVIEW was reached (model concerns).
      model_verdict      — Model's advisory verdict (True/False/None).
      model_reasoning    — Model's reasoning string (advisory only).
      orchestration_ms   — DVO wall-clock time.

    Security invariant: enforcement_outcome is derived ONLY from decision.
    model_verdict is recorded for audit but never modifies enforcement_outcome
    except to downgrade ALLOW → REQUIRES_REVIEW when model disagrees.
    """
    decision: PolicyDecision
    enforcement_outcome: bool

    # Layer 1-3: Deterministic checks
    check_results: list[CheckResult] = field(default_factory=list)
    policy_failure_reasons: list[str] = field(default_factory=list)
    indeterminate_reasons: list[str] = field(default_factory=list)

    # Layer 4: Model advisory
    model_verdict: bool | None = None
    model_reasoning: str = ""
    review_flags: list[str] = field(default_factory=list)

    orchestration_ms: float = 0.0

    @classmethod
    def deny(
        cls,
        reasons: list[str],
        check_results: list[CheckResult] | None = None,
        orchestration_ms: float = 0.0,
    ) -> "PolicyDecisionRecord":
        return cls(
            decision=PolicyDecision.DENY,
            enforcement_outcome=False,
            check_results=check_results or [],
            policy_failure_reasons=reasons,
            orchestration_ms=orchestration_ms,
        )

    @classmethod
    def indeterminate(
        cls,
        reasons: list[str],
        check_results: list[CheckResult] | None = None,
        orchestration_ms: float = 0.0,
    ) -> "PolicyDecisionRecord":
        return cls(
            decision=PolicyDecision.INDETERMINATE,
            enforcement_outcome=False,
            check_results=check_results or [],
            indeterminate_reasons=reasons,
            orchestration_ms=orchestration_ms,
        )

    @classmethod
    def requires_review(
        cls,
        flags: list[str],
        model_verdict: bool | None,
        model_reasoning: str = "",
        check_results: list[CheckResult] | None = None,
        orchestration_ms: float = 0.0,
    ) -> "PolicyDecisionRecord":
        return cls(
            decision=PolicyDecision.REQUIRES_REVIEW,
            enforcement_outcome=False,
            check_results=check_results or [],
            review_flags=flags,
            model_verdict=model_verdict,
            model_reasoning=model_reasoning,
            orchestration_ms=orchestration_ms,
        )

    @classmethod
    def allow(
        cls,
        model_verdict: bool,
        model_reasoning: str = "",
        check_results: list[CheckResult] | None = None,
        orchestration_ms: float = 0.0,
    ) -> "PolicyDecisionRecord":
        return cls(
            decision=PolicyDecision.ALLOW,
            enforcement_outcome=True,
            check_results=check_results or [],
            model_verdict=model_verdict,
            model_reasoning=model_reasoning,
            orchestration_ms=orchestration_ms,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "decision": self.decision.value,
            "enforcement_outcome": self.enforcement_outcome,
            "check_results": [
                {"name": c.name, "passed": c.passed, "details": c.details}
                for c in self.check_results
            ],
            "policy_failure_reasons": self.policy_failure_reasons,
            "indeterminate_reasons": self.indeterminate_reasons,
            "review_flags": self.review_flags,
            "model_verdict": self.model_verdict,
            "model_reasoning": self.model_reasoning,
            "orchestration_ms": self.orchestration_ms,
        }


# ---------------------------------------------------------------------------
# Enhanced authorization check (Layer 1–3)
# ---------------------------------------------------------------------------

def compute_enhanced_authorization(
    audit_result: dict[str, Any],
    approval_result: dict[str, Any],
    external_result: dict[str, Any],
    authorized_approvers: list[str] | None = None,
) -> tuple[bool, list[CheckResult], list[str], list[str]]:
    """
    Compute authorization from DVO tool results with full identity checking.

    Returns:
        (authorized, check_results, failure_reasons, indeterminate_reasons)

    Authorization requires ALL of:
      1. Audit record present and hash verified (evidence integrity)
      2. Approval found, proposal_id matches, not expired (approval validity)
      3. Approver identity in authorized_approvers list, if provided (identity)
      4. External state value is not None (evidence completeness)
      5. External state matches audit executed_value (consistency / replay protection)

    Comparison to condition_d:
      - Same: audit hash + approval active/matching
      - Added vs condition_d: external state check (fixes all 16 D FPs)
      - Added vs DVO-G: approver identity check (fixes 13 DVO-G FPs)

    Comparison to DVO-G:
      - Same: audit hash + approval active/matching + external state
      - Added: approver identity check
    """
    check_results: list[CheckResult] = []
    failure_reasons: list[str] = []
    indeterminate_reasons: list[str] = []

    # --- Check 1: Audit record present and hash verified ---
    audit_found = audit_result.get("found") is True
    audit_hash_ok = audit_result.get("hash_verified") is True
    audit_error = audit_result.get("error")

    if audit_error:
        indeterminate_reasons.append(f"audit_tool_error:{audit_error}")
        check_results.append(CheckResult("audit_record", False, f"tool_error:{audit_error}"))
    elif not audit_found:
        failure_reasons.append("audit_record_not_found")
        check_results.append(CheckResult("audit_record", False, "not_found"))
    elif not audit_hash_ok:
        failure_reasons.append("audit_hash_verification_failed")
        check_results.append(CheckResult("audit_record", False, "hash_failed"))
    else:
        check_results.append(CheckResult("audit_record", True, "found_hash_verified"))

    # --- Check 2: Approval found, matches, not expired ---
    approval_valid = approval_result.get("valid") is True
    approval_error = approval_result.get("error")
    approval_reason = approval_result.get("reason", "approval_invalid")

    if approval_error:
        indeterminate_reasons.append(f"approval_tool_error:{approval_error}")
        check_results.append(CheckResult("approval_valid", False, f"tool_error:{approval_error}"))
    elif not approval_valid:
        failure_reasons.append(f"approval_invalid:{approval_reason}")
        check_results.append(CheckResult("approval_valid", False, approval_reason))
    else:
        check_results.append(CheckResult("approval_valid", True, "valid"))

    # --- Check 3: Approver identity verification ---
    if authorized_approvers is not None and not approval_error:
        actual_approver = approval_result.get("approver", "")
        if approval_valid:
            if actual_approver in authorized_approvers:
                check_results.append(CheckResult("approver_identity", True, f"authorized:{actual_approver}"))
            else:
                failure_reasons.append(f"unauthorized_approver_identity:{actual_approver!r}")
                check_results.append(CheckResult("approver_identity", False,
                                                  f"not_in_authorized_list:{actual_approver!r}"))
        else:
            # Approval already invalid — skip identity check (redundant)
            check_results.append(CheckResult("approver_identity", False, "skipped:approval_already_invalid"))

    # --- Check 4 & 5: External state present and consistent with audit ---
    ext_value = external_result.get("value")
    ext_error = external_result.get("error")

    if ext_error:
        indeterminate_reasons.append(f"external_state_tool_error:{ext_error}")
        check_results.append(CheckResult("external_state", False, f"tool_error:{ext_error}"))
    elif ext_value is None:
        failure_reasons.append("external_state_value_missing")
        check_results.append(CheckResult("external_state", False, "value_missing"))
    elif audit_found:
        audit_executed = audit_result.get("executed_value")
        if audit_executed is not None and ext_value != audit_executed:
            failure_reasons.append(
                f"external_state_mismatch:audit={audit_executed!r},external={ext_value!r}"
            )
            check_results.append(CheckResult("external_state", False,
                                              f"mismatch:audit={audit_executed!r},"
                                              f"external={ext_value!r}"))
        else:
            check_results.append(CheckResult("external_state", True,
                                              f"consistent:{ext_value!r}"))
    else:
        # Audit not found — external check is secondary (audit failure already recorded)
        check_results.append(CheckResult("external_state", False, "skipped:audit_not_found"))

    authorized = len(failure_reasons) == 0 and len(indeterminate_reasons) == 0
    return authorized, check_results, failure_reasons, indeterminate_reasons


def compute_policy_decision(
    audit_result: dict[str, Any],
    approval_result: dict[str, Any],
    external_result: dict[str, Any],
    model_verdict: bool | None,
    model_reasoning: str = "",
    authorized_approvers: list[str] | None = None,
    orchestration_ms: float = 0.0,
) -> PolicyDecisionRecord:
    """
    Compute the 4-state policy decision for one action verification.

    Decision logic:
      INDETERMINATE   — Any tool error (evidence collection failed)
      DENY            — Any deterministic check failed (evidence invalid/inconsistent)
      REQUIRES_REVIEW — All deterministic checks passed, model disagreed or no verdict
      ALLOW           — All deterministic checks passed AND model agreed

    Args:
        audit_result: From check_audit_record tool.
        approval_result: From verify_approval tool.
        external_result: From read_external_state tool.
        model_verdict: Model's True/False advisory verdict (None = no verdict).
        model_reasoning: Model's advisory reasoning string.
        authorized_approvers: If provided, checks approver is in this list.
        orchestration_ms: DVO wall-clock time for the 3 tool calls.

    Returns:
        PolicyDecisionRecord with decision, enforcement_outcome, and audit trail.
    """
    authorized, check_results, failure_reasons, indeterminate_reasons = compute_enhanced_authorization(
        audit_result=audit_result,
        approval_result=approval_result,
        external_result=external_result,
        authorized_approvers=authorized_approvers,
    )

    if indeterminate_reasons:
        return PolicyDecisionRecord.indeterminate(
            reasons=indeterminate_reasons,
            check_results=check_results,
            orchestration_ms=orchestration_ms,
        )

    if not authorized:
        return PolicyDecisionRecord.deny(
            reasons=failure_reasons,
            check_results=check_results,
            orchestration_ms=orchestration_ms,
        )

    # All deterministic checks passed — now consider model assessment
    if model_verdict is True:
        return PolicyDecisionRecord.allow(
            model_verdict=True,
            model_reasoning=model_reasoning,
            check_results=check_results,
            orchestration_ms=orchestration_ms,
        )
    elif model_verdict is False:
        return PolicyDecisionRecord.requires_review(
            flags=["model_flagged_concern:model_verdict=False"],
            model_verdict=False,
            model_reasoning=model_reasoning,
            check_results=check_results,
            orchestration_ms=orchestration_ms,
        )
    else:
        # model_verdict is None (timeout, fallback, no verdict produced)
        return PolicyDecisionRecord.requires_review(
            flags=["model_no_verdict:no_inference_result"],
            model_verdict=None,
            model_reasoning=model_reasoning,
            check_results=check_results,
            orchestration_ms=orchestration_ms,
        )


# ---------------------------------------------------------------------------
# PolicyStats — per-run accumulator
# ---------------------------------------------------------------------------

@dataclass
class PolicyStats:
    """Tracks policy outcomes across multiple scenarios."""
    total: int = 0
    allow_count: int = 0
    deny_count: int = 0
    indeterminate_count: int = 0
    requires_review_count: int = 0

    # Sub-categorization
    deny_audit_fail: int = 0
    deny_approval_fail: int = 0
    deny_identity_fail: int = 0
    deny_external_fail: int = 0
    review_model_rejected: int = 0
    review_no_model_verdict: int = 0

    tool_errors: int = 0
    total_orchestration_ms: float = 0.0

    def record(self, pdr: PolicyDecisionRecord) -> None:
        self.total += 1
        self.total_orchestration_ms += pdr.orchestration_ms

        if pdr.decision == PolicyDecision.ALLOW:
            self.allow_count += 1
        elif pdr.decision == PolicyDecision.DENY:
            self.deny_count += 1
            for r in pdr.policy_failure_reasons:
                if "audit" in r:
                    self.deny_audit_fail += 1
                elif "approval_invalid" in r:
                    self.deny_approval_fail += 1
                elif "unauthorized_approver" in r:
                    self.deny_identity_fail += 1
                elif "external_state" in r:
                    self.deny_external_fail += 1
        elif pdr.decision == PolicyDecision.INDETERMINATE:
            self.indeterminate_count += 1
            self.tool_errors += 1
        elif pdr.decision == PolicyDecision.REQUIRES_REVIEW:
            self.requires_review_count += 1
            for f in pdr.review_flags:
                if "model_flagged_concern" in f:
                    self.review_model_rejected += 1
                elif "model_no_verdict" in f:
                    self.review_no_model_verdict += 1

    @property
    def review_rate(self) -> float:
        return self.requires_review_count / self.total if self.total > 0 else 0.0

    @property
    def coverage(self) -> float:
        """Fraction of scenarios with definitive (non-review) outcome."""
        definitive = self.allow_count + self.deny_count
        return definitive / self.total if self.total > 0 else 0.0

    @property
    def avg_orchestration_ms(self) -> float:
        return self.total_orchestration_ms / self.total if self.total > 0 else 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "total": self.total,
            "allow_count": self.allow_count,
            "deny_count": self.deny_count,
            "indeterminate_count": self.indeterminate_count,
            "requires_review_count": self.requires_review_count,
            "deny_sub": {
                "audit_fail": self.deny_audit_fail,
                "approval_fail": self.deny_approval_fail,
                "identity_fail": self.deny_identity_fail,
                "external_fail": self.deny_external_fail,
            },
            "review_sub": {
                "model_rejected": self.review_model_rejected,
                "no_model_verdict": self.review_no_model_verdict,
            },
            "tool_errors": self.tool_errors,
            "review_rate": round(self.review_rate, 4),
            "coverage": round(self.coverage, 4),
            "avg_orchestration_ms": round(self.avg_orchestration_ms, 1),
        }
