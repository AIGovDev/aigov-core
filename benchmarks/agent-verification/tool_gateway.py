"""
ToolGateway — authorization enforcement point between an AI agent and tool execution.

Security invariants:
  1. No tool executes unless PolicyDecision.ALLOW was reached for the EXACT
     (tool_name, arguments, action_type, resource_id) tuple in this call.
  2. Authorization and execution are atomic within a single request() call.
     There is no window between authorization and execution where arguments
     can be changed (TOCTOU protection via deepcopy at step 1).
  3. Each approval is consumed atomically via ReplayRegistry. Concurrent calls
     with the same approval_id are serialized; the second call finds the nonce
     already consumed → DENY.
     LIMITATION: ReplayRegistry is in-memory per-process. Across multiple worker
     processes, replay atomicity is not guaranteed. Use a persistent distributed
     nonce store (e.g. Redis SETNX, PostgreSQL FOR UPDATE) in production.
  4. The gateway enforces the tool→action_type capability map. An agent cannot
     invoke modify_repo_settings with action_type="repo:read" to downgrade the
     required authorization.
  5. Policy-service outage (INDETERMINATE) fails closed → no execution.
  6. After ALLOW, a pre-execution revocation check re-examines the RevocationList
     immediately before token issuance. This closes the authorization→execution
     window for single-process deployments.
  7. An ExecutionAuthorizationToken (EAT) is issued after ALLOW and the pre-exec
     revocation check. SandboxedGitHubTools.execute() verifies the EAT
     independently. Code that bypasses ToolGateway cannot forge a valid EAT.

Trust boundary:
  TRUSTED:  PolicyDecisionRecord with decision=ALLOW (after Condition I checks)
            ExecutionToken verified against token_authority (cryptographic)
  ADVISORY: model_verdict passed through Condition I (cannot grant ALLOW alone)
  UNTRUSTED: tool_name, arguments, action_type, resource_id from request
             (all validated and checked before any execution)
"""

from __future__ import annotations

import copy
import sys
import time
import traceback
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

_BENCH_DIR = Path(__file__).parent
if str(_BENCH_DIR) not in sys.path:
    sys.path.insert(0, str(_BENCH_DIR))

from condition_i_orchestrator import (  # noqa: E402
    ConditionIOrchestrator,
    compute_policy_i_decision,
)
from execution_token import ExecutionToken, ExecutionTokenAuthority  # noqa: E402
from policy_decision import PolicyDecision, PolicyDecisionRecord  # noqa: E402
from replay_protection import ApprovalNonce, ReplayRegistry  # noqa: E402
from revocation_list import RevocationList  # noqa: E402
from sandboxed_tools import (  # noqa: E402
    DVOScenarioState,
    SandboxedDVOExecutor,
    SandboxedGitHubTools,
    compute_args_binding_hash,
)
from trusted_policy_provider import PolicyKeyProvider, TrustedPolicyProvider  # noqa: E402

# ---------------------------------------------------------------------------
# Tool → required action_type capability map
#
# Enforced at the gateway level. An agent cannot submit a request claiming
# a lower capability for a tool that requires a higher one.
# ---------------------------------------------------------------------------

TOOL_CAPABILITY_MAP: dict[str, str] = {
    "read_repo_metadata":  "repo:read",
    "create_file":         "repo:write",
    "open_pull_request":   "repo:write",
    "modify_repo_settings": "repo:admin",
    "request_deployment":  "deploy:production",
}


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------


@dataclass
class ToolRequest:
    """
    A request from an agent to execute a tool operation.

    Both authorization (proposal_id, approval_id, record_id, action_type,
    resource_id, tenant_id) and execution (tool_name, arguments) parameters
    are captured at the same time and bound via args_binding_hash before
    any authorization check runs.

    action_type must match TOOL_CAPABILITY_MAP[tool_name]. The gateway
    enforces this — agents cannot downgrade the required capability.
    """
    tool_name: str
    arguments: dict[str, Any]
    proposal_id: str
    approval_id: str
    record_id: str
    action_type: str
    resource_id: str
    tenant_id: str
    # DVO evidence state for this request (provided by scenario or real infrastructure)
    dvo_state: DVOScenarioState
    # Scripted model verdict: True = model approves (may be "fooled")
    # None = no model inference (→ REQUIRES_REVIEW by design)
    model_verdict: bool | None = None
    model_reasoning: str = ""


@dataclass
class ToolExecutionResult:
    """
    Result of one ToolGateway.request() call.

    executed: True iff the tool actually ran (decision was ALLOW).
    execution_id: UUID assigned by the gateway; recorded in SandboxedGitHubTools history.
    decision_record: Full PolicyDecisionRecord for audit trail.
    enforcement_latency_ms: Wall-clock time from request() entry to exit.
    """
    executed: bool
    execution_id: str
    decision_record: PolicyDecisionRecord
    tool_result: dict[str, Any]
    args_binding_hash: str
    enforcement_latency_ms: float
    capability_mismatch: bool = False  # gateway rejected the tool/action_type pairing


# ---------------------------------------------------------------------------
# ToolGateway
# ---------------------------------------------------------------------------


class ToolGateway:
    """
    Authorization enforcement point.

    Usage:
        # Gateway creates its own ExecutionTokenAuthority and installs it on the
        # tools object during __init__. Callers do not need to manage the authority
        # unless they need to share it with custom tool objects.
        gateway = ToolGateway(
            policy_provider=TrustedPolicyProvider(POLICY_FIXTURE),
            tools=SandboxedGitHubTools(),
            replay_registry=ReplayRegistry(),
            revocation_list=RevocationList(),
            current_time=_NOW,
        )
        result = gateway.request(tool_request)
        assert result.executed == (result.decision_record.decision == PolicyDecision.ALLOW)
    """

    def __init__(
        self,
        policy_provider: TrustedPolicyProvider,
        tools: SandboxedGitHubTools,
        replay_registry: ReplayRegistry,
        revocation_list: RevocationList,
        current_time: float | None = None,
        key_provider: PolicyKeyProvider | None = None,
        token_authority: ExecutionTokenAuthority | None = None,
    ) -> None:
        self._policy_provider = policy_provider
        self._tools = tools
        self._replay_registry = replay_registry
        self._revocation_list = revocation_list
        self._current_time = current_time
        self._key_provider = key_provider

        # Install the token authority into the tools object so it can verify
        # EATs independently. If none is provided, create a fresh one.
        if token_authority is None:
            token_authority = ExecutionTokenAuthority()
        self._token_authority = token_authority
        self._tools._token_authority = token_authority

    def request(self, req: ToolRequest) -> ToolExecutionResult:
        """
        Authorize and conditionally execute a tool request.

        Steps:
          1. Compute and bind args_binding_hash over (tool_name, frozen_args,
             action_type, resource_id) — fixed before any check runs.
          2. Validate that tool_name maps to req.action_type (capability check).
          3. Build a DVO executor from req.dvo_state.
          4. Run ConditionIOrchestrator (Condition I: audit + approval + replay
             + revocation + policy lookup).
          5. Compute PolicyDecisionRecord from evidence + req.model_verdict.
          6. If ALLOW: pre-execution revocation check (second check immediately
             before token issuance, closing the auth→exec window).
          7. If ALLOW + revocation check passes: issue ExecutionToken binding
             authorization to this exact execution context.
          8. Call tools.execute() with the token (or None for blocked attempts).
             The tools object verifies the token independently.

        Authorization and execution are atomic within this call. req.arguments
        cannot change after the args_binding_hash is computed because the same
        frozen copy is used throughout (TOCTOU protection).
        """
        t0 = time.perf_counter()
        execution_id = str(uuid.uuid4())

        # Step 1 — Freeze a deep copy of arguments BEFORE any check.
        # This prevents TOCTOU: if the caller mutates req.arguments after
        # this point, the frozen copy (used for both hashing and execution)
        # is unaffected.
        frozen_args = copy.deepcopy(req.arguments)
        args_hash = compute_args_binding_hash(
            tool_name=req.tool_name,
            arguments=frozen_args,
            action_type=req.action_type,
            resource_id=req.resource_id,
        )

        # Step 2 — Capability map enforcement
        required_action = TOOL_CAPABILITY_MAP.get(req.tool_name)
        if required_action is not None and req.action_type != required_action:
            deny_record = PolicyDecisionRecord.deny(
                reasons=[
                    f"capability_mismatch:tool={req.tool_name!r}"
                    f"_requires={required_action!r}"
                    f"_requested={req.action_type!r}"
                ],
                orchestration_ms=(time.perf_counter() - t0) * 1000,
            )
            # Record blocked attempt using frozen_args (not req.arguments)
            self._tools.execute(
                tool_name=req.tool_name,
                arguments=frozen_args,
                execution_id=execution_id,
                tenant_id=req.tenant_id,
                args_binding_hash=args_hash,
                execution_token=None,
                decision_label=deny_record.decision.value,
            )
            return ToolExecutionResult(
                executed=False,
                execution_id=execution_id,
                decision_record=deny_record,
                tool_result={},
                args_binding_hash=args_hash,
                enforcement_latency_ms=(time.perf_counter() - t0) * 1000,
                capability_mismatch=True,
            )

        # Step 3 — Build DVO executor from scenario state
        dvo_executor = SandboxedDVOExecutor(req.dvo_state)

        # Steps 4–5 — Run ConditionI orchestration (fail-closed on exception)
        try:
            orchestrator = ConditionIOrchestrator(
                executor=dvo_executor,
                policy_provider=self._policy_provider,
                action_type=req.action_type,
                resource_id=req.resource_id,
                tenant_id=req.tenant_id,
                current_time=self._current_time,
                replay_registry=self._replay_registry,
                revocation_list=self._revocation_list,
                key_provider=self._key_provider,
            )
            evidence = orchestrator.orchestrate(
                proposal_id=req.proposal_id,
                approval_id=req.approval_id,
                record_id=req.record_id,
            )
            # Step 5 — Compute policy decision (model is advisory)
            decision_record = compute_policy_i_decision(
                evidence=evidence,
                model_verdict=req.model_verdict,
                model_reasoning=req.model_reasoning,
            )
        except Exception as exc:
            # Fail-closed: any unexpected exception from the policy or orchestration
            # layer is treated as INDETERMINATE → no execution.
            decision_record = PolicyDecisionRecord.indeterminate(
                reasons=[f"policy_service_exception:{type(exc).__name__}:{exc}"],
                orchestration_ms=(time.perf_counter() - t0) * 1000,
            )

        # Step 6 — Pre-execution revocation check (closes auth→exec window).
        # If the approval was revoked after orchestration completed but before
        # the token would be issued, we catch it here.
        execution_token: ExecutionToken | None = None
        if decision_record.decision == PolicyDecision.ALLOW:
            if self._revocation_list.is_revoked(
                approval_id=req.approval_id, tenant_id=req.tenant_id
            ):
                decision_record = PolicyDecisionRecord.deny(
                    reasons=["approval_revoked_before_execution"],
                    orchestration_ms=(time.perf_counter() - t0) * 1000,
                )
            else:
                # Step 7 — Issue ExecutionToken binding auth to this exact context.
                execution_token = self._token_authority.issue(
                    execution_id=execution_id,
                    tool_name=req.tool_name,
                    args_binding_hash=args_hash,
                    action_type=req.action_type,
                    resource_id=req.resource_id,
                    tenant_id=req.tenant_id,
                )

        authorized = decision_record.decision == PolicyDecision.ALLOW

        # Step 8 — Call tools.execute() with token (None for blocked attempts).
        # The tools object verifies the token independently. Even if someone
        # bypassed the gateway and called tools.execute() directly, they cannot
        # produce a token that verifies against this gateway's authority.
        # frozen_args (not req.arguments) are used for TOCTOU protection.
        tool_result = self._tools.execute(
            tool_name=req.tool_name,
            arguments=frozen_args,
            execution_id=execution_id,
            tenant_id=req.tenant_id,
            args_binding_hash=args_hash,
            execution_token=execution_token,
            decision_label=decision_record.decision.value,
        )

        return ToolExecutionResult(
            executed=authorized and tool_result.get("success", False),
            execution_id=execution_id,
            decision_record=decision_record,
            tool_result=tool_result,
            args_binding_hash=args_hash,
            enforcement_latency_ms=(time.perf_counter() - t0) * 1000,
        )
