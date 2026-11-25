"""Run tool calls through AIGov Core. The sandbox runs a call only after Core accepts it.

Order for every call:

1. The runner submits the call to Core as an evidence event (``tool_call`` for reads,
   ``consequential_tool_call`` for writes). Core applies the signed policy.
2. Core answers ALLOW (accepted, with a record hash), REQUIRE_APPROVAL, DENY, or
   INDETERMINATE (Core unreachable). The runner takes that answer as the decision.
3. Only on ALLOW does the runner issue a sandbox execution token and call the sandbox. The
   sandbox still verifies the token before it changes anything.
4. A refusal is recorded in Core as ``tool_call_blocked``.

The runner holds no authorization logic of its own. It needs only the sandbox and the token
authority, which are the execution side of the decision.
"""

from __future__ import annotations

import copy
import uuid
from dataclasses import dataclass, field
from typing import Any

from execution_token import ExecutionTokenAuthority
from sandboxed_tools import SandboxedGitHubTools, compute_args_binding_hash
from tool_gateway import TOOL_CAPABILITY_MAP

from .core_gate import CoreClient, CoreDecision, new_event
from .gate import Decision

TENANT = "acme-corp"
AGENT = "agent:release-bot"


@dataclass
class CallOutcome:
    decision: Decision
    reason: str
    executed: bool
    core_event_id: str | None = None
    core_record_hash: str | None = None
    request_event_id: str | None = None
    execution_id: str | None = None
    latencies_ms: list[tuple[str, float]] = field(default_factory=list)

    @classmethod
    def from_core(cls, d: CoreDecision, *, executed: bool = False) -> CallOutcome:
        return cls(
            decision=d.decision,
            reason=d.reason,
            executed=executed,
            core_event_id=d.event_id,
            core_record_hash=d.record_hash,
        )


class CoreRunner:
    def __init__(self, core: CoreClient) -> None:
        self.core = core
        self.authority = ExecutionTokenAuthority()
        self.sandbox = SandboxedGitHubTools(token_authority=self.authority)
        self.submissions: list[tuple[str, float]] = []

    # ------------------------------------------------------------------ Core submissions

    def _submit(
        self,
        event_type: str,
        run_id: str,
        payload: dict[str, Any],
        *,
        ts_utc: str | None = None,
    ) -> CoreDecision:
        event = new_event(event_type, run_id, payload, ts_utc=ts_utc)
        decision = self.core.submit(event)
        self.submissions.append((event_type, decision.latency_ms))
        return decision

    # ------------------------------------------------------------------ operations

    def read(
        self, run_id: str, tool: str, args: dict[str, Any], repo: str, tool_call_id: str
    ) -> CallOutcome:
        decision = self._submit(
            "tool_call", run_id, {"tool_name": tool, "tool_call_id": tool_call_id}
        )
        if decision.decision != Decision.ALLOW:
            self._record_block(run_id, tool, tool_call_id, decision.reason)
            return CallOutcome.from_core(decision)
        outcome = CallOutcome.from_core(decision, executed=False)
        return self._execute(outcome, tool, args, repo)

    def request_approval(
        self, run_id: str, tool: str, args: dict[str, Any], tool_call_id: str
    ) -> CoreDecision:
        binding = self._binding(tool, args, repo=args["repo_id"])
        return self._submit(
            "tool_approval_requested",
            run_id,
            {
                "tool_name": tool,
                "tool_call_id": tool_call_id,
                "args_binding_hash": binding,
            },
        )

    def human_decide(
        self,
        run_id: str,
        approver: str,
        approve: bool,
        tool: str,
        args: dict[str, Any],
        tool_call_id: str,
        *,
        ts_utc: str | None = None,
    ) -> CoreDecision:
        """A human decision, posted to Core as a ``human_approved`` event. Core checks the approver."""
        binding = self._binding(tool, args, repo=args["repo_id"])
        return self._submit(
            "human_approved",
            run_id,
            {
                "approver": approver,
                "decision": "approve" if approve else "reject",
                "scope": "tool_execution",
                "tool_call_id": tool_call_id,
                "args_binding_hash": binding,
            },
            ts_utc=ts_utc,
        )

    def write(
        self,
        run_id: str,
        tool: str,
        args: dict[str, Any],
        tool_call_id: str,
        approval_event_id: str | None,
    ) -> CallOutcome:
        """A consequential call.

        With no approval yet, the runner first records an approval request in Core. It then
        probes Core with that request as the approval. Core refuses, and the runner reports
        REQUIRE_APPROVAL. The request is recorded and visible to the approver.
        """
        binding = self._binding(tool, args, repo=args["repo_id"])
        request_event_id: str | None = None
        if approval_event_id is None:
            requested = self.request_approval(run_id, tool, args, tool_call_id)
            if requested.decision != Decision.ALLOW:
                outcome = CallOutcome.from_core(requested)
                self._record_block(run_id, tool, tool_call_id, requested.reason)
                return outcome
            request_event_id = requested.event_id
            approval_event_id = request_event_id
        decision = self._submit(
            "consequential_tool_call",
            run_id,
            {
                "tool_name": tool,
                "tool_call_id": tool_call_id,
                "approval_event_id": approval_event_id,
                "args_binding_hash": binding,
            },
        )
        if decision.decision != Decision.ALLOW:
            self._record_block(run_id, tool, tool_call_id, decision.reason)
            outcome = CallOutcome.from_core(decision)
            outcome.request_event_id = request_event_id
            return outcome
        outcome = CallOutcome.from_core(decision, executed=False)
        outcome.request_event_id = request_event_id
        return self._execute(outcome, tool, args, args["repo_id"])

    # ------------------------------------------------------------------ helpers

    def _binding(self, tool: str, args: dict[str, Any], *, repo: str) -> str:
        action = TOOL_CAPABILITY_MAP[tool]
        return compute_args_binding_hash(tool, args, action, repo)

    def _record_block(
        self, run_id: str, tool: str, tool_call_id: str, reason: str
    ) -> None:
        # Core's refusal is the decision. This record keeps the refusal in the ledger.
        self._submit(
            "tool_call_blocked",
            run_id,
            {"tool_name": tool, "tool_call_id": tool_call_id, "reason": reason},
        )

    def _execute(
        self, outcome: CallOutcome, tool: str, args: dict[str, Any], repo: str
    ) -> CallOutcome:
        """Run the sandbox call. Core has accepted it, so the local token is issued now."""
        call_args = copy.deepcopy(args)
        action = TOOL_CAPABILITY_MAP[tool]
        binding = compute_args_binding_hash(tool, call_args, action, repo)
        execution_id = "exe_" + uuid.uuid4().hex
        token = self.authority.issue(
            execution_id=execution_id,
            tool_name=tool,
            args_binding_hash=binding,
            action_type=action,
            resource_id=repo,
            tenant_id=TENANT,
        )
        result = self.sandbox.execute(
            tool,
            call_args,
            execution_id=execution_id,
            tenant_id=TENANT,
            args_binding_hash=binding,
            execution_token=token,
            decision_label="core_accepted",
            expected_action_type=action,
            expected_resource_id=repo,
        )
        outcome.executed = bool(result.get("success"))
        outcome.execution_id = execution_id
        if not outcome.executed:
            outcome.decision = Decision.DENY
            outcome.reason = f"sandbox:{result.get('blocked_reason')}"
        return outcome


def unavailable_core(base_url: str = "http://127.0.0.1:9") -> CoreClient:
    """A client pointed at an address where nothing listens. Used to show fail-closed behaviour."""
    return CoreClient(base_url, "unused-key", timeout_sec=2.0)
