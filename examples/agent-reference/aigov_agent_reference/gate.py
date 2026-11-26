"""Pre-execution gate for agent tool calls.

Every tool call the agent makes goes through ``AgentGate.request``. The gate evaluates
the call in this order, and stops at the first decision that is not ALLOW:

1. The tool must be on the agent's allowlist and must map to a known action type.
2. If the action type needs human approval:
   a. No approval ID yet -> create a pending request, return REQUIRE_APPROVAL.
   b. Unknown approval ID, or an approval that does not match this exact call (tool,
      action, resource, or argument binding hash) -> DENY.
   c. Pending -> REQUIRE_APPROVAL. Rejected -> DENY.
   d. Approved but expired or revoked -> DENY.
3. The approver of record (or the agent itself, for actions that need no approval) must
   be authorized by the signed policy for this action and resource and tenant.
4. The approval is consumed once (replay protection).
5. The revocation list is checked again immediately before execution.
6. A write-ahead entry is appended to the decision log. Only then is an execution token
   issued. The sandbox verifies that token itself before it runs anything.

Any exception in steps 1-6 returns INDETERMINATE and executes nothing (fail closed).
If the decision log cannot be written, nothing executes either, because the write-ahead
entry comes before execution.

``enforce=False`` turns the gate into a logging-only observer for the benchmark's
condition B. It records the same decisions and then executes every call anyway.
"""

from __future__ import annotations

import copy
import json
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

# The decision type is the SDK's, so the in-process gate and Core share one enum.
from aigov_py.trusted.core import Decision
from execution_token import ExecutionTokenAuthority
from replay_protection import ApprovalNonce, ReplayRegistry
from revocation_list import RevocationList
from sandboxed_tools import SandboxedGitHubTools, compute_args_binding_hash
from tool_gateway import TOOL_CAPABILITY_MAP

from .approvals import ApprovalStore
from .decision_log import DecisionLog, verify_chain
from .policy import ReferencePolicy


@dataclass(frozen=True)
class ToolCall:
    tool_name: str
    arguments: dict[str, Any]
    principal: str
    repo_id: str
    approval_id: str | None = None


@dataclass(frozen=True)
class GateOutcome:
    decision: Decision
    reason: str
    executed: bool
    execution_id: str
    approval_id: str | None
    latency_ms: float
    data: dict[str, Any] | None = None


@dataclass(frozen=True)
class _Evaluation:
    decision: Decision
    reason: str
    approval_id: str | None
    action_type: str
    resource_id: str
    args_hash: str
    approver: str | None
    nonce: ApprovalNonce | None


class AgentGate:
    def __init__(
        self,
        *,
        policy: ReferencePolicy,
        approvals: ApprovalStore,
        sandbox: SandboxedGitHubTools,
        decision_log: DecisionLog,
        replay: ReplayRegistry,
        revocation: RevocationList,
        token_authority: ExecutionTokenAuthority,
        enforce: bool = True,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._policy = policy
        self._approvals = approvals
        self._sandbox = sandbox
        self._log = decision_log
        self._replay = replay
        self._revocation = revocation
        self._authority = token_authority
        self._enforce = enforce
        self._clock = clock

    @property
    def decision_log(self) -> DecisionLog:
        return self._log

    # ------------------------------------------------------------------ evaluation

    def _evaluate(
        self, call: ToolCall, arguments: dict[str, Any], now: float
    ) -> _Evaluation:
        tenant = self._policy.tenant_id
        tool = call.tool_name

        def ev(decision: Decision, reason: str, **kw: Any) -> _Evaluation:
            fields: dict[str, Any] = {
                "approval_id": call.approval_id,
                "action_type": TOOL_CAPABILITY_MAP.get(tool, ""),
                "resource_id": call.repo_id,
                "args_hash": "",
                "approver": None,
                "nonce": None,
            }
            fields.update(kw)
            return _Evaluation(decision=decision, reason=reason, **fields)

        if (
            call.principal != self._policy.agent_principal
            or tool not in self._policy.allowed_tools
        ):
            return ev(Decision.DENY, "tool_not_permitted_for_agent")
        if tool not in TOOL_CAPABILITY_MAP:
            return ev(Decision.DENY, "unknown_tool")

        action = TOOL_CAPABILITY_MAP[tool]
        args_hash = compute_args_binding_hash(tool, arguments, action, call.repo_id)

        if action in self._policy.approval_required_action_types:
            if call.approval_id is None:
                new_id = self._approvals.create_request(
                    tenant_id=tenant,
                    tool_name=tool,
                    action_type=action,
                    resource_id=call.repo_id,
                    args_binding_hash=args_hash,
                    now=now,
                )
                return ev(
                    Decision.REQUIRE_APPROVAL,
                    "approval_required",
                    approval_id=new_id,
                    args_hash=args_hash,
                )

            rec = self._approvals.get(call.approval_id)
            if rec is None:
                return ev(Decision.DENY, "unknown_approval", args_hash=args_hash)
            if (
                rec.tenant_id != tenant
                or rec.tool_name != tool
                or rec.action_type != action
                or rec.resource_id != call.repo_id
                or rec.args_binding_hash != args_hash
            ):
                return ev(
                    Decision.DENY,
                    "approval_does_not_match_request",
                    args_hash=args_hash,
                )
            status = rec.status.value
            if status == "pending":
                return ev(
                    Decision.REQUIRE_APPROVAL, "approval_pending", args_hash=args_hash
                )
            if status == "rejected":
                return ev(
                    Decision.DENY,
                    "human_rejected",
                    args_hash=args_hash,
                    approver=rec.approver,
                )
            if rec.expires_at is None or now > rec.expires_at:
                return ev(
                    Decision.DENY,
                    "approval_expired",
                    args_hash=args_hash,
                    approver=rec.approver,
                )
            if self._revocation.is_revoked(call.approval_id, tenant):
                return ev(
                    Decision.DENY,
                    "approval_revoked",
                    args_hash=args_hash,
                    approver=rec.approver,
                )

            subject = rec.approver
            nonce = ApprovalNonce(
                approval_id=call.approval_id,
                tenant_id=tenant,
                action_type=action,
                resource_id=call.repo_id,
                proposal_id=args_hash,
            )
        else:
            subject = call.principal
            nonce = None

        lookup = self._policy.provider.lookup_authorization(
            approver_email=subject,
            action_type=action,
            resource_id=call.repo_id,
            tenant_id=tenant,
            current_time=now,
        )
        if not lookup.authorized:
            return ev(
                Decision.DENY,
                f"policy:{lookup.failure_reason}",
                args_hash=args_hash,
                approver=subject if nonce is not None else None,
                nonce=nonce,
            )

        if nonce is not None:
            if self._enforce:
                consumed = self._replay.try_consume(nonce)
            else:
                consumed = self._replay.is_consumed(nonce)
            if not consumed:
                return ev(
                    Decision.DENY,
                    "approval_replayed",
                    args_hash=args_hash,
                    approver=subject,
                    nonce=nonce,
                )
            if self._revocation.is_revoked(call.approval_id, tenant):
                return ev(
                    Decision.DENY,
                    "approval_revoked_before_execution",
                    args_hash=args_hash,
                    approver=subject,
                    nonce=nonce,
                )

        return ev(
            Decision.ALLOW,
            "authorized",
            args_hash=args_hash,
            approver=subject,
            nonce=nonce,
        )

    # ------------------------------------------------------------------ public API

    def request(self, call: ToolCall) -> GateOutcome:
        started = time.perf_counter()
        execution_id = "exe_" + uuid.uuid4().hex
        # Copy once. Authorization and execution both use this copy (no check-then-use gap).
        arguments = copy.deepcopy(call.arguments)
        now = self._clock()
        try:
            try:
                evaluation = self._evaluate(call, arguments, now)
            except Exception as exc:
                if self._enforce:
                    raise
                # Logging-only mode never blocks. Record the evaluation failure and let the call run.
                evaluation = _Evaluation(
                    decision=Decision.INDETERMINATE,
                    reason=f"gate_unavailable:{type(exc).__name__}",
                    approval_id=call.approval_id,
                    action_type=TOOL_CAPABILITY_MAP.get(call.tool_name, ""),
                    resource_id=call.repo_id,
                    args_hash=compute_args_binding_hash(
                        call.tool_name,
                        arguments,
                        TOOL_CAPABILITY_MAP.get(call.tool_name, ""),
                        call.repo_id,
                    ),
                    approver=None,
                    nonce=None,
                )
            self._log.append(
                {
                    "event": "decision",
                    "execution_id": execution_id,
                    "tool": call.tool_name,
                    "principal": call.principal,
                    "decision": evaluation.decision.value,
                    "reason": evaluation.reason,
                    "approval_id": evaluation.approval_id,
                    "approver": evaluation.approver,
                    "args_binding_hash": evaluation.args_hash,
                    "enforced": self._enforce,
                }
            )
            allow = evaluation.decision == Decision.ALLOW
            if not allow and self._enforce:
                return self._outcome(
                    evaluation, execution_id, executed=False, started=started
                )
            # Write-ahead: the authorization entry is recorded before the token is issued.
            self._log.append(
                {
                    "event": "authorized" if allow else "logged_only_would_block",
                    "execution_id": execution_id,
                    "tool": call.tool_name,
                }
            )
            token = self._authority.issue(
                execution_id=execution_id,
                tool_name=call.tool_name,
                args_binding_hash=evaluation.args_hash,
                action_type=evaluation.action_type,
                resource_id=evaluation.resource_id,
                tenant_id=self._policy.tenant_id,
            )
            result = self._sandbox.execute(
                call.tool_name,
                arguments,
                execution_id=execution_id,
                tenant_id=self._policy.tenant_id,
                args_binding_hash=evaluation.args_hash,
                execution_token=token,
                decision_label="allow" if allow else "logged_only",
                expected_action_type=evaluation.action_type,
                expected_resource_id=evaluation.resource_id,
            )
            self._log.append(
                {
                    "event": "executed",
                    "execution_id": execution_id,
                    "success": bool(result.get("success")),
                    "blocked_reason": result.get("blocked_reason"),
                }
            )
            if not allow:
                # Logging-only mode: the decision is what the gate would have decided. The
                # call ran anyway, and `executed` records that.
                return GateOutcome(
                    evaluation.decision,
                    evaluation.reason,
                    bool(result.get("success")),
                    execution_id,
                    evaluation.approval_id,
                    _ms(started),
                    data=result.get("data"),
                )
            if not result.get("success"):
                return GateOutcome(
                    Decision.DENY,
                    f"sandbox:{result.get('blocked_reason')}",
                    False,
                    execution_id,
                    evaluation.approval_id,
                    _ms(started),
                )
            return self._outcome(
                evaluation,
                execution_id,
                executed=True,
                started=started,
                data=result.get("data"),
            )
        except Exception as exc:  # noqa: BLE001 - fail closed on any error, including log failures
            return GateOutcome(
                Decision.INDETERMINATE,
                f"gate_unavailable:{type(exc).__name__}",
                False,
                execution_id,
                call.approval_id,
                _ms(started),
            )

    def _outcome(
        self,
        ev: _Evaluation,
        execution_id: str,
        *,
        executed: bool,
        started: float,
        data: dict[str, Any] | None = None,
    ) -> GateOutcome:
        return GateOutcome(
            decision=ev.decision,
            reason=ev.reason,
            executed=executed,
            execution_id=execution_id,
            approval_id=ev.approval_id,
            latency_ms=_ms(started),
            data=data,
        )


def _ms(started: float) -> float:
    return (time.perf_counter() - started) * 1000.0


def verify_evidence(
    log_path: Path, sandbox: SandboxedGitHubTools
) -> tuple[bool, list[str]]:
    """Check the decision log and the sandbox history against each other.

    Passes when the hash chain verifies and every sandbox execution that was authorized is
    preceded in the log by an ``authorized`` entry for the same execution ID.
    """
    problems: list[str] = []
    ok, reason = verify_chain(Path(log_path))
    if not ok:
        problems.append(f"chain:{reason}")
    authorized_ids = set()
    if ok:
        for line in Path(log_path).read_text().splitlines():
            if not line.strip():
                continue
            entry = json.loads(line)["entry"]
            if entry.get("event") == "authorized":
                authorized_ids.add(entry["execution_id"])
    for record in sandbox.execution_history():
        if record.authorized and record.execution_id not in authorized_ids:
            problems.append(f"unlogged_execution:{record.execution_id}")
    return (not problems), problems
