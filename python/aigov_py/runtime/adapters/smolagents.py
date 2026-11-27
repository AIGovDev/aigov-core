"""Trusted execution bridge for smolagents tools.

Expose only this bridge to the agent, never the underlying performer or
approver credentials. The executor owns all side effects.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from threading import BoundedSemaphore, Lock
from typing import Any
from uuid import uuid4

from aigov_py.trusted import AgentActor, CoreDecision, Decision, Executor, Refused

MAX_PENDING_APPROVALS = 128


@dataclass(frozen=True)
class PendingApproval:
    """Host-only binding between one original tool call and Core's request response."""

    tool: str
    call_id: str
    arguments: dict[str, Any]
    request: CoreDecision


def invoke_registered_tool(
    agent: AgentActor,
    executor: Executor,
    tool: str,
    arguments: dict[str, Any],
    *,
    call_id: str | None = None,
    approval_event_id: str | None = None,
    _pending_approvals: dict[str, PendingApproval] | None = None,
    _pending_lock: Any = None,
    _pending_slots: Any = None,
) -> dict[str, Any]:
    """Request authorization and execute only with Core's signed authorization.

    Host-only arguments are intentionally private and must never be derived from
    model-controlled tool arguments.
    """
    if tool not in agent.tools:
        raise Refused("tool_not_registered")
    args = json.loads(json.dumps(arguments, allow_nan=False))
    cid = call_id or str(uuid4())
    spec = agent.tools[tool]
    if spec.kind == "write" and not approval_event_id:
        slot_reserved = False
        if _pending_approvals is not None:
            if _pending_lock is None or _pending_slots is None:
                raise Refused("pending_approval_store_unavailable")
            if not _pending_slots.acquire(blocking=False):
                raise Refused("pending_approval_capacity_exceeded")
            slot_reserved = True
        try:
            request = agent.request_approval(tool, args, cid)
            if request.decision is Decision.ALLOW and request.event_id:
                if _pending_approvals is not None:
                    with _pending_lock:
                        _pending_approvals[cid] = PendingApproval(
                            tool=tool,
                            call_id=cid,
                            arguments=args,
                            request=request,
                        )
                    slot_reserved = False
                decision = "REQUIRE_APPROVAL"
            else:
                decision = (
                    request.decision.value
                    if request.decision is not Decision.ALLOW
                    else "INDETERMINATE"
                )
            return {
                "decision": decision,
                "call_id": cid,
                "request_event_id": request.event_id,
                "executed": False,
            }
        finally:
            if slot_reserved:
                _pending_slots.release()
    if spec.kind == "write":
        if not call_id:
            raise Refused("approval_call_id_required")
        decision = agent.submit_write(tool, args, cid, approval_event_id)
    else:
        decision = agent.read(tool, args, cid)
    if decision.decision is not Decision.ALLOW or not decision.authorization:
        return {
            "decision": decision.decision.value
            if decision.decision is not Decision.ALLOW
            else "INDETERMINATE",
            "call_id": cid,
            "executed": False,
        }
    outcome = executor.execute(
        run_id=agent.run_id, tool=tool, arguments=args, signed=decision.authorization
    )
    return {
        "decision": "ALLOW",
        "call_id": cid,
        "executed": outcome.executed,
        "reason": outcome.reason,
        "receipt_recorded": outcome.receipt_recorded,
    }


def take_pending_approval(tool: Any, call_id: str | None = None) -> PendingApproval:
    """Consume a Core-backed approval request from host-only adapter state.

    The returned handle contains the original arguments, call ID, Core event, and
    policy revision. If no ID is given, the oldest pending request for the named
    tool is consumed. This helper is never exposed as an agent tool.
    """
    pending = getattr(tool, "_aigov_pending_approvals", None)
    lock = getattr(tool, "_aigov_pending_lock", None)
    slots = getattr(tool, "_aigov_pending_slots", None)
    if pending is None or lock is None or slots is None:
        raise Refused("pending_approval_not_found")
    with lock:
        selected_id = call_id
        if selected_id is None:
            selected_id = next(
                (key for key, item in pending.items() if item.tool == tool.name), None
            )
        request = pending.get(selected_id) if selected_id is not None else None
        if request is not None and request.tool == tool.name:
            pending.pop(selected_id)
        else:
            request = None
    if request is None:
        raise Refused("pending_approval_not_found")
    slots.release()
    return request


def make_smolagents_tool(
    agent: AgentActor,
    executor: Executor,
    tool: str,
    *,
    description: str,
    inputs: dict[str, Any],
) -> Any:
    """Expose a registered tool as a status-returning smolagents Tool.

    The host supplies the schema. Approval resumption remains host-only.
    """
    from smolagents import Tool

    if tool not in agent.tools:
        raise Refused("tool_not_registered")
    if not isinstance(inputs, dict):
        raise TypeError("Tool inputs must be a mapping")
    if {"call_id", "approval_event_id"} & inputs.keys():
        raise ValueError("Reserved host-only input")

    pending_approvals: dict[str, PendingApproval] = {}
    pending_lock = Lock()
    pending_slots = BoundedSemaphore(MAX_PENDING_APPROVALS)

    class GovernedTool(Tool):
        name = tool
        output_type = "string"
        skip_forward_signature_validation = True

        def forward(self, **kwargs: Any) -> str:
            if not kwargs.keys() <= self.inputs.keys():
                raise Refused("unexpected_tool_argument")
            result = invoke_registered_tool(
                agent,
                executor,
                tool,
                kwargs,
                _pending_approvals=pending_approvals,
                _pending_lock=pending_lock,
                _pending_slots=pending_slots,
            )
            # Call IDs and approval event identifiers stay in host memory.
            result.pop("request_event_id", None)
            result.pop("policy_revision", None)
            result.pop("call_id", None)
            return json.dumps(result)

    GovernedTool.description = description
    GovernedTool.inputs = json.loads(json.dumps(inputs))
    GovernedTool._aigov_pending_approvals = pending_approvals
    GovernedTool._aigov_pending_lock = pending_lock
    GovernedTool._aigov_pending_slots = pending_slots
    return GovernedTool()
