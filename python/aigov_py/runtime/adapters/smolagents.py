"""Trusted execution bridge for smolagents tools.

Expose only this bridge to the agent, never the underlying performer or
approver credentials. The executor owns all side effects.
"""
from __future__ import annotations

import json
from typing import Any
from uuid import uuid4

from aigov_py.trusted import AgentActor, Decision, Executor, Refused


def invoke_registered_tool(
    agent: AgentActor, executor: Executor, tool: str, arguments: dict[str, Any],
    *, call_id: str | None = None, approval_event_id: str | None = None,
) -> dict[str, Any]:
    """Return a status, not the underlying tool's result.

    Approval identifiers must come from the trusted host, not model input.
    """
    if tool not in agent.tools:
        raise Refused("tool_not_registered")
    args = json.loads(json.dumps(arguments, allow_nan=False))
    cid = call_id or str(uuid4())
    spec = agent.tools[tool]
    if spec.kind == "write" and not approval_event_id:
        request = agent.request_approval(tool, args, cid)
        return {
            "decision": "REQUIRE_APPROVAL" if request.decision is Decision.ALLOW else request.decision.value,
            "call_id": cid,
            "request_event_id": request.event_id,
            "executed": False,
        }
    if spec.kind == "write":
        if not call_id:
            raise Refused("approval_call_id_required")
        decision = agent.submit_write(tool, args, cid, approval_event_id)
    else:
        decision = agent.read(tool, args, cid)
    if decision.decision is not Decision.ALLOW or not decision.authorization:
        return {"decision": decision.decision.value if decision.decision is not Decision.ALLOW else "INDETERMINATE",
                "call_id": cid, "executed": False}
    outcome = executor.execute(run_id=agent.run_id, tool=tool, arguments=args,
                               signed=decision.authorization)
    return {"decision": "ALLOW", "call_id": cid, "executed": outcome.executed,
            "reason": outcome.reason, "receipt_recorded": outcome.receipt_recorded}


def make_smolagents_tool(agent: AgentActor, executor: Executor, tool: str,
                         *, description: str, inputs: dict[str, Any]) -> Any:
    """Expose a registered tool as a status-returning smolagents Tool.

    The host supplies the schema. Approval resumption remains host-only.
    """
    from smolagents import Tool

    if tool not in agent.tools:
        raise Refused("tool_not_registered")
    if not isinstance(inputs, dict):
        raise ValueError("Tool inputs must be a mapping")
    if {"call_id", "approval_event_id"} & inputs.keys():
        raise ValueError("Reserved host-only input")

    class GovernedTool(Tool):
        name = tool
        output_type = "string"
        skip_forward_signature_validation = True

        def forward(self, **kwargs: Any) -> str:
            if not kwargs.keys() <= self.inputs.keys():
                raise Refused("unexpected_tool_argument")
            return json.dumps(invoke_registered_tool(agent, executor, tool, kwargs))

    GovernedTool.description = description
    GovernedTool.inputs = json.loads(json.dumps(inputs))
    return GovernedTool()
