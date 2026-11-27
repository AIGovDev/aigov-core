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
