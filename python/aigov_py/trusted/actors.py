"""The agent and the human approver, each with its own credential.

- ``AgentActor`` requests approvals and submits calls. Its key cannot approve, revoke, sign, or write receipts, and Core
  refuses each of those by role.
- ``ApproverActor`` decides approvals and revocations in one identity, which must match the identity Core
  authenticated for its key.

Neither actor performs a side effect. Calls that Core allows are performed by the executor (``executor.py``).
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from .core import CoreClient, CoreDecision, new_event
from .tools import ToolSpec, args_binding_hash


def _spec(tools: Mapping[str, ToolSpec], tool: str) -> ToolSpec:
    spec = tools.get(tool)
    if spec is None:
        raise KeyError(
            f"tool {tool!r} is not registered; Core would refuse it, and no request is sent"
        )
    return spec


class AgentActor:
    """The agent's own identity, bound to one run."""

    def __init__(
        self, core: CoreClient, run_id: str, tools: Mapping[str, ToolSpec]
    ) -> None:
        self.core = core
        self.run_id = run_id
        self.tools = dict(tools)

    def _event(self, event_type: str, payload: dict[str, Any]):  # type: ignore[no-untyped-def]
        return new_event(
            event_type,
            self.run_id,
            payload,
            actor=self.core.actor,
            system=self.core.system,
        )

    def request_approval(
        self, tool: str, args: dict[str, Any], tool_call_id: str
    ) -> CoreDecision:
        spec = _spec(self.tools, tool)
        return self.core.submit(
            self._event(
                "tool_approval_requested",
                {
                    "tool_name": tool,
                    "tool_call_id": tool_call_id,
                    "args_binding_hash": args_binding_hash(spec, args),
                },
            )
        )

    def submit_write(
        self, tool: str, args: dict[str, Any], tool_call_id: str, approval_event_id: str
    ) -> CoreDecision:
        spec = _spec(self.tools, tool)
        return self.core.submit(
            self._event(
                "consequential_tool_call",
                {
                    "tool_name": tool,
                    "tool_call_id": tool_call_id,
                    "approval_event_id": approval_event_id,
                    "args_binding_hash": args_binding_hash(spec, args),
                },
            )
        )

    def read(self, tool: str, args: dict[str, Any], tool_call_id: str) -> CoreDecision:
        spec = _spec(self.tools, tool)
        return self.core.submit(
            self._event(
                "tool_call",
                {
                    "tool_name": tool,
                    "tool_call_id": tool_call_id,
                    "args_binding_hash": args_binding_hash(spec, args),
                },
            )
        )

    def record_block(self, tool: str, tool_call_id: str, reason: str) -> CoreDecision:
        return self.core.submit(
            self._event(
                "tool_call_blocked",
                {"tool_name": tool, "tool_call_id": tool_call_id, "reason": reason},
            )
        )


class ApproverActor:
    """A human approver's own identity. ``identity`` must match the identity Core authenticated for this key."""

    def __init__(
        self, core: CoreClient, identity: str, tools: Mapping[str, ToolSpec]
    ) -> None:
        self.core = core
        self.identity = identity
        self.tools = dict(tools)

    def decide(
        self,
        *,
        run_id: str,
        request: CoreDecision,
        tool: str,
        args: dict[str, Any],
        tool_call_id: str,
        approve: bool,
        claimed_approver: str | None = None,
        ts_utc: str | None = None,
    ) -> CoreDecision:
        spec = _spec(self.tools, tool)
        return self.core.submit(
            new_event(
                "human_approved",
                run_id,
                {
                    "approver": claimed_approver
                    if claimed_approver is not None
                    else self.identity,
                    "decision": "approve" if approve else "reject",
                    "scope": "tool_execution",
                    "tool_name": tool,
                    "tool_call_id": tool_call_id,
                    "args_binding_hash": args_binding_hash(spec, args),
                    "policy_revision": request.policy_revision or "",
                    "request_event_id": request.event_id or "",
                },
                ts_utc=ts_utc,
                actor=self.core.actor,
                system=self.core.system,
            )
        )

    def revoke(
        self, *, run_id: str, approval_event_id: str, reason: str
    ) -> CoreDecision:
        return self.core.submit(
            new_event(
                "human_approval_revoked",
                run_id,
                {"approval_event_id": approval_event_id, "reason": reason},
                actor=self.core.actor,
                system=self.core.system,
            )
        )
