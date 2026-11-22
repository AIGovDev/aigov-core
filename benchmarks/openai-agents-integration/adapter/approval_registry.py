"""
Pre-approval registry for the AIGov OpenAI Agents SDK integration.

In production, approvals are obtained from a human reviewer or automated
policy system BEFORE the AI agent runs. This registry simulates that:
the harness pre-registers approvals, the agent consumes them when it
invokes tools.

Design invariants:
  - Each registered approval may only be consumed ONCE (single-use).
    Replay attempts raise ApprovalNotFound.
  - Approvals are keyed by (tool_name, action_type, resource_id, tenant_id).
    A wrong key fails: cross-tenant or cross-resource consumption is
    structurally impossible.
  - Thread-safe via a lock (single-process tests only; production would
    use a persistent approval store).

This models the real-world "pre-approval" lifecycle:
  1. Human or policy system approves a specific action on a specific resource
     for a specific tenant.
  2. The agent runs and invokes the tool.
  3. The adapter consumes the approval and passes it to the AIGov gateway.
  4. If no approval exists (or was already consumed), the tool call is denied.
"""

from __future__ import annotations

import threading
import uuid
from dataclasses import dataclass, field
from typing import Any

import sys
from pathlib import Path

_BENCH = Path(__file__).parent.parent.parent / "agent-verification"
sys.path.insert(0, str(_BENCH))

from sandboxed_tools import DVOScenarioState


class ApprovalNotFound(Exception):
    """Raised when no matching approval exists or it was already consumed."""


@dataclass(frozen=True)
class ApprovalKey:
    tool_name: str
    action_type: str
    resource_id: str
    tenant_id: str


@dataclass
class ApprovalEntry:
    proposal_id: str
    approval_id: str
    record_id: str
    approver_email: str
    # DVO evidence state for this approval
    audit_found: bool = True
    audit_hash_verified: bool = True
    audit_executed_value: str | None = None
    approval_active: bool = True
    approval_matches_proposal: bool = True
    external_state_value: str | None = "approved"


class ApprovalRegistry:
    """
    Single-use pre-approval store.

    Usage:
        registry = ApprovalRegistry()
        registry.register(
            tool_name="update_document",
            action_type="document:write",
            resource_id="tenant-A/doc-1",
            tenant_id="tenant-A",
            approver_email="alice@example.com",
        )
        # ... agent runs and calls update_document ...
        # adapter consumes the approval:
        entry, dvo = registry.consume("update_document", "document:write",
                                      "tenant-A/doc-1", "tenant-A")
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        # key → list of entries (FIFO; first registered is first consumed)
        self._approvals: dict[ApprovalKey, list[ApprovalEntry]] = {}
        # history of consumed approvals (for audit assertions)
        self._consumed: list[tuple[ApprovalKey, ApprovalEntry]] = []

    def register(
        self,
        tool_name: str,
        action_type: str,
        resource_id: str,
        tenant_id: str,
        approver_email: str = "approver@example.com",
        proposal_id: str | None = None,
        approval_id: str | None = None,
        record_id: str | None = None,
        audit_found: bool = True,
        audit_hash_verified: bool = True,
        audit_executed_value: str | None = None,
        approval_active: bool = True,
        approval_matches_proposal: bool = True,
        external_state_value: str | None = "approved",
    ) -> ApprovalEntry:
        """Register one single-use approval. Returns the entry."""
        key = ApprovalKey(tool_name, action_type, resource_id, tenant_id)
        entry = ApprovalEntry(
            proposal_id=proposal_id or f"prop-{uuid.uuid4().hex[:8]}",
            approval_id=approval_id or f"appr-{uuid.uuid4().hex[:8]}",
            record_id=record_id or f"rec-{uuid.uuid4().hex[:8]}",
            approver_email=approver_email,
            audit_found=audit_found,
            audit_hash_verified=audit_hash_verified,
            audit_executed_value=audit_executed_value,
            approval_active=approval_active,
            approval_matches_proposal=approval_matches_proposal,
            external_state_value=external_state_value,
        )
        with self._lock:
            self._approvals.setdefault(key, []).append(entry)
        return entry

    def consume(
        self,
        tool_name: str,
        action_type: str,
        resource_id: str,
        tenant_id: str,
    ) -> tuple[ApprovalEntry, DVOScenarioState]:
        """
        Consume one approval for (tool, action, resource, tenant).

        Returns (entry, dvo_state) for use in ToolGateway.request().
        Raises ApprovalNotFound if no approval matches or none remain.
        """
        key = ApprovalKey(tool_name, action_type, resource_id, tenant_id)
        with self._lock:
            entries = self._approvals.get(key, [])
            if not entries:
                raise ApprovalNotFound(
                    f"No pre-approval for tool={tool_name!r} action={action_type!r} "
                    f"resource={resource_id!r} tenant={tenant_id!r}"
                )
            entry = entries.pop(0)
            self._consumed.append((key, entry))

        dvo = DVOScenarioState(
            proposal_id=entry.proposal_id,
            approval_id=entry.approval_id,
            record_id=entry.record_id,
            approver_email=entry.approver_email,
            audit_found=entry.audit_found,
            audit_hash_verified=entry.audit_hash_verified,
            audit_executed_value=entry.audit_executed_value,
            approval_active=entry.approval_active,
            approval_matches_proposal=entry.approval_matches_proposal,
            external_state_value=entry.external_state_value,
        )
        return entry, dvo

    def pending_count(self) -> int:
        """Number of unconsumed approvals."""
        with self._lock:
            return sum(len(v) for v in self._approvals.values())

    def consumed_count(self) -> int:
        with self._lock:
            return len(self._consumed)

    def reset(self) -> None:
        """Clear all approvals and history (between test cases)."""
        with self._lock:
            self._approvals.clear()
            self._consumed.clear()
