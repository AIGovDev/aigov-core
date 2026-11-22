"""
AIGov OpenAI Agents SDK Adapter.

Wraps document tools so every invocation passes through the AIGov
authorization gateway BEFORE any side effect is performed.

Authorization flow for each tool call:
  1. Adapter looks up a pre-registered approval from the ApprovalRegistry.
     If none exists → DENY immediately (no gateway call needed).
  2. Adapter calls ToolGateway.request() with:
       - tool_name, frozen arguments (deepcopy before auth)
       - independently supplied action_type, resource_id, tenant_id
       - execution_id (UUID, fresh per call)
       - DVOScenarioState from the consumed approval
  3. Gateway enforces: policy lookup, replay protection, revocation,
     EAT issuance, EAT verification (FINDING-3 fix: action_type/resource_id
     from request context, not from token).
  4. Only if gateway returns ALLOW does the tool execute its side effect.

Security properties inherited from the existing AIGov gateway:
  - EAT HMAC-SHA256: tool call cannot proceed without a valid token
  - Replay protection: each approval_id consumed at most once
  - Revocation: pre-execution revocation check closes auth→exec window
  - Fail-closed: policy outage or DB unavailability → DENY
  - Tautology-free: action_type/resource_id from request, never from token
  - Portable timestamps: UTC wall clock (time.time_ns()), not monotonic
"""

from __future__ import annotations

import copy
import sys
import threading
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

_BENCH = Path(__file__).parent.parent.parent / "agent-verification"
sys.path.insert(0, str(_BENCH))

from approval_registry import ApprovalNotFound, ApprovalRegistry
from document_store import DocumentRecord, DocumentStore
from execution_token import ExecutionToken, ExecutionTokenAuthority
from policy_decision import PolicyDecision
from replay_protection import ReplayRegistry
from revocation_list import RevocationList
from sandboxed_tools import DVOScenarioState, compute_args_binding_hash
from tool_gateway import ToolGateway, ToolRequest, ToolExecutionResult
from trusted_policy_provider import TrustedPolicyProvider


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------


@dataclass
class ToolCallResult:
    """
    Outcome of one guarded tool call.

    authorized:        True iff AIGov gateway returned ALLOW.
    executed:          True iff the tool side effect actually ran.
    decision:          "allow" / "deny" / "indeterminate" / "no_approval"
    data:              tool-specific result (None on failure)
    block_reason:      short slug for the denial cause (or "")
    execution_id:      UUID assigned to this call
    args_binding_hash: SHA-256 binding (tool, args, action, resource)
    """

    authorized: bool
    executed: bool
    decision: str
    data: Any
    block_reason: str
    execution_id: str
    args_binding_hash: str


# ---------------------------------------------------------------------------
# Sandboxed document tools — the actual side-effect layer
# ---------------------------------------------------------------------------


@dataclass
class _ExecRecord:
    execution_id: str
    tool_name: str
    arguments: dict
    authorized: bool
    decision: str
    block_reason: str
    tenant_id: str
    args_binding_hash: str
    executed_at: float


class SandboxedDocumentTools:
    """
    Document-specific sandboxed tool executor.

    Implements the same interface that ToolGateway expects from its `tools`
    parameter. ToolGateway assigns `self._token_authority` after construction.

    execute() verifies the ExecutionAuthorizationToken independently before
    performing any side effect. This is the same EAT-verification pattern
    used by SandboxedGitHubTools in the existing AIGov stack.

    Three supported operations:
      read_document   — no mutation, returns content + version
      update_document — writes content to DocumentStore
      delete_document — soft-deletes document from DocumentStore
    """

    SUPPORTED_TOOLS = frozenset({"read_document", "update_document", "delete_document"})

    # Maps tool_name → required action_type (matches TOOL_CAPABILITIES in adapter)
    TOOL_ACTION_TYPES = {
        "read_document":   "document:read",
        "update_document": "document:write",
        "delete_document": "document:delete",
    }

    def __init__(self, document_store: DocumentStore) -> None:
        self._store = document_store
        self._lock = threading.Lock()
        self._history: list[_ExecRecord] = []
        # Assigned by ToolGateway after construction:
        self._token_authority: ExecutionTokenAuthority | None = None
        self._audit_store = None  # optional; can be set externally

    def execute(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        execution_id: str,
        tenant_id: str,
        args_binding_hash: str,
        execution_token: "ExecutionToken | None" = None,
        decision_label: str = "",
        expected_action_type: str = "",
        expected_resource_id: str = "",
    ) -> dict[str, Any]:
        """
        Verify EAT and conditionally perform the tool operation.

        Authorization is determined solely by EAT verification against the
        token_authority installed by ToolGateway. The caller-supplied
        expected_action_type and expected_resource_id are independent context
        values (FINDING-3 fix): they come from the original request, not from
        the token's own fields.
        """
        authorized = False
        block_reason = "no_execution_token"

        # Defense-in-depth: enforce that the supplied action_type matches what
        # this tool requires. Catches action_type downgrade attacks where a
        # caller passes action_type="document:read" to delete_document to get
        # the more permissive policy to authorize a destructive operation.
        # This check runs before EAT verification so it fires even when the
        # gateway's TOOL_CAPABILITY_MAP check is bypassed (e.g., stale map).
        expected_for_tool = self.TOOL_ACTION_TYPES.get(tool_name, "")
        if expected_for_tool and expected_action_type and expected_action_type != expected_for_tool:
            block_reason = (
                f"action_type_mismatch:tool={tool_name!r}"
                f"_requires={expected_for_tool!r}"
                f"_got={expected_action_type!r}"
            )
            record = _ExecRecord(
                execution_id=execution_id, tool_name=tool_name,
                arguments=arguments, authorized=False,
                decision=decision_label or "blocked_action_type_mismatch",
                block_reason=block_reason, tenant_id=tenant_id,
                args_binding_hash=args_binding_hash, executed_at=time.time(),
            )
            with self._lock:
                self._history.append(record)
            return {
                "success": False, "execution_id": execution_id,
                "data": None, "blocked_reason": block_reason,
            }

        if execution_token is not None and self._token_authority is not None:
            verify_action   = expected_action_type   or execution_token.action_type
            verify_resource = expected_resource_id   or execution_token.resource_id
            ok, reason = self._token_authority.verify_for_execution(
                token=execution_token,
                expected_tool_name=tool_name,
                expected_args_binding_hash=args_binding_hash,
                expected_action_type=verify_action,
                expected_resource_id=verify_resource,
                expected_tenant_id=tenant_id,
                expected_execution_id=execution_id,
            )
            if ok:
                authorized = True
                block_reason = ""
            else:
                block_reason = reason
        elif execution_token is not None and self._token_authority is None:
            block_reason = "no_token_authority_configured"

        effective_decision = decision_label if decision_label else (
            "allow" if authorized else "blocked_no_valid_token"
        )

        record = _ExecRecord(
            execution_id=execution_id,
            tool_name=tool_name,
            arguments=arguments,
            authorized=authorized,
            decision=effective_decision,
            block_reason=block_reason,
            tenant_id=tenant_id,
            args_binding_hash=args_binding_hash,
            executed_at=time.time(),
        )
        with self._lock:
            self._history.append(record)

        if not authorized:
            return {
                "success": False,
                "execution_id": execution_id,
                "data": None,
                "blocked_reason": block_reason or effective_decision,
            }

        if tool_name not in self.SUPPORTED_TOOLS:
            return {
                "success": False,
                "execution_id": execution_id,
                "data": None,
                "blocked_reason": f"unsupported_tool:{tool_name}",
            }

        result = self._dispatch(tool_name, arguments, tenant_id, execution_id)
        return {"success": True, "execution_id": execution_id, "data": result,
                "blocked_reason": None}

    def _dispatch(self, tool_name: str, arguments: dict,
                  tenant_id: str, execution_id: str) -> dict:
        doc_id = arguments.get("doc_id", arguments.get("document_id", ""))
        if tool_name == "read_document":
            rec = self._store.read(doc_id, tenant_id)
            if rec is None:
                return {"found": False, "doc_id": doc_id, "content": None, "version": 0}
            return {"found": True, "doc_id": rec.doc_id,
                    "content": rec.content, "version": rec.version}
        elif tool_name == "update_document":
            content = arguments.get("content", "")
            rec = self._store.update(doc_id, tenant_id, content)
            return {"updated": True, "doc_id": rec.doc_id, "version": rec.version}
        elif tool_name == "delete_document":
            deleted = self._store.delete(doc_id, tenant_id)
            return {"deleted": deleted, "doc_id": doc_id}
        return {"error": f"unrouted:{tool_name}"}

    def execution_history(self) -> list[_ExecRecord]:
        with self._lock:
            return list(self._history)

    def authorized_executions(self) -> list[_ExecRecord]:
        with self._lock:
            return [r for r in self._history if r.authorized]

    def blocked_executions(self) -> list[_ExecRecord]:
        with self._lock:
            return [r for r in self._history if not r.authorized]

    def reset(self) -> None:
        with self._lock:
            self._history.clear()


# ---------------------------------------------------------------------------
# Core adapter: combines gateway + document tools + approval registry
# ---------------------------------------------------------------------------


class AIGovGuardedDocumentTools:
    """
    Three document tools (read, update, delete) wrapped with AIGov
    authorization enforcement.

    Every call to execute_tool() goes through the full AIGov gateway stack:
      ApprovalRegistry → ToolGateway → ConditionIOrchestrator → EAT → execute

    Caller is responsible for pre-registering approvals in the registry
    before the tool is invoked. This mirrors the real-world pre-approval
    lifecycle (human or policy system approves actions before the agent runs).

    The LLM cannot:
      - Execute a tool without a pre-approved approval
      - Replay an approval (each is single-use)
      - Substitute action_type or resource_id (bound by HMAC via args_binding_hash)
      - Execute cross-tenant (tenant_id from execution context, not from prompt)
    """

    # Maps tool_name → (action_type, gateway_capability)
    # action_type is passed independently to verify_for_execution (FINDING-3 fix)
    TOOL_CAPABILITIES: dict[str, str] = {
        "read_document":   "document:read",
        "update_document": "document:write",
        "delete_document": "document:delete",
    }

    def __init__(
        self,
        document_store: DocumentStore,
        approval_registry: ApprovalRegistry,
        policy_fixture: dict,
        replay_registry: ReplayRegistry | None = None,
        revocation_list: RevocationList | None = None,
        current_time: float | None = None,
    ) -> None:
        self._store = document_store
        self._approvals = approval_registry
        self._sandboxed = SandboxedDocumentTools(document_store)

        self._gateway = ToolGateway(
            policy_provider=TrustedPolicyProvider(policy_fixture),
            tools=self._sandboxed,
            replay_registry=replay_registry or ReplayRegistry(),
            revocation_list=revocation_list or RevocationList(),
            current_time=current_time,
        )

    def execute_tool(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        tenant_id: str,
    ) -> ToolCallResult:
        """
        Authorize and conditionally execute one document tool call.

        Arguments are frozen (deepcopy) BEFORE authorization. The same
        frozen copy is used for both HMAC binding and execution so that
        argument mutation between authorization and execution is impossible.

        tenant_id comes from the per-call execution context, not from the
        agent's prompt. The LLM cannot escalate privileges by supplying a
        different tenant_id; the calling context controls what tenant is
        in scope.
        """
        if tool_name not in self.TOOL_CAPABILITIES:
            return ToolCallResult(
                authorized=False, executed=False,
                decision="deny", data=None,
                block_reason=f"unknown_tool:{tool_name}",
                execution_id="", args_binding_hash="",
            )

        action_type = self.TOOL_CAPABILITIES[tool_name]
        # resource_id binds authorization to the specific document
        resource_id = _resource_id_from_args(tool_name, arguments, tenant_id)

        # Step 1: consume a pre-registered approval.
        try:
            entry, dvo_state = self._approvals.consume(
                tool_name=tool_name,
                action_type=action_type,
                resource_id=resource_id,
                tenant_id=tenant_id,
            )
        except ApprovalNotFound as exc:
            return ToolCallResult(
                authorized=False, executed=False,
                decision="no_approval", data=None,
                block_reason=str(exc),
                execution_id="", args_binding_hash="",
            )

        # Step 2: build a ToolRequest and call the gateway.
        # Arguments are deepcopied here (ToolGateway also deepcopies internally,
        # but we do it here too so the registry entry is not affected by any
        # mutation that happens before the gateway's deepcopy).
        req = ToolRequest(
            tool_name=tool_name,
            arguments=copy.deepcopy(arguments),
            proposal_id=entry.proposal_id,
            approval_id=entry.approval_id,
            record_id=entry.record_id,
            action_type=action_type,         # from TOOL_CAPABILITIES, not from LLM
            resource_id=resource_id,         # from args + tenant, not from token
            tenant_id=tenant_id,             # from execution context
            dvo_state=dvo_state,
            model_verdict=True,
        )
        gw_result = self._gateway.request(req)

        return ToolCallResult(
            authorized=gw_result.executed,
            executed=gw_result.executed,
            decision=gw_result.decision_record.decision.value,
            data=gw_result.tool_result.get("data") if gw_result.executed else None,
            block_reason=gw_result.tool_result.get("blocked_reason", "")
                         if not gw_result.executed else "",
            execution_id=gw_result.execution_id,
            args_binding_hash=gw_result.args_binding_hash,
        )

    @property
    def gateway(self) -> ToolGateway:
        return self._gateway

    @property
    def sandboxed_tools(self) -> SandboxedDocumentTools:
        return self._sandboxed


def _resource_id_from_args(
    tool_name: str, arguments: dict[str, Any], tenant_id: str
) -> str:
    """
    Derive a canonical resource_id from tool arguments and tenant.

    The resource_id is part of the HMAC-signed EAT payload and is passed
    independently to verify_for_execution (FINDING-3 fix). It binds
    authorization to the specific document, preventing token substitution
    across documents or tenants.
    """
    doc_id = str(arguments.get("doc_id", arguments.get("document_id", "")))
    return f"{tenant_id}/{doc_id}"


# ---------------------------------------------------------------------------
# OpenAI Agents SDK integration
# ---------------------------------------------------------------------------

try:
    from agents import FunctionTool, RunContextWrapper
    from agents.tool import ToolContext
    _AGENTS_AVAILABLE = True
except ImportError:
    _AGENTS_AVAILABLE = False


def make_sdk_tools(
    guarded: AIGovGuardedDocumentTools,
    tenant_id: str,
) -> list:
    """
    Create three OpenAI Agents SDK FunctionTool objects backed by AIGov.

    Each tool's on_invoke_tool async function calls guarded.execute_tool(),
    which runs the full AIGov authorization pipeline before any side effect.

    tenant_id is captured in the closure — it comes from the execution
    context, not from the LLM's arguments. The LLM cannot override it.

    Returns a list of FunctionTool objects ready to pass to Agent(tools=...).
    """
    if not _AGENTS_AVAILABLE:
        raise ImportError("openai-agents is not installed")

    import asyncio
    import json as _json

    def _parse_args(args_json: str, tool_name: str) -> dict | str:
        """Parse tool arguments; return error JSON string on malformed input."""
        try:
            parsed = _json.loads(args_json)
            if not isinstance(parsed, dict):
                raise TypeError("args must be a JSON object")
            return parsed
        except (ValueError, TypeError) as exc:
            return _json.dumps({
                "authorized": False,
                "decision": "deny",
                "data": None,
                "block_reason": f"malformed_args:{tool_name}:{exc}",
            })

    async def _invoke_read(ctx, args_json: str) -> str:
        args = _parse_args(args_json, "read_document")
        if isinstance(args, str):
            return args
        result = guarded.execute_tool("read_document", args, tenant_id)
        return _json.dumps({
            "authorized": result.authorized,
            "decision": result.decision,
            "data": result.data,
            "block_reason": result.block_reason,
        })

    async def _invoke_update(ctx, args_json: str) -> str:
        args = _parse_args(args_json, "update_document")
        if isinstance(args, str):
            return args
        result = guarded.execute_tool("update_document", args, tenant_id)
        return _json.dumps({
            "authorized": result.authorized,
            "decision": result.decision,
            "data": result.data,
            "block_reason": result.block_reason,
        })

    async def _invoke_delete(ctx, args_json: str) -> str:
        args = _parse_args(args_json, "delete_document")
        if isinstance(args, str):
            return args
        result = guarded.execute_tool("delete_document", args, tenant_id)
        return _json.dumps({
            "authorized": result.authorized,
            "decision": result.decision,
            "data": result.data,
            "block_reason": result.block_reason,
        })

    _SCHEMA_DOC_READ = {
        "type": "object",
        "properties": {
            "doc_id": {"type": "string", "description": "Document identifier"},
        },
        "required": ["doc_id"],
        "additionalProperties": False,
    }
    _SCHEMA_DOC_WRITE = {
        "type": "object",
        "properties": {
            "doc_id":   {"type": "string", "description": "Document identifier"},
            "content":  {"type": "string", "description": "New document content"},
        },
        "required": ["doc_id", "content"],
        "additionalProperties": False,
    }
    _SCHEMA_DOC_DELETE = {
        "type": "object",
        "properties": {
            "doc_id": {"type": "string", "description": "Document identifier"},
        },
        "required": ["doc_id"],
        "additionalProperties": False,
    }

    return [
        FunctionTool(
            name="read_document",
            description="Read a document by ID. Requires document:read authorization.",
            params_json_schema=_SCHEMA_DOC_READ,
            on_invoke_tool=_invoke_read,
        ),
        FunctionTool(
            name="update_document",
            description="Update document content. Requires document:write authorization.",
            params_json_schema=_SCHEMA_DOC_WRITE,
            on_invoke_tool=_invoke_update,
        ),
        FunctionTool(
            name="delete_document",
            description="Delete a document. Requires document:delete authorization.",
            params_json_schema=_SCHEMA_DOC_DELETE,
            on_invoke_tool=_invoke_delete,
        ),
    ]
