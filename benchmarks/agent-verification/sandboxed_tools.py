"""
Sandboxed tool implementations for agent-tool integration testing.

Two executor types:
  SandboxedDVOExecutor   — drives ConditionIOrchestrator's three DVO checks
                           (check_audit_record, verify_approval, read_external_state)
                           from scenario-defined state.
  SandboxedGitHubTools   — the actual GitHub-like operations an agent can request.
                           Tracks every execution attempt with a unique execution_id.

Security design note:
  SandboxedDVOExecutor is NOT the same as SandboxedGitHubTools. The DVO layer
  verifies the authorization context (audit records, approvals) independently of
  the tool that the agent wants to execute. ToolGateway wires both together.

Authorization design note:
  SandboxedGitHubTools.execute() requires a valid ExecutionToken issued by the
  gateway's ExecutionTokenAuthority. This prevents direct invocation bypass:
  code that calls execute() without going through ToolGateway cannot produce a
  token that verifies against the authority held by the tools object.
"""

from __future__ import annotations

import hashlib
import json
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from execution_token import ExecutionToken, ExecutionTokenAuthority

# ---------------------------------------------------------------------------
# DVO sandbox — drives ConditionIOrchestrator's evidence checks
# ---------------------------------------------------------------------------


@dataclass
class DVOScenarioState:
    """
    Per-scenario state for the three DVO tool checks.

    The gateway creates one of these per ToolRequest and passes it
    to SandboxedDVOExecutor so the orchestrator gets the scenario's
    pre-configured evidence values.
    """
    proposal_id: str
    approval_id: str
    record_id: str
    approver_email: str

    # check_audit_record returns
    audit_found: bool
    audit_hash_verified: bool
    audit_executed_value: str | None

    # verify_approval returns
    approval_active: bool
    approval_matches_proposal: bool  # approval_id references this proposal

    # read_external_state returns
    external_state_value: str | None


class SandboxedDVOExecutor:
    """
    SandboxToolExecutor-compatible executor backed by DVOScenarioState.

    Implements the interface expected by ConditionIOrchestrator:
      execute("check_audit_record", {"proposal_id": ...})
      execute("verify_approval", {"proposal_id": ..., "approval_id": ...})
      execute("read_external_state", {"record_id": ..., "field": ...})
    """

    def __init__(self, state: DVOScenarioState) -> None:
        self._state = state

    def execute(self, tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        if tool_name == "check_audit_record":
            return self._check_audit_record(arguments)
        elif tool_name == "verify_approval":
            return self._verify_approval(arguments)
        elif tool_name == "read_external_state":
            return self._read_external_state(arguments)
        else:
            return {"error": f"unknown_tool:{tool_name}"}

    def _check_audit_record(self, args: dict[str, Any]) -> dict[str, Any]:
        proposal_id = args.get("proposal_id", "")
        if proposal_id != self._state.proposal_id:
            return {"found": False, "hash_verified": False, "executed_value": None}
        return {
            "found": self._state.audit_found,
            "hash_verified": self._state.audit_hash_verified,
            "executed_value": self._state.audit_executed_value,
        }

    def _verify_approval(self, args: dict[str, Any]) -> dict[str, Any]:
        proposal_id = args.get("proposal_id", "")
        approval_id = args.get("approval_id", "")

        if proposal_id != self._state.proposal_id:
            return {"valid": False, "approver": "", "reason": "proposal_id_mismatch"}

        if approval_id != self._state.approval_id:
            return {"valid": False, "approver": "", "reason": "approval_id_not_found"}

        if not self._state.approval_matches_proposal:
            return {"valid": False, "approver": self._state.approver_email,
                    "reason": "approval_does_not_match_proposal"}

        if not self._state.approval_active:
            return {"valid": False, "approver": self._state.approver_email,
                    "reason": "approval_expired_or_inactive"}

        return {"valid": True, "approver": self._state.approver_email, "reason": "valid"}

    def _read_external_state(self, args: dict[str, Any]) -> dict[str, Any]:
        record_id = args.get("record_id", "")
        if record_id != self._state.record_id:
            return {"value": None}
        return {"value": self._state.external_state_value}


# ---------------------------------------------------------------------------
# Sandboxed GitHub-like tools — what the agent actually wants to execute
# ---------------------------------------------------------------------------


@dataclass
class ToolExecutionRecord:
    """Immutable record of one tool execution attempt (authorized or blocked)."""
    execution_id: str
    tool_name: str
    arguments: dict[str, Any]
    authorized: bool        # True iff ExecutionToken verified; False for all blocked attempts
    token_verified: bool    # mirrors authorized; explicit field for audit clarity
    decision: str           # ALLOW / DENY / INDETERMINATE / REQUIRES_REVIEW / blocked_no_token
    tenant_id: str
    args_binding_hash: str
    executed_at: float
    block_reason: str = ""  # populated when authorized=False; empty on success


class SandboxedGitHubTools:
    """
    In-memory simulation of GitHub repository operations.

    All writes are in-memory only — no real GitHub API calls.

    Tracks every execution attempt with a unique execution_id so the
    evaluation can verify that unauthorized operations never actually ran.

    Thread-safe: a lock serializes all state mutations.

    Authorization model:
      execute() requires a valid ExecutionToken from this tools object's
      token_authority. Code that calls execute() without a valid token
      (including code that bypasses ToolGateway entirely) cannot produce
      a token that verifies, and the call is treated as blocked.
    """

    SUPPORTED_TOOLS = frozenset({
        "read_repo_metadata",
        "create_file",
        "open_pull_request",
        "modify_repo_settings",
        "request_deployment",
    })

    def __init__(
        self,
        token_authority: "ExecutionTokenAuthority | None" = None,
        audit_store: "Any | None" = None,
    ) -> None:
        self._lock = threading.Lock()
        self._token_authority: ExecutionTokenAuthority | None = token_authority
        self._audit_store = audit_store  # SqlAuditStore | None; optional persistent audit
        # Repo state keyed by (tenant_id, repo_id)
        self._repos: dict[tuple[str, str], dict[str, Any]] = {}
        # Execution history — includes both authorized executions and blocked attempts
        self._history: list[ToolExecutionRecord] = []

    def execute(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        execution_id: str,
        tenant_id: str,
        args_binding_hash: str,
        execution_token: "ExecutionToken | None" = None,
        # Caller-supplied decision label for audit trail (e.g. "deny", "indeterminate")
        # Ignored when deciding whether to execute; only the token governs that.
        decision_label: str = "",
    ) -> dict[str, Any]:
        """
        Execute a tool operation.

        Authorization is determined by verifying execution_token against
        this instance's token_authority. The caller-supplied boolean
        is NOT trusted. Only a token issued by the same authority as this
        tools object was constructed with authorizes actual execution.

        ONLY actually performs the operation when the token is present and
        verifies. Always records the attempt to history regardless of outcome.

        Returns:
          {"success": bool, "execution_id": str, "data": ..., "blocked_reason": str|None}
        """
        from execution_token import ExecutionToken, ExecutionTokenAuthority  # avoid circular

        # Determine authorization via token verification, NOT from a caller-supplied bool
        authorized = False
        block_reason = "no_execution_token"

        if execution_token is not None and self._token_authority is not None:
            ok, reason = self._token_authority.verify_for_execution(
                token=execution_token,
                expected_tool_name=tool_name,
                expected_args_binding_hash=args_binding_hash,
                expected_action_type=execution_token.action_type,
                expected_resource_id=execution_token.resource_id,
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
        # else: execution_token is None → "no_execution_token"

        effective_decision = decision_label if decision_label else ("allow" if authorized else "blocked_no_valid_token")

        record = ToolExecutionRecord(
            execution_id=execution_id,
            tool_name=tool_name,
            arguments=arguments,
            authorized=authorized,
            token_verified=authorized,
            decision=effective_decision,
            tenant_id=tenant_id,
            args_binding_hash=args_binding_hash,
            executed_at=time.time(),
            block_reason=block_reason,
        )
        with self._lock:
            self._history.append(record)
            # Write to persistent audit store if configured.
            # This commit is SEPARATE from the nonce-consumption commit.
            # See sql_audit_store.py module docstring for the atomicity gap.
            if self._audit_store is not None:
                key_id = execution_token.key_id if execution_token is not None else None
                self._audit_store.record(
                    execution_id=execution_id,
                    tenant_id=tenant_id,
                    tool_name=tool_name,
                    action_type=execution_token.action_type if execution_token else "",
                    resource_id=execution_token.resource_id if execution_token else "",
                    args_binding_hash=args_binding_hash,
                    key_id=key_id,
                    decision=effective_decision,
                    authorized=authorized,
                    block_reason=block_reason or None,
                )

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

            dispatch = {
                "read_repo_metadata": self._read_repo_metadata,
                "create_file": self._create_file,
                "open_pull_request": self._open_pull_request,
                "modify_repo_settings": self._modify_repo_settings,
                "request_deployment": self._request_deployment,
            }
            result = dispatch[tool_name](arguments, tenant_id, execution_id)
            return {"success": True, "execution_id": execution_id, "data": result,
                    "blocked_reason": None}

    def _repo_key(self, arguments: dict[str, Any], tenant_id: str) -> tuple[str, str]:
        repo_id = arguments.get("repo_id", "unknown")
        return (tenant_id, repo_id)

    def _ensure_repo(self, key: tuple[str, str]) -> None:
        if key not in self._repos:
            self._repos[key] = {
                "files": {},
                "pull_requests": [],
                "settings": {"visibility": "private", "branch_protection": True},
                "deployments": [],
            }

    def _read_repo_metadata(
        self, args: dict[str, Any], tenant_id: str, execution_id: str
    ) -> dict[str, Any]:
        key = self._repo_key(args, tenant_id)
        self._ensure_repo(key)
        repo = self._repos[key]
        return {
            "repo_id": args.get("repo_id"),
            "tenant_id": tenant_id,
            "file_count": len(repo["files"]),
            "pr_count": len(repo["pull_requests"]),
            "settings": dict(repo["settings"]),
            "execution_id": execution_id,
        }

    def _create_file(
        self, args: dict[str, Any], tenant_id: str, execution_id: str
    ) -> dict[str, Any]:
        key = self._repo_key(args, tenant_id)
        self._ensure_repo(key)
        path = args.get("path", "unnamed")
        content = args.get("content", "")
        self._repos[key]["files"][path] = {
            "content": content,
            "created_at": time.time(),
            "execution_id": execution_id,
        }
        return {"created_path": path, "execution_id": execution_id}

    def _open_pull_request(
        self, args: dict[str, Any], tenant_id: str, execution_id: str
    ) -> dict[str, Any]:
        key = self._repo_key(args, tenant_id)
        self._ensure_repo(key)
        pr = {
            "pr_number": len(self._repos[key]["pull_requests"]) + 1,
            "title": args.get("title", ""),
            "description": args.get("description", ""),
            "base": args.get("base", "main"),
            "head": args.get("head", "feature"),
            "created_at": time.time(),
            "execution_id": execution_id,
        }
        self._repos[key]["pull_requests"].append(pr)
        return {"pr_number": pr["pr_number"], "execution_id": execution_id}

    def _modify_repo_settings(
        self, args: dict[str, Any], tenant_id: str, execution_id: str
    ) -> dict[str, Any]:
        key = self._repo_key(args, tenant_id)
        self._ensure_repo(key)
        setting_key = args.get("setting_key", "")
        value = args.get("value")
        self._repos[key]["settings"][setting_key] = value
        return {"setting_key": setting_key, "new_value": value, "execution_id": execution_id}

    def _request_deployment(
        self, args: dict[str, Any], tenant_id: str, execution_id: str
    ) -> dict[str, Any]:
        key = self._repo_key(args, tenant_id)
        self._ensure_repo(key)
        deployment = {
            "deployment_id": f"deploy-{execution_id[:8]}",
            "repo_id": args.get("repo_id"),
            "environment": args.get("environment", "staging"),
            "requested_at": time.time(),
            "execution_id": execution_id,
        }
        self._repos[key]["deployments"].append(deployment)
        return {"deployment_id": deployment["deployment_id"], "execution_id": execution_id}

    # --- Inspection (for evaluation only) ---

    def execution_history(self) -> list[ToolExecutionRecord]:
        with self._lock:
            return list(self._history)

    def authorized_executions(self) -> list[ToolExecutionRecord]:
        with self._lock:
            return [r for r in self._history if r.authorized]

    def blocked_executions(self) -> list[ToolExecutionRecord]:
        with self._lock:
            return [r for r in self._history if not r.authorized]

    def reset(self) -> None:
        with self._lock:
            self._repos.clear()
            self._history.clear()


# ---------------------------------------------------------------------------
# Canonical args binding hash
# ---------------------------------------------------------------------------


def compute_args_binding_hash(tool_name: str, arguments: dict[str, Any],
                               action_type: str, resource_id: str) -> str:
    """
    SHA-256 hash binding (tool_name, arguments, action_type, resource_id).

    Included in the authorization trace. Any change to these fields after
    authorization is granted would produce a different hash, breaking the
    binding chain.

    action_type and resource_id are included so that an agent cannot
    re-use a binding hash by changing only the capability or resource target.
    """
    payload = json.dumps({
        "tool_name": tool_name,
        "arguments": arguments,
        "action_type": action_type,
        "resource_id": resource_id,
    }, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode()).hexdigest()
