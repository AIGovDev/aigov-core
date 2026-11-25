"""The reference's trusted execution. The implementation is the SDK's (``aigov_py.trusted``).

This module adds only what the reference needs and the SDK does not provide:

- a process-wide tool registry (``register_tool``, ``TOOL_ACTIONS``), which the reference and its tests use, backed by
  the in-process benchmark's capability map;
- the in-process benchmark's sandboxed GitHub-style tools as the executor's default performer, with ``executor.sandbox``
  for the scenarios that inspect them.

Every security check runs in the SDK. Nothing here decides whether a call is authorized or verified.
"""

from __future__ import annotations

import sqlite3
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from aigov_py.trusted.actors import AgentActor as _SDKAgentActor
from aigov_py.trusted.actors import ApproverActor as _SDKApproverActor
from aigov_py.trusted.authorization import (
    AUTH_DOMAIN,
    AUTH_SCHEMA,
    CLOCK_SKEW_SECONDS,
    Refused,
    verify_authorization_signature,
)
from aigov_py.trusted.core import CoreClient, CoreDecision, Decision, new_event
from aigov_py.trusted.evidence import offline_evidence_checks
from aigov_py.trusted.executor import ExecutionOutcome, result_digest
from aigov_py.trusted.executor import Executor as _SDKExecutor
from aigov_py.trusted.provision import load_state
from aigov_py.trusted.store import ExecutionStore as _SDKExecutionStore
from aigov_py.trusted.store import executor_store_migration
from aigov_py.trusted.tools import ToolSpec, args_binding_hash

# The benchmark's modules are imported by name; the reference's tests and scripts put that directory on sys.path.
from execution_token import ExecutionTokenAuthority
from sandboxed_tools import SandboxedGitHubTools
from tool_gateway import TOOL_CAPABILITY_MAP

TENANT = "acme-corp"

# Process-wide registry for the reference. A deployment should pass explicit ``tools`` to the SDK instead.
TOOL_ACTIONS: dict[str, str] = dict(TOOL_CAPABILITY_MAP)
TOOL_RESOURCE_KEY: dict[str, str] = {}


def register_tool(tool: str, action: str, resource_key: str = "repo_id") -> None:
    """Register a tool, its action type, and the argument that names its resource."""
    TOOL_ACTIONS[tool] = action
    TOOL_RESOURCE_KEY[tool] = resource_key


def _spec(tool: str) -> ToolSpec:
    # The kind is not used by the actors or the executor, so the registry view is written as "write".
    return ToolSpec(
        tool, TOOL_ACTIONS[tool], "write", TOOL_RESOURCE_KEY.get(tool, "repo_id")
    )


def _registry_view() -> dict[str, ToolSpec]:
    return {tool: _spec(tool) for tool in TOOL_ACTIONS}


def resource_of(tool: str, arguments: dict[str, Any]) -> str:
    return str(arguments.get(TOOL_RESOURCE_KEY.get(tool, "repo_id"), ""))


def args_digest(tool: str, arguments: dict[str, Any]) -> str:
    """Argument digest used by approvals and authorizations. The SDK computes it; this uses the reference registry."""
    return args_binding_hash(_spec(tool), arguments)


class ExecutionStore(_SDKExecutionStore):
    """The SDK store. The reference applies its migration to its own files, which it may do because it is not shipped."""

    def __init__(self, path: Path) -> None:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(path) as conn:
            conn.executescript(executor_store_migration())
        super().__init__(path)


class AgentActor(_SDKAgentActor):
    """The SDK agent actor, with the reference registry as its default tools."""

    def __init__(
        self, core: CoreClient, run_id: str, tools: dict[str, ToolSpec] | None = None
    ) -> None:
        super().__init__(core, run_id, _registry_view() if tools is None else tools)


class ApproverActor(_SDKApproverActor):
    """The SDK approver actor, with the reference registry as its default tools."""

    def __init__(
        self, core: CoreClient, identity: str, tools: dict[str, ToolSpec] | None = None
    ) -> None:
        super().__init__(core, identity, _registry_view() if tools is None else tools)


def _sandbox_performer(
    sandbox: SandboxedGitHubTools, authority: ExecutionTokenAuthority
) -> Callable[[str, dict[str, Any], str], dict[str, Any]]:
    """The benchmark's side effect: issue an execution token for the sandbox, then execute."""

    def perform(
        tool: str, arguments: dict[str, Any], execution_id: str
    ) -> dict[str, Any]:
        digest = args_digest(tool, arguments)
        token = authority.issue(
            execution_id=execution_id,
            tool_name=tool,
            args_binding_hash=digest,
            action_type=TOOL_ACTIONS[tool],
            resource_id=resource_of(tool, arguments),
            tenant_id=TENANT,
        )
        return sandbox.execute(
            tool,
            arguments,
            execution_id=token.execution_id,
            tenant_id=TENANT,
            args_binding_hash=digest,
            execution_token=token,
            decision_label="executor_verified",
            expected_action_type=TOOL_ACTIONS[tool],
            expected_resource_id=resource_of(tool, arguments),
        )

    return perform


class Executor(_SDKExecutor):
    """The SDK executor. Without a performer, it performs against the in-process benchmark's sandbox."""

    def __init__(
        self,
        *,
        core: CoreClient,
        public_key_b64: str,
        audience: str,
        store: ExecutionStore,
        clock: Callable[[], float] = time.time,
        performer: Callable[[str, dict[str, Any], str], dict[str, Any]] | None = None,
    ) -> None:
        self._authority = ExecutionTokenAuthority()
        self._sandbox = SandboxedGitHubTools(token_authority=self._authority)
        super().__init__(
            core=core,
            public_key_b64=public_key_b64,
            audience=audience,
            store=store,
            tools=_registry_view(),
            performer=performer
            if performer is not None
            else _sandbox_performer(self._sandbox, self._authority),
            clock=clock,
        )

    @property
    def sandbox(self) -> SandboxedGitHubTools:
        return self._sandbox


__all__ = [
    "AUTH_DOMAIN",
    "AUTH_SCHEMA",
    "CLOCK_SKEW_SECONDS",
    "TENANT",
    "TOOL_ACTIONS",
    "TOOL_RESOURCE_KEY",
    "AgentActor",
    "ApproverActor",
    "CoreClient",
    "CoreDecision",
    "Decision",
    "ExecutionOutcome",
    "ExecutionStore",
    "Executor",
    "Refused",
    "args_digest",
    "load_state",
    "new_event",
    "offline_evidence_checks",
    "register_tool",
    "resource_of",
    "result_digest",
    "verify_authorization_signature",
]
