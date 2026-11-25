"""Customer integration interface for AIGov Core.

A customer describes its tools, approvers, and identities in an ``IntegrationConfig``, supplies a ``performer`` that
performs its real side effects, and then calls ``Integration`` for each consequential step. Core decides and signs. The
executor verifies the authorization itself before the performer runs. Nothing here changes Core.

This module composes the trusted-execution code of ``examples/agent-reference`` (actors, executor, policy builder,
identity generator) and the launcher of ``examples/customer-pilot``. It adds no new security logic. The guarantees are
those of the reference, documented in ``docs/customer-integration.md``.

Each ``Integration`` holds one client per credential. The agent client cannot approve, and the approver clients cannot
submit calls. The executor client records receipts and checks status only.
"""

from __future__ import annotations

import secrets
import sys
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parents[1]
REF_DIR = REPO_ROOT / "examples" / "agent-reference"
PILOT_DIR = REPO_ROOT / "examples" / "customer-pilot"
for _p in (REF_DIR, REF_DIR / "service", PILOT_DIR):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

import pilot_launch
from aigov_agent_reference.core_gate import CoreClient, CoreDecision
from aigov_agent_reference.core_policy import policy_document
from aigov_agent_reference.core_trusted import (
    AgentActor,
    ApproverActor,
    ExecutionOutcome,
    ExecutionStore,
    Executor,
    offline_evidence_checks,
    register_tool,
)
from trust_setup import build

Performer = Callable[[str, dict[str, Any], str], dict[str, Any]]
UNREACHABLE_URL = "http://127.0.0.1:9"  # a port nothing listens on, used to test fail-closed behaviour


@dataclass(frozen=True)
class Tool:
    """A customer tool. ``kind`` is ``read`` (no approval) or ``write`` (approval required)."""

    name: str
    action: str
    kind: str
    resource_key: str = "resource_id"


@dataclass(frozen=True)
class IntegrationConfig:
    tenant: str
    policy_id: str
    tools: tuple[Tool, ...]
    approvers: dict[
        str, str
    ]  # approver name -> identity; these identities are the allowlist
    agent_identity: str
    executor_identity: str
    approval_max_age_seconds: int = 30
    auth_ttl_seconds: int = 60

    def __post_init__(self) -> None:
        names = [t.name for t in self.tools]
        if len(names) != len(set(names)):
            raise ValueError("tool names must be unique")
        for t in self.tools:
            if t.kind not in ("read", "write"):
                raise ValueError(f"tool {t.name}: kind must be 'read' or 'write'")
        if not any(t.kind == "write" for t in self.tools):
            raise ValueError(
                "at least one write tool is needed; reads alone need no approval"
            )
        if not self.approvers:
            raise ValueError("at least one approver is needed for write tools")
        if self.agent_identity == self.executor_identity:
            raise ValueError("the agent and the executor must be different identities")
        if any(identity == self.agent_identity for identity in self.approvers.values()):
            raise ValueError("an approver identity cannot be the agent identity")

    def tool(self, name: str) -> Tool:
        for t in self.tools:
            if t.name == name:
                return t
        raise KeyError(
            f"unknown tool {name!r}; it is not in the policy, so Core refuses it"
        )

    def policy_document(self) -> dict[str, Any]:
        return policy_document(
            policy_id=self.policy_id,
            read_tools=[t.name for t in self.tools if t.kind == "read"],
            write_tools=[t.name for t in self.tools if t.kind == "write"],
            approvers=list(self.approvers.values()),
            approval_max_age_seconds=self.approval_max_age_seconds,
        )

    def register(self) -> None:
        """Register the tools with the trusted layer so argument digests and resource checks use them."""
        for t in self.tools:
            register_tool(t.name, t.action, t.resource_key)

    def generate(self, state_dir: Path) -> dict[str, Any]:
        """Per-run identities, keys, signed policy, and Core environment. Nothing is reused between runs."""
        self.register()
        return build(
            state_dir,
            approver_identities=self.approvers,
            document=self.policy_document(),
            tenant=self.tenant,
            agent_principal=self.agent_identity,
            executor_principal=self.executor_identity,
            executor_audience=self.executor_identity,
            auth_ttl_seconds=self.auth_ttl_seconds,
        )


class Integration:
    """One business process against one Core. Use one instance per run."""

    def __init__(
        self,
        config: IntegrationConfig,
        core_url: str,
        state: dict[str, Any],
        out_dir: Path,
        performer: Performer,
        *,
        run_id: str | None = None,
    ) -> None:
        self.config = config
        self.core_url = core_url
        self.state = state
        self._out_dir = out_dir
        self._performer = performer
        self.run_id = run_id or f"run-{uuid.uuid4().hex[:12]}"
        keys = state["keys"]
        self._core_for = lambda key: CoreClient(core_url, key)
        self.agent = AgentActor(self._core_for(keys["agent"]), self.run_id)
        self._approvers = {
            name: ApproverActor(self._core_for(keys[name]), identity)
            for name, identity in config.approvers.items()
        }
        self._executor_core = self._core_for(keys["executor"])
        out_dir.mkdir(parents=True, exist_ok=True)
        self.executor = Executor(
            core=self._executor_core,
            public_key_b64=state["authorization_public_key"],
            audience=config.executor_identity,
            store=ExecutionStore(out_dir / "executor.sqlite"),
            performer=performer,
        )

    def unreachable_view(self) -> Integration:
        """The same run, with Core unreachable. Used to test fail-closed behaviour."""
        return Integration(
            self.config,
            UNREACHABLE_URL,
            self.state,
            self._out_dir,
            self._performer,
            run_id=self.run_id,
        )

    # --- agent side -------------------------------------------------------------------------------------------------

    def request_approval(
        self, tool: str, args: dict[str, Any], call_id: str
    ) -> CoreDecision:
        """Record that the agent wants a write. Returns the request; a human then decides it."""
        self.config.tool(tool)
        return self.agent.request_approval(tool, args, call_id)

    def call(
        self, tool: str, args: dict[str, Any], call_id: str, approval_event_id: str = ""
    ) -> CoreDecision:
        """Submit a call. Reads need no approval. Writes need an approval event that Core accepts for this call."""
        spec = self.config.tool(tool)
        if spec.kind == "read":
            return self.agent.read(tool, args, call_id)
        return self.agent.submit_write(tool, args, call_id, approval_event_id)

    # --- human side ------------------------------------------------------------------------------------------------

    def approve(
        self,
        approver: str,
        request: CoreDecision,
        tool: str,
        args: dict[str, Any],
        call_id: str,
        *,
        approve: bool = True,
        claimed_approver: str | None = None,
    ) -> CoreDecision:
        """The named approver decides under its own credential. ``claimed_approver`` is for impersonation tests."""
        return self._approvers[approver].decide(
            run_id=self.run_id,
            request=request,
            tool=tool,
            args=args,
            tool_call_id=call_id,
            approve=approve,
            claimed_approver=claimed_approver,
        )

    def revoke(
        self, approver: str, approval_event_id: str, reason: str
    ) -> CoreDecision:
        return self._approvers[approver].revoke(
            run_id=self.run_id, approval_event_id=approval_event_id, reason=reason
        )

    # --- executor side ---------------------------------------------------------------------------------------------

    def execute(
        self, tool: str, args: dict[str, Any], decision: CoreDecision
    ) -> ExecutionOutcome:
        """Hand the executor Core's authorization. It verifies, reserves, performs once, and records a receipt."""
        return self.executor.execute(
            run_id=self.run_id,
            tool=tool,
            arguments=args,
            signed=decision.authorization or {},
        )

    def execute_with(
        self, tool: str, args: dict[str, Any], signed: dict[str, Any]
    ) -> ExecutionOutcome:
        """Execute with an explicit authorization. Used to test replay and modified arguments."""
        return self.executor.execute(
            run_id=self.run_id, tool=tool, arguments=args, signed=signed
        )

    # --- evidence --------------------------------------------------------------------------------------------------

    def export(self) -> dict[str, Any]:
        return self._executor_core.export(self.run_id)

    def verify(self, authorizations: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Core's chain check, plus offline checks that need only the export and the pinned public key."""
        ok, msg = self._executor_core.verify_run(self.run_id)
        checks = [{"name": "core_chain_verifies", "ok": ok, "detail": msg}]
        checks += offline_evidence_checks(
            self.export(),
            authorizations,
            self.state["authorization_public_key"],
            self.config.executor_identity,
            self.run_id,
        )
        return checks


def start_core(
    config: IntegrationConfig,
    state_dir: Path,
    *,
    port: int,
    mode: str = "docker",
    image: str = "aigov-core:integration",
    binary: Path | None = None,
    database_url: str | None = None,
) -> tuple[pilot_launch.Running, str]:
    """Start Core with this configuration's policy and identities. Returns the running Core and its resource prefix.

    Every resource name carries a prefix unique to this call, so ``stop_core`` removes only what this call created.
    """
    prefix = "aigov-int-" + secrets.token_hex(3)
    try:
        if mode == "docker":
            running = pilot_launch.start_docker(
                state_dir, port, image, prefix=prefix, generate=config.generate
            )
        elif mode == "binary":
            if binary is None or database_url is None:
                raise ValueError("binary mode needs binary and database_url")
            running = pilot_launch.start_binary(
                state_dir, port, binary, database_url, generate=config.generate
            )
        else:
            raise ValueError("mode must be 'docker' or 'binary'")
    except BaseException:
        # A failed start must not leave resources behind: the caller never receives the prefix.
        stop_core(state_dir, prefix)
        raise
    return running, prefix


def stop_core(state_dir: Path, prefix: str) -> list[str]:
    return pilot_launch.stop(state_dir, prefix=prefix)
