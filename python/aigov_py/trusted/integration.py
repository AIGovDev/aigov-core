"""The integration interface a customer application uses: configuration, one run, and the Core launcher.

A customer describes its tools, approvers, and identities in an ``IntegrationConfig``, supplies a ``performer`` that
performs its side effects, and calls ``Integration`` for each consequential step. Core decides and signs. The executor
verifies the authorization before the performer runs.

Nothing here changes Core. The configuration is validated when it is created, so an unsafe setting fails before any
Core is started.
"""

from __future__ import annotations

import secrets
import uuid
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .actors import AgentActor, ApproverActor
from .authorization import Refused
from .core import CoreClient, CoreDecision, Decision
from .evidence import offline_evidence_checks
from .executor import ExecutionOutcome, Executor, Performer
from .launch import Running, start_binary, start_docker, stop
from .policy import build_policy_document
from .provision import provision
from .store import ExecutionStore
from .tools import ToolSpec, tool_registry

Tool = ToolSpec
UNREACHABLE_URL = "http://127.0.0.1:9"  # a port nothing listens on, for tests of fail-closed behaviour
POLICY_EXPIRES_AT = "2999-01-01T00:00:00Z"


@dataclass(frozen=True)
class IntegrationConfig:
    """The customer's tools, approvers, and identities. Validated when created."""

    tenant: str
    policy_id: str
    tools: tuple[ToolSpec, ...]
    approvers: Mapping[
        str, str
    ]  # approver name -> identity; these identities form the policy allowlist
    agent_identity: str
    executor_identity: str
    # Approvers that hold a credential but are NOT on the allowlist. Core refuses their approvals, by policy. Used to
    # demonstrate that refusal; a customer normally leaves this empty.
    unlisted_approvers: Mapping[str, str] = field(default_factory=dict)
    approval_max_age_seconds: int = 30
    approval_max_skew_seconds: int = 60
    auth_ttl_seconds: int = 60
    policy_issuer_id: str = "aigov-integration"
    policy_issuer_display_name: str = "AIGov integration (per run)"
    policy_signer: str = "aigov-integration"

    def __post_init__(self) -> None:
        registry = tool_registry(self.tools)  # rejects duplicates and bad kinds
        if not any(t.kind == "write" for t in registry.values()):
            raise ValueError(
                "at least one write tool is needed; reads alone need no approval"
            )
        if not self.approvers:
            raise ValueError("at least one approver is needed for write tools")
        if not self.tenant or not self.policy_id:
            raise ValueError("tenant and policy_id must be non-empty")
        if self.agent_identity == self.executor_identity:
            raise ValueError("the agent and the executor must be different identities")
        if any(identity == self.agent_identity for identity in self.approvers.values()):
            raise ValueError("an approver identity cannot be the agent identity")
        everyone = {**self.approvers, **self.unlisted_approvers}
        if len(everyone) != len(self.approvers) + len(self.unlisted_approvers):
            raise ValueError(
                "approver names must be unique across the allowlist and the unlisted approvers"
            )
        if len(set(everyone.values())) != len(everyone):
            raise ValueError("each approver must have its own identity")
        if any(
            identity == self.agent_identity
            for identity in self.unlisted_approvers.values()
        ):
            raise ValueError("an approver identity cannot be the agent identity")
        if self.approval_max_age_seconds < 1:
            raise ValueError("approval_max_age_seconds must be at least 1")

    @property
    def registry(self) -> dict[str, ToolSpec]:
        return tool_registry(self.tools)

    def tool(self, name: str) -> ToolSpec:
        spec = self.registry.get(name)
        if spec is None:
            raise KeyError(
                f"unknown tool {name!r}; it is not in the policy, so Core refuses it"
            )
        return spec

    def policy_document(self) -> dict[str, Any]:
        reg = self.registry
        return build_policy_document(
            policy_id=self.policy_id,
            issuer_id=self.policy_issuer_id,
            issuer_display_name=self.policy_issuer_display_name,
            created_at_utc=_now_policy(),
            read_tools=[t.name for t in reg.values() if t.kind == "read"],
            write_tools=[t.name for t in reg.values() if t.kind == "write"],
            approvers=list(self.approvers.values()),
            approval_max_age_seconds=self.approval_max_age_seconds,
            approval_max_skew_seconds=self.approval_max_skew_seconds,
        )

    def generate(self, state_dir: Path) -> dict[str, Any]:
        """Per-run identities, keys, signed policy, and Core environment. Nothing is reused between runs."""
        return provision(
            state_dir,
            tenant=self.tenant,
            approvers=everyone_approvers(self),
            agent_identity=self.agent_identity,
            executor_identity=self.executor_identity,
            policy_document=self.policy_document(),
            policy_issuer_id=self.policy_issuer_id,
            policy_signer=self.policy_signer,
            policy_created_at_utc=_now_policy(),
            policy_expires_at_utc=POLICY_EXPIRES_AT,
            auth_ttl_seconds=self.auth_ttl_seconds,
        )


def everyone_approvers(config: IntegrationConfig) -> dict[str, str]:
    """Every approver that needs a credential: the allowlisted ones and the unlisted ones."""
    return {**config.approvers, **config.unlisted_approvers}


def _now_policy() -> str:
    from datetime import UTC, datetime

    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


class Integration:
    """One business process against one Core. Use one instance per run."""

    def __init__(
        self,
        config: IntegrationConfig,
        core_url: str,
        state: Mapping[str, Any],
        out_dir: Path,
        performer: Performer,
        *,
        run_id: str | None = None,
    ) -> None:
        self.config = config
        self.core_url = core_url
        self.state = dict(state)
        self.run_id = run_id or f"run-{uuid.uuid4().hex[:12]}"
        self._out_dir = Path(out_dir)
        self._performer = performer
        self._tools = config.registry
        keys = self.state["keys"]
        self.agent = AgentActor(
            self._client(keys["agent"], config.agent_identity), self.run_id, self._tools
        )
        self._approvers = {
            name: ApproverActor(
                self._client(keys[name], identity), identity, self._tools
            )
            for name, identity in {
                **config.approvers,
                **config.unlisted_approvers,
            }.items()
        }
        self._executor_core = self._client(keys["executor"], config.executor_identity)
        self._out_dir.mkdir(parents=True, exist_ok=True)
        self.executor = Executor(
            core=self._executor_core,
            public_key_b64=self.state["authorization_public_key"],
            audience=config.executor_identity,
            store=ExecutionStore(self._out_dir / "executor.sqlite"),
            tools=self._tools,
            performer=performer,
        )

    def _client(self, key: str, identity: str) -> CoreClient:
        return CoreClient(
            self.core_url, key, actor=identity, system="aigov-integration"
        )

    def unreachable_view(self) -> Integration:
        """The same run with Core unreachable, sharing the executor store. For tests of fail-closed behaviour."""
        return Integration(
            self.config,
            UNREACHABLE_URL,
            self.state,
            self._out_dir,
            self._performer,
            run_id=self.run_id,
        )

    # --- agent side ----------------------------------------------------------------------------------------------

    def request_approval(
        self, tool: str, args: dict[str, Any], call_id: str
    ) -> CoreDecision:
        """Record that the agent wants a write. A human then decides it."""
        self.config.tool(tool)
        return self.agent.request_approval(tool, args, call_id)

    def call(
        self, tool: str, args: dict[str, Any], call_id: str, approval_event_id: str = ""
    ) -> CoreDecision:
        """Submit a call. A read needs no approval. A write needs an approval event that Core accepts for this call."""
        spec = self.config.tool(tool)
        if spec.kind == "read":
            return self.agent.read(tool, args, call_id)
        return self.agent.submit_write(tool, args, call_id, approval_event_id)

    # --- human side ----------------------------------------------------------------------------------------------

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
        """The named approver decides under its own credential. ``claimed_approver`` exists for impersonation tests."""
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

    # --- executor side -------------------------------------------------------------------------------------------

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
        """Execute with an explicit authorization. For tests of replay and modified arguments."""
        return self.executor.execute(
            run_id=self.run_id, tool=tool, arguments=args, signed=signed
        )

    # --- evidence ------------------------------------------------------------------------------------------------

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
) -> tuple[Running, str]:
    """Start Core with this configuration's policy and identities. Returns the running Core and its resource prefix.

    The prefix is unique to this call, so ``stop_core`` removes only what this call created.
    """
    prefix = "aigov-int-" + secrets.token_hex(3)
    if mode == "docker":
        running = start_docker(
            state_dir, port, image, prefix=prefix, generate=config.generate
        )
    elif mode == "binary":
        if binary is None or database_url is None:
            raise ValueError("binary mode needs binary and database_url")
        running = start_binary(
            state_dir,
            port,
            binary,
            database_url,
            prefix=prefix,
            generate=config.generate,
        )
    else:
        raise ValueError("mode must be 'docker' or 'binary'")
    return running, prefix


def stop_core(state_dir: Path, prefix: str) -> list[str]:
    return stop(state_dir, prefix=prefix)


__all__ = [
    "Decision",
    "ExecutionOutcome",
    "Integration",
    "IntegrationConfig",
    "Refused",
    "Tool",
    "ToolSpec",
    "start_core",
    "stop_core",
]
