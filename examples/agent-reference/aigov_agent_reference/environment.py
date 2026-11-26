"""Wire one isolated environment: policy, approvals, replay, revocation, sandbox, and log.

Each scenario and each benchmark case gets its own environment, so no state leaks between
runs. Replay protection uses SQLite, so separate processes see the same consumed nonces.
"""

from __future__ import annotations

import tempfile
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from execution_token import ExecutionTokenAuthority
from key_provider import InMemoryKeyProvider
from nonce_store import SqlNonceStore
from replay_protection import ReplayRegistry
from revocation_list import RevocationList
from sandboxed_tools import SandboxedGitHubTools

from .approvals import ApprovalStore
from .decision_log import DecisionLog
from .gate import AgentGate
from .policy import ReferencePolicy, load_policy


@dataclass
class Environment:
    workdir: Path
    policy: ReferencePolicy
    approvals: ApprovalStore
    sandbox: SandboxedGitHubTools
    log: DecisionLog
    replay: ReplayRegistry
    revocation: RevocationList
    authority: ExecutionTokenAuthority
    gate: AgentGate
    clock: Clock


class Clock:
    """A settable clock so expiry scenarios do not sleep."""

    def __init__(self, start: float | None = None) -> None:
        self._now = time.time() if start is None else start

    def __call__(self) -> float:
        return self._now

    def advance(self, seconds: float) -> None:
        self._now += seconds


def build_environment(
    workdir: Path | None = None,
    *,
    enforce: bool = True,
    approval_ttl: float = 300.0,
) -> Environment:
    root = (
        Path(workdir)
        if workdir is not None
        else Path(tempfile.mkdtemp(prefix="aigov-ref-"))
    )
    root.mkdir(parents=True, exist_ok=True)
    clock = Clock()
    policy = load_policy(now=clock())
    approvals = ApprovalStore(str(root / "approvals.sqlite"), ttl_seconds=approval_ttl)
    # The reference process uses an unmanaged in-memory signing key. The benchmark warns
    # about that, and a production deployment would use a managed key (see the README).
    authority = ExecutionTokenAuthority(
        key_provider=InMemoryKeyProvider(key_id="reference-process", key_bytes=None)
    )
    sandbox = SandboxedGitHubTools(token_authority=authority)
    replay = ReplayRegistry(
        backend=SqlNonceStore("sqlite", path=str(root / "nonces.sqlite"))
    )
    revocation = RevocationList()
    log = DecisionLog(root / "decision_log.jsonl")
    gate = AgentGate(
        policy=policy,
        approvals=approvals,
        sandbox=sandbox,
        decision_log=log,
        replay=replay,
        revocation=revocation,
        token_authority=authority,
        enforce=enforce,
        clock=clock,
    )
    return Environment(
        workdir=root,
        policy=policy,
        approvals=approvals,
        sandbox=sandbox,
        log=log,
        replay=replay,
        revocation=revocation,
        authority=authority,
        gate=gate,
        clock=clock,
    )


def repo_state(env: Environment, repo_id: str) -> dict:
    """Read back the sandbox state for one repository (read-only inspection)."""
    key = (env.policy.tenant_id, repo_id)
    state = env.sandbox._repos.get(key)
    if state is None:
        return {"files": {}, "deployments": [], "pull_requests": [], "settings": {}}
    return {
        "files": {p: dict(v) for p, v in state["files"].items()},
        "deployments": list(state["deployments"]),
        "pull_requests": list(state["pull_requests"]),
        "settings": dict(state["settings"]),
    }


ClockFactory = Callable[[], float]
