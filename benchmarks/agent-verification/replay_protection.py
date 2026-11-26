"""
Replay protection for Condition I authorization.

ApprovalNonce binds an approval to its full execution context.
ReplayRegistry provides atomic, thread-safe check-and-consume semantics,
delegating to a pluggable NonceStore backend.

Default backend: InMemoryNonceStore — single-process only, for tests.
Production backend: SqlNonceStore("postgresql", dsn=...) — distributed-safe.

Usage:
    # Test (default)
    registry = ReplayRegistry()

    # Production (PostgreSQL)
    from nonce_store import SqlNonceStore
    store = SqlNonceStore("postgresql", dsn=os.environ["DATABASE_URL"])
    registry = ReplayRegistry(backend=store)
    gateway = ToolGateway(..., replay_registry=registry)

Security invariant:
  A nonce is considered consumed on first successful try_consume().
  Any subsequent try_consume() with the same composite key returns False.
  Distributed safety depends on the backend: check is_distributed_safe.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from nonce_store import InMemoryNonceStore, SqlNonceStore


@dataclass(frozen=True)
class ApprovalNonce:
    """
    Composite nonce binding an approval to its execution context.

    Five fields together form the unique key:
      approval_id    — specific approval being consumed
      tenant_id      — tenant context (cross-tenant replays differ here)
      action_type    — action being authorized
      resource_id    — resource being acted on
      proposal_id    — proposal this approval was issued for

    Rationale for each field:
      - approval_id alone is insufficient: same approval may be valid for
        different tenants/resources if the authorization model is misconfigured.
      - tenant_id prevents cross-tenant replays.
      - action_type + resource_id prevent scope-change replays.
      - proposal_id binds to the specific work item.
    """
    approval_id: str
    tenant_id: str
    action_type: str
    resource_id: str
    proposal_id: str

    def as_string(self) -> str:
        """Canonical deterministic string for the registry key."""
        fields = {
            "approval_id": self.approval_id,
            "tenant_id": self.tenant_id,
            "action_type": self.action_type,
            "resource_id": self.resource_id,
            "proposal_id": self.proposal_id,
        }
        canonical = json.dumps(fields, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode()).hexdigest()


class ReplayRegistry:
    """
    Approval-nonce registry backed by a pluggable NonceStore.

    The ConditionIOrchestrator calls try_consume(nonce: ApprovalNonce).
    The registry converts the nonce to its canonical string and delegates
    to the backend NonceStore.

    Default backend is InMemoryNonceStore (not distributed-safe; for tests).
    For production, inject a SqlNonceStore("postgresql", dsn=...) backend.

    Thread-safety: guaranteed by the backend.
    Distributed safety: reported by backend.is_distributed_safe.
    """

    def __init__(self, backend=None) -> None:  # backend: NonceStore | None
        if backend is None:
            from nonce_store import InMemoryNonceStore
            backend = InMemoryNonceStore()
        self._backend = backend

    def try_consume(self, nonce: ApprovalNonce) -> bool:
        """
        Atomically check and consume the nonce.

        Returns True if the nonce was not previously consumed (first use).
        Returns False if the nonce was already consumed (replay detected).
        Thread-safe (and cross-process safe if backend.is_distributed_safe).
        """
        return self._backend.try_consume(nonce.as_string())

    def is_consumed(self, nonce: ApprovalNonce) -> bool:
        """Check whether the nonce has been consumed, without consuming it."""
        return self._backend.is_consumed(nonce.as_string())

    def reset(self) -> None:
        """Clear all consumed nonces. Use for test isolation between runs."""
        self._backend.reset()

    @property
    def consumed_count(self) -> int:
        """Number of consumed nonces (may not be supported by all backends)."""
        count = getattr(self._backend, "consumed_count", None)
        if count is None:
            raise AttributeError(
                f"Backend {type(self._backend).__name__} does not expose consumed_count"
            )
        return count

    @property
    def is_distributed_safe(self) -> bool:
        """
        True iff the backend provides cross-process / cross-host atomicity.

        False means the same nonce can be consumed multiple times if two
        separate processes each have their own backend instance. Production
        deployments MUST use a SqlNonceStore("postgresql", ...) backend.
        """
        return self._backend.is_distributed_safe
