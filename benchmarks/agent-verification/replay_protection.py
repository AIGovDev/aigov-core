"""
Replay protection for Condition I authorization.

ApprovalNonce binds an approval to its full execution context.
ReplayRegistry provides atomic, thread-safe check-and-consume semantics.

Security invariant:
  A nonce is considered consumed on first successful try_consume().
  Any subsequent try_consume() with the same composite key returns False.
  The registry is per-instance; benchmarks should create one per run.
"""

from __future__ import annotations

import hashlib
import json
import threading
from dataclasses import dataclass


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
    In-memory per-instance replay registry.

    Provides atomic check-and-consume semantics: try_consume() checks and
    marks a nonce as consumed in one operation under a mutex.

    Thread-safety: a threading.Lock guards all state mutations. Two concurrent
    try_consume() calls with the same nonce will result in exactly one True
    return and one False return.

    Lifecycle:
      - Create one registry per benchmark run (not per scenario) to catch
        cross-scenario replays.
      - Call reset() between runs when test isolation is needed.
    """

    def __init__(self) -> None:
        self._consumed: set[str] = set()
        self._lock = threading.Lock()

    def try_consume(self, nonce: ApprovalNonce) -> bool:
        """
        Atomically check and consume the nonce.

        Returns True if the nonce was not previously consumed (first use).
        Returns False if the nonce was already consumed (replay detected).
        Thread-safe.
        """
        key = nonce.as_string()
        with self._lock:
            if key in self._consumed:
                return False
            self._consumed.add(key)
            return True

    def is_consumed(self, nonce: ApprovalNonce) -> bool:
        """Check whether the nonce has been consumed, without consuming it."""
        key = nonce.as_string()
        with self._lock:
            return key in self._consumed

    def reset(self) -> None:
        """Clear all consumed nonces. Use for test isolation between runs."""
        with self._lock:
            self._consumed.clear()

    @property
    def consumed_count(self) -> int:
        """Number of consumed nonces in this registry."""
        with self._lock:
            return len(self._consumed)

    @property
    def is_distributed_safe(self) -> bool:
        """
        False. This registry uses threading.Lock and an in-memory set.

        Single-process atomicity is guaranteed: two threads calling try_consume()
        with the same nonce produce exactly one True and one False.

        Cross-process atomicity is NOT guaranteed: two separate processes each
        have their own registry. The same approval_id can be consumed by both
        processes simultaneously, and neither detects the replay.

        Production deployments MUST replace this with a persistent, distributed-
        atomic nonce store (e.g. Redis SETNX, PostgreSQL advisory lock, or a
        dedicated approval-service with transactional nonce consumption).
        """
        return False
