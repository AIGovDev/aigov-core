"""
Approval-level revocation list for Condition I.

Distinct from PolicyRecord.revoked (policy-level revocation at fixture time).
RevocationList handles runtime revocation: an approval is issued and valid,
but then revoked before it is consumed (e.g., approver's access is terminated
between issuance and execution).

Security invariants:
  - Revocation is tenant-scoped: same approval_id in different tenants
    is treated as independent.
  - Fail-closed: is_revoked() returns False only for explicitly known-not-revoked
    approvals. Unknown approvals are not revoked by default (open), but callers
    can wrap this in a closed-world assumption if the deployment requires it.
  - Thread-safe via threading.Lock.
"""

from __future__ import annotations

import hashlib
import json
import threading
import time
from dataclasses import dataclass, field
from typing import Any


@dataclass
class RevocationEntry:
    """A single revocation record."""
    approval_id: str
    tenant_id: str
    revoked_at: float      # Unix timestamp
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "approval_id": self.approval_id,
            "tenant_id": self.tenant_id,
            "revoked_at": self.revoked_at,
            "reason": self.reason,
        }


class RevocationList:
    """
    Independently maintained approval-level revocation state.

    Separate from PolicyRecord.revoked (which is a fixture-time policy flag).
    This list can be updated at runtime to revoke specific approval instances
    after they have been issued.

    Use cases:
      - Approver's account is compromised after they issued an approval
      - Approval was issued for a resource that has since been decommissioned
      - Security incident requiring invalidation of pending approvals
      - Testing revocation between approval-issuance and execution

    Thread-safe via threading.Lock.

    Note on fail-closed design:
      In production, this list would be backed by a persistent store with
      push-based invalidation. If the store is unreachable, the caller should
      treat the status as INDETERMINATE (not ALLOW). For this benchmark,
      the store is always available (in-memory).
    """

    def __init__(self) -> None:
        self._entries: dict[str, RevocationEntry] = {}
        self._lock = threading.Lock()

    def _key(self, approval_id: str, tenant_id: str) -> str:
        """Composite key for tenant-scoped lookup."""
        return json.dumps({"a": approval_id, "t": tenant_id}, sort_keys=True)

    def revoke(
        self,
        approval_id: str,
        tenant_id: str,
        reason: str,
        revoked_at: float | None = None,
    ) -> None:
        """
        Add an approval to the revocation list.

        Idempotent: revoking an already-revoked approval is a no-op
        (first revocation wins).
        """
        if revoked_at is None:
            revoked_at = time.time()
        key = self._key(approval_id, tenant_id)
        with self._lock:
            if key not in self._entries:
                self._entries[key] = RevocationEntry(
                    approval_id=approval_id,
                    tenant_id=tenant_id,
                    revoked_at=revoked_at,
                    reason=reason,
                )

    def is_revoked(self, approval_id: str, tenant_id: str) -> bool:
        """Return True if the approval has been explicitly revoked."""
        key = self._key(approval_id, tenant_id)
        with self._lock:
            return key in self._entries

    def get_revocation_entry(
        self, approval_id: str, tenant_id: str
    ) -> RevocationEntry | None:
        """Return the revocation entry if present, else None."""
        key = self._key(approval_id, tenant_id)
        with self._lock:
            return self._entries.get(key)

    def state_hash(self) -> str:
        """
        Deterministic SHA-256 hash of the current revocation state.

        Changes whenever an entry is added. Useful for detecting stale
        or divergent revocation state between replicas.
        """
        with self._lock:
            entries = sorted(self._entries.values(), key=lambda e: (e.tenant_id, e.approval_id))
        rows = [e.to_dict() for e in entries]
        canonical = json.dumps(rows, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode()).hexdigest()

    def entry_count(self) -> int:
        """Number of revoked approvals in this list."""
        with self._lock:
            return len(self._entries)
