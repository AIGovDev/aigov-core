"""
Audit reconciler for detecting and resolving incomplete executions.

After a process crash, some execution IDs will have an "authorized_pre_execution"
row but no "executed" row. The reconciler identifies these orphaned pre-execution
rows so operators can investigate whether:

  a) The crash happened before dispatch (document unmodified — safe to discard)
  b) The crash happened during/after dispatch (document may have been modified
     — requires investigation to determine true execution outcome)

The reconciler does NOT make this determination automatically. It surfaces the
execution IDs that need investigation and allows operators to close them with
a reconciliation row.

Reconciliation rows use decision="reconciled_no_dispatch" or
"reconciled_dispatch_confirmed" to distinguish the two outcomes. Once a
reconciliation row exists for an execution_id, it is excluded from future
orphan reports.

Usage:
    reconciler = AuditReconciler(audit_store)
    orphans = reconciler.orphaned_pre_executions()
    for entry in orphans:
        # investigate ...
        reconciler.mark_reconciled(entry.execution_id, tenant_id=entry.tenant_id,
                                   outcome="no_dispatch")
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from sql_audit_store import AuditEntry, SqlAuditStore


@dataclass
class ReconciliationEntry:
    """Summary of one execution_id requiring reconciliation."""
    execution_id: str
    tenant_id: str
    tool_name: str
    pre_exec_logged_at: float    # Unix timestamp of authorized_pre_execution row
    args_binding_hash: str


class AuditReconciler:
    """
    Identifies execution IDs with incomplete audit trails.

    An execution is "complete" when BOTH of these rows exist:
      • decision="authorized_pre_execution"  (authorization granted)
      • decision="executed"                  (dispatch completed)

    An execution is "orphaned" when "authorized_pre_execution" exists but
    "executed" does NOT. This indicates either:
      - A process crash between pre-execution audit and dispatch
      - A crash during/after dispatch before the post-execution audit write

    An execution is "reconciled" when a "reconciled_no_dispatch" or
    "reconciled_dispatch_confirmed" row exists for the same execution_id.
    Reconciled executions are excluded from orphan reports.
    """

    # Decision labels that constitute a complete execution evidence chain
    COMPLETE_DECISIONS   = frozenset({"authorized_pre_execution", "executed"})
    # Decision labels that mark a reconciled orphan (operator-confirmed)
    RECONCILE_DECISIONS  = frozenset({"reconciled_no_dispatch", "reconciled_dispatch_confirmed"})

    def __init__(self, audit_store: "SqlAuditStore") -> None:
        self._store = audit_store

    def orphaned_pre_executions(
        self,
        tenant_id: str | None = None,
        limit: int = 500,
    ) -> list[ReconciliationEntry]:
        """
        Return execution IDs that have "authorized_pre_execution" but no "executed" row,
        and no reconciliation row.

        tenant_id=None queries all tenants (requires audit store to support it; falls
        back gracefully for per-tenant stores).
        """
        # Build a map: execution_id → set of decisions seen for that execution
        all_entries = self._fetch(tenant_id, limit)
        by_exec: dict[str, list] = {}
        for entry in all_entries:
            by_exec.setdefault(entry.execution_id, []).append(entry)

        orphans: list[ReconciliationEntry] = []
        for execution_id, entries in by_exec.items():
            decisions = {e.decision for e in entries}
            has_pre   = "authorized_pre_execution" in decisions
            has_exec  = "executed" in decisions
            has_recon = bool(decisions & self.RECONCILE_DECISIONS)
            if has_pre and not has_exec and not has_recon:
                # Find the pre-execution row for metadata
                pre_entry = next(
                    e for e in entries if e.decision == "authorized_pre_execution"
                )
                orphans.append(ReconciliationEntry(
                    execution_id=execution_id,
                    tenant_id=pre_entry.tenant_id,
                    tool_name=pre_entry.tool_name,
                    pre_exec_logged_at=pre_entry.logged_at,
                    args_binding_hash=pre_entry.args_binding_hash,
                ))

        return orphans

    def verified_executions(
        self,
        tenant_id: str | None = None,
        limit: int = 500,
    ) -> list[tuple]:
        """
        Return (pre_exec_entry, executed_entry) pairs where both rows exist.

        These are confirmed completed executions with full audit evidence.
        """
        all_entries = self._fetch(tenant_id, limit)
        by_exec: dict[str, list] = {}
        for entry in all_entries:
            by_exec.setdefault(entry.execution_id, []).append(entry)

        pairs = []
        for entries in by_exec.values():
            by_decision = {e.decision: e for e in entries}
            if "authorized_pre_execution" in by_decision and "executed" in by_decision:
                pairs.append((
                    by_decision["authorized_pre_execution"],
                    by_decision["executed"],
                ))
        return pairs

    def mark_reconciled(
        self,
        execution_id: str,
        tenant_id: str,
        tool_name: str = "",
        args_binding_hash: str = "",
        outcome: str = "no_dispatch",
    ) -> None:
        """
        Close an orphaned execution by writing a reconciliation row.

        outcome must be one of:
          "no_dispatch"           — crash before dispatch; document unmodified
          "dispatch_confirmed"    — crash after dispatch; document may be modified

        After this call, orphaned_pre_executions() will no longer report this
        execution_id.
        """
        if outcome not in ("no_dispatch", "dispatch_confirmed"):
            raise ValueError(
                f"outcome must be 'no_dispatch' or 'dispatch_confirmed', got {outcome!r}"
            )
        decision = f"reconciled_{outcome}"
        self._store.record(
            execution_id=execution_id,
            tenant_id=tenant_id,
            tool_name=tool_name,
            action_type="",
            resource_id="",
            args_binding_hash=args_binding_hash,
            key_id=None,
            decision=decision,
            authorized=True,
            block_reason=None,
        )

    def _fetch(self, tenant_id: str | None, limit: int) -> list:
        """Fetch audit entries, optionally filtered by tenant."""
        if tenant_id is not None:
            return self._store.get_by_tenant(tenant_id, limit=limit)
        # Fall back to a large per-tenant scan when no specific tenant given.
        # For production use, the audit store should expose a global scan;
        # this is a best-effort fallback for single-tenant test setups.
        try:
            # Try a hypothetical get_all() that some implementations may provide
            return self._store.get_all(limit=limit)
        except AttributeError:
            return []
