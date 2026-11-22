"""
Persistent, transaction-safe approval registry for the AIGov OpenAI Agents SDK integration.

Replaces the in-memory ApprovalRegistry with a SQLite or PostgreSQL-backed store
that survives process restarts and prevents concurrent replay across threads and
processes.

Atomic single-use consumption
==============================
Consumption uses an UPDATE … WHERE consumed_at IS NULL that touches exactly one
row. The UPDATE is atomic under SQLite WAL (file-level locking) and PostgreSQL
row-level locking. Two concurrent calls competing for the same approval_id are
serialised by the database; exactly one wins (rowcount == 1); the other gets
rowcount == 0 and raises ApprovalNotFound.

Schema
======
aigov_sdk_approvals
  approval_id      TEXT PRIMARY KEY   — unique per registered approval
  tool_name        TEXT NOT NULL
  action_type      TEXT NOT NULL
  resource_id      TEXT NOT NULL
  tenant_id        TEXT NOT NULL
  proposal_id      TEXT NOT NULL
  record_id        TEXT NOT NULL
  approver_email   TEXT NOT NULL
  — DVO evidence (passed to ConditionIOrchestrator as DVOScenarioState)
  audit_found               INTEGER NOT NULL DEFAULT 1
  audit_hash_verified       INTEGER NOT NULL DEFAULT 1
  audit_executed_value      TEXT
  approval_active           INTEGER NOT NULL DEFAULT 1
  approval_matches_proposal INTEGER NOT NULL DEFAULT 1
  external_state_value      TEXT DEFAULT 'approved'
  — lifecycle
  registered_at    REAL    NOT NULL   — Unix timestamp
  consumed_at      REAL               — NULL until consumed; set atomically
  consumed_by_pid  INTEGER            — OS PID that consumed (diagnostic)

Durability gap (documented)
============================
The same atomicity gap documented in sql_audit_store.py applies here: approval
consumption (this table's UPDATE) and the subsequent audit-log INSERT commit
in separate transactions. If the process crashes between them, the approval is
consumed but no audit row exists. This is the same trade-off as the existing
nonce store. See sql_audit_store.py for the full explanation.
"""

from __future__ import annotations

import os
import sqlite3
import threading
import time
import uuid
from dataclasses import dataclass
from typing import Literal

import sys
from pathlib import Path

_BENCH = Path(__file__).parent.parent.parent / "agent-verification"
sys.path.insert(0, str(_BENCH))

from approval_registry import ApprovalNotFound  # re-exported; both registries raise this
from sandboxed_tools import DVOScenarioState


class ApprovalRegistryError(Exception):
    """Unrecoverable I/O error from the backing store."""


@dataclass
class ApprovalEntry:
    proposal_id: str
    approval_id: str
    record_id: str
    approver_email: str
    audit_found: bool = True
    audit_hash_verified: bool = True
    audit_executed_value: str | None = None
    approval_active: bool = True
    approval_matches_proposal: bool = True
    external_state_value: str | None = "approved"


# ---------------------------------------------------------------------------
# SQL schema and queries
# ---------------------------------------------------------------------------

_SQLITE_CREATE = """
    CREATE TABLE IF NOT EXISTS aigov_sdk_approvals (
        approval_id               TEXT    PRIMARY KEY,
        tool_name                 TEXT    NOT NULL,
        action_type               TEXT    NOT NULL,
        resource_id               TEXT    NOT NULL,
        tenant_id                 TEXT    NOT NULL,
        proposal_id               TEXT    NOT NULL,
        record_id                 TEXT    NOT NULL,
        approver_email            TEXT    NOT NULL,
        audit_found               INTEGER NOT NULL DEFAULT 1,
        audit_hash_verified       INTEGER NOT NULL DEFAULT 1,
        audit_executed_value      TEXT,
        approval_active           INTEGER NOT NULL DEFAULT 1,
        approval_matches_proposal INTEGER NOT NULL DEFAULT 1,
        external_state_value      TEXT    DEFAULT 'approved',
        registered_at             REAL    NOT NULL,
        consumed_at               REAL,
        consumed_by_pid           INTEGER
    )
"""
_SQLITE_IDX1 = (
    "CREATE INDEX IF NOT EXISTS aigov_sdk_approvals_key "
    "ON aigov_sdk_approvals(tool_name, action_type, resource_id, tenant_id, consumed_at)"
)
_SQLITE_INSERT = """
    INSERT INTO aigov_sdk_approvals
        (approval_id, tool_name, action_type, resource_id, tenant_id,
         proposal_id, record_id, approver_email,
         audit_found, audit_hash_verified, audit_executed_value,
         approval_active, approval_matches_proposal, external_state_value,
         registered_at)
    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
"""
# Find the oldest unconsumed approval for the key; use rowid for determinism.
_SQLITE_FIND = """
    SELECT approval_id, proposal_id, record_id, approver_email,
           audit_found, audit_hash_verified, audit_executed_value,
           approval_active, approval_matches_proposal, external_state_value
    FROM aigov_sdk_approvals
    WHERE tool_name   = ?
      AND action_type = ?
      AND resource_id = ?
      AND tenant_id   = ?
      AND consumed_at IS NULL
    ORDER BY registered_at ASC
    LIMIT 1
"""
_SQLITE_CONSUME = """
    UPDATE aigov_sdk_approvals
    SET consumed_at = ?, consumed_by_pid = ?
    WHERE approval_id = ? AND consumed_at IS NULL
"""
_SQLITE_PENDING = """
    SELECT COUNT(*) FROM aigov_sdk_approvals
    WHERE tool_name=? AND action_type=? AND resource_id=? AND tenant_id=? AND consumed_at IS NULL
"""
_SQLITE_PENDING_ALL = "SELECT COUNT(*) FROM aigov_sdk_approvals WHERE consumed_at IS NULL"
_SQLITE_CONSUMED_ALL = "SELECT COUNT(*) FROM aigov_sdk_approvals WHERE consumed_at IS NOT NULL"
_SQLITE_DELETE_ALL = "DELETE FROM aigov_sdk_approvals"

_PG_CREATE = """
    CREATE TABLE IF NOT EXISTS aigov_sdk_approvals (
        approval_id               TEXT         PRIMARY KEY,
        tool_name                 TEXT         NOT NULL,
        action_type               TEXT         NOT NULL,
        resource_id               TEXT         NOT NULL,
        tenant_id                 TEXT         NOT NULL,
        proposal_id               TEXT         NOT NULL,
        record_id                 TEXT         NOT NULL,
        approver_email            TEXT         NOT NULL,
        audit_found               BOOLEAN      NOT NULL DEFAULT TRUE,
        audit_hash_verified       BOOLEAN      NOT NULL DEFAULT TRUE,
        audit_executed_value      TEXT,
        approval_active           BOOLEAN      NOT NULL DEFAULT TRUE,
        approval_matches_proposal BOOLEAN      NOT NULL DEFAULT TRUE,
        external_state_value      TEXT         DEFAULT 'approved',
        registered_at             TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
        consumed_at               TIMESTAMPTZ,
        consumed_by_pid           INTEGER
    )
"""
_PG_IDX1 = (
    "CREATE INDEX IF NOT EXISTS aigov_sdk_approvals_key "
    "ON aigov_sdk_approvals(tool_name, action_type, resource_id, tenant_id, consumed_at)"
)
_PG_INSERT = """
    INSERT INTO aigov_sdk_approvals
        (approval_id, tool_name, action_type, resource_id, tenant_id,
         proposal_id, record_id, approver_email,
         audit_found, audit_hash_verified, audit_executed_value,
         approval_active, approval_matches_proposal, external_state_value)
    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
"""
_PG_FIND = """
    SELECT approval_id, proposal_id, record_id, approver_email,
           audit_found, audit_hash_verified, audit_executed_value,
           approval_active, approval_matches_proposal, external_state_value
    FROM aigov_sdk_approvals
    WHERE tool_name   = %s
      AND action_type = %s
      AND resource_id = %s
      AND tenant_id   = %s
      AND consumed_at IS NULL
    ORDER BY registered_at ASC
    LIMIT 1
    FOR UPDATE SKIP LOCKED
"""
_PG_CONSUME = """
    UPDATE aigov_sdk_approvals
    SET consumed_at = NOW(), consumed_by_pid = %s
    WHERE approval_id = %s AND consumed_at IS NULL
"""
_PG_PENDING_ALL = "SELECT COUNT(*) FROM aigov_sdk_approvals WHERE consumed_at IS NULL"
_PG_CONSUMED_ALL = "SELECT COUNT(*) FROM aigov_sdk_approvals WHERE consumed_at IS NOT NULL"
_PG_DELETE_ALL = "DELETE FROM aigov_sdk_approvals"


# ---------------------------------------------------------------------------
# SqlApprovalRegistry
# ---------------------------------------------------------------------------


class SqlApprovalRegistry:
    """
    Persistent, transaction-safe single-use approval registry.

    Backends:
      "sqlite"      — WAL mode + 5-second busy timeout. Multi-process safe on a
                      single machine (file locking). is_distributed_safe = False.
      "postgresql"  — FOR UPDATE SKIP LOCKED + row-level locking. Distributed-safe
                      across workers and hosts. is_distributed_safe = True.

    Usage (drop-in replacement for the in-memory ApprovalRegistry):
        registry = SqlApprovalRegistry(backend="sqlite", path="/data/approvals.db")
        registry.register(tool_name="delete_document", action_type="document:delete",
                          resource_id="tenant-A/doc-1", tenant_id="tenant-A",
                          approver_email="alice@example.com")
        entry, dvo = registry.consume("delete_document", "document:delete",
                                      "tenant-A/doc-1", "tenant-A")

    Atomicity guarantee:
      Two threads/processes racing to consume the same approval: exactly one
      wins (UPDATE rowcount == 1). The other receives ApprovalNotFound.
    """

    def __init__(
        self,
        backend: Literal["sqlite", "postgresql"] = "sqlite",
        path: str = ":memory:",
        dsn: str = "",
    ) -> None:
        self._backend = backend
        self._path = path
        self._dsn = dsn
        self._lock = threading.Lock()   # extra guard for in-process reentrancy

        if backend == "sqlite":
            self._init_sqlite()
        elif backend == "postgresql":
            self._init_postgres()
        else:
            raise ValueError(f"Unknown backend {backend!r}; use 'sqlite' or 'postgresql'")

    @property
    def is_distributed_safe(self) -> bool:
        return self._backend == "postgresql"

    # -------------------------------------------------------------------------
    # Public API — same interface as the in-memory ApprovalRegistry
    # -------------------------------------------------------------------------

    def register(
        self,
        tool_name: str,
        action_type: str,
        resource_id: str,
        tenant_id: str,
        approver_email: str = "approver@example.com",
        proposal_id: str | None = None,
        approval_id: str | None = None,
        record_id: str | None = None,
        audit_found: bool = True,
        audit_hash_verified: bool = True,
        audit_executed_value: str | None = None,
        approval_active: bool = True,
        approval_matches_proposal: bool = True,
        external_state_value: str | None = "approved",
    ) -> ApprovalEntry:
        entry = ApprovalEntry(
            proposal_id=proposal_id or f"prop-{uuid.uuid4().hex[:8]}",
            approval_id=approval_id or f"appr-{uuid.uuid4().hex[:8]}",
            record_id=record_id or f"rec-{uuid.uuid4().hex[:8]}",
            approver_email=approver_email,
            audit_found=audit_found,
            audit_hash_verified=audit_hash_verified,
            audit_executed_value=audit_executed_value,
            approval_active=approval_active,
            approval_matches_proposal=approval_matches_proposal,
            external_state_value=external_state_value,
        )
        self._do_insert(entry, tool_name, action_type, resource_id, tenant_id)
        return entry

    def consume(
        self,
        tool_name: str,
        action_type: str,
        resource_id: str,
        tenant_id: str,
    ) -> tuple[ApprovalEntry, DVOScenarioState]:
        """
        Atomically consume one approval for the given key.

        Returns (ApprovalEntry, DVOScenarioState).
        Raises ApprovalNotFound if no unused approval exists or concurrent
        consumption already won the race.
        """
        entry = self._do_consume(tool_name, action_type, resource_id, tenant_id)
        dvo = DVOScenarioState(
            proposal_id=entry.proposal_id,
            approval_id=entry.approval_id,
            record_id=entry.record_id,
            approver_email=entry.approver_email,
            audit_found=entry.audit_found,
            audit_hash_verified=entry.audit_hash_verified,
            audit_executed_value=entry.audit_executed_value,
            approval_active=entry.approval_active,
            approval_matches_proposal=entry.approval_matches_proposal,
            external_state_value=entry.external_state_value,
        )
        return entry, dvo

    def pending_count(self) -> int:
        """Number of unconsumed approvals."""
        return self._count(_SQLITE_PENDING_ALL if self._backend == "sqlite" else _PG_PENDING_ALL)

    def consumed_count(self) -> int:
        return self._count(_SQLITE_CONSUMED_ALL if self._backend == "sqlite" else _PG_CONSUMED_ALL)

    def reset(self) -> None:
        """Delete all rows. For test isolation only."""
        self._execute_write(_SQLITE_DELETE_ALL if self._backend == "sqlite" else _PG_DELETE_ALL, ())

    # -------------------------------------------------------------------------
    # SQLite implementation
    # -------------------------------------------------------------------------

    def _init_sqlite(self) -> None:
        conn = self._sqlite_conn()
        try:
            conn.execute(_SQLITE_CREATE)
            conn.execute(_SQLITE_IDX1)
            conn.commit()
        finally:
            conn.close()

    def _sqlite_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._path, timeout=5.0)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=5000")
        return conn

    def _sqlite_insert(self, entry: ApprovalEntry, tool_name, action_type, resource_id, tenant_id):
        conn = self._sqlite_conn()
        try:
            conn.execute(_SQLITE_INSERT, (
                entry.approval_id, tool_name, action_type, resource_id, tenant_id,
                entry.proposal_id, entry.record_id, entry.approver_email,
                int(entry.audit_found), int(entry.audit_hash_verified),
                entry.audit_executed_value,
                int(entry.approval_active), int(entry.approval_matches_proposal),
                entry.external_state_value,
                time.time(),
            ))
            conn.commit()
        except sqlite3.IntegrityError as exc:
            raise ApprovalRegistryError(f"Duplicate approval_id: {exc}") from exc
        finally:
            conn.close()

    def _sqlite_consume(self, tool_name, action_type, resource_id, tenant_id) -> ApprovalEntry:
        with self._lock:
            conn = self._sqlite_conn()
            try:
                row = conn.execute(_SQLITE_FIND, (tool_name, action_type, resource_id, tenant_id)).fetchone()
                if row is None:
                    raise ApprovalNotFound(
                        f"No pre-approval: tool={tool_name!r} action={action_type!r} "
                        f"resource={resource_id!r} tenant={tenant_id!r}"
                    )
                approval_id = row[0]
                cur = conn.execute(_SQLITE_CONSUME, (time.time(), os.getpid(), approval_id))
                conn.commit()
                if cur.rowcount != 1:
                    # Concurrent consume won the race (shouldn't happen under the lock,
                    # but cross-process racing without the lock can reach here)
                    raise ApprovalNotFound(
                        f"Approval {approval_id!r} already consumed (concurrent race)"
                    )
            finally:
                conn.close()
        return ApprovalEntry(
            proposal_id=row[1],
            approval_id=row[0],
            record_id=row[2],
            approver_email=row[3],
            audit_found=bool(row[4]),
            audit_hash_verified=bool(row[5]),
            audit_executed_value=row[6],
            approval_active=bool(row[7]),
            approval_matches_proposal=bool(row[8]),
            external_state_value=row[9],
        )

    # -------------------------------------------------------------------------
    # PostgreSQL implementation
    # -------------------------------------------------------------------------

    def _init_postgres(self) -> None:
        try:
            with self._pg_conn() as conn:
                conn.execute(_PG_CREATE)
                conn.execute(_PG_IDX1)
                conn.commit()
        except ApprovalRegistryError:
            raise
        except Exception as exc:
            raise ApprovalRegistryError(f"PostgreSQL init failed: {exc}") from exc

    def _pg_conn(self):
        try:
            import psycopg
        except ImportError as exc:
            raise ApprovalRegistryError(
                "psycopg[binary]>=3.3.9 required. Install: pip install 'psycopg[binary]>=3.3.9'"
            ) from exc
        return psycopg.connect(self._dsn)

    def _pg_insert(self, entry: ApprovalEntry, tool_name, action_type, resource_id, tenant_id):
        try:
            with self._pg_conn() as conn:
                conn.execute(_PG_INSERT, (
                    entry.approval_id, tool_name, action_type, resource_id, tenant_id,
                    entry.proposal_id, entry.record_id, entry.approver_email,
                    entry.audit_found, entry.audit_hash_verified,
                    entry.audit_executed_value,
                    entry.approval_active, entry.approval_matches_proposal,
                    entry.external_state_value,
                ))
                conn.commit()
        except Exception as exc:
            raise ApprovalRegistryError(f"PostgreSQL insert failed: {exc}") from exc

    def _pg_consume(self, tool_name, action_type, resource_id, tenant_id) -> ApprovalEntry:
        try:
            with self._pg_conn() as conn:
                row = conn.execute(_PG_FIND, (tool_name, action_type, resource_id, tenant_id)).fetchone()
                if row is None:
                    raise ApprovalNotFound(
                        f"No pre-approval: tool={tool_name!r} action={action_type!r} "
                        f"resource={resource_id!r} tenant={tenant_id!r}"
                    )
                approval_id = row[0]
                cur = conn.execute(_PG_CONSUME, (os.getpid(), approval_id))
                conn.commit()
                if cur.rowcount != 1:
                    raise ApprovalNotFound(
                        f"Approval {approval_id!r} already consumed (concurrent race)"
                    )
        except ApprovalNotFound:
            raise
        except Exception as exc:
            raise ApprovalRegistryError(f"PostgreSQL consume failed: {exc}") from exc
        return ApprovalEntry(
            proposal_id=row[1],
            approval_id=row[0],
            record_id=row[2],
            approver_email=row[3],
            audit_found=bool(row[4]),
            audit_hash_verified=bool(row[5]),
            audit_executed_value=row[6],
            approval_active=bool(row[7]),
            approval_matches_proposal=bool(row[8]),
            external_state_value=row[9],
        )

    # -------------------------------------------------------------------------
    # Dispatch helpers
    # -------------------------------------------------------------------------

    def _do_insert(self, entry, tool_name, action_type, resource_id, tenant_id):
        if self._backend == "sqlite":
            self._sqlite_insert(entry, tool_name, action_type, resource_id, tenant_id)
        else:
            self._pg_insert(entry, tool_name, action_type, resource_id, tenant_id)

    def _do_consume(self, tool_name, action_type, resource_id, tenant_id) -> ApprovalEntry:
        if self._backend == "sqlite":
            return self._sqlite_consume(tool_name, action_type, resource_id, tenant_id)
        return self._pg_consume(tool_name, action_type, resource_id, tenant_id)

    def _count(self, sql: str) -> int:
        if self._backend == "sqlite":
            conn = self._sqlite_conn()
            try:
                return conn.execute(sql).fetchone()[0]
            finally:
                conn.close()
        else:
            with self._pg_conn() as conn:
                return conn.execute(sql).fetchone()[0]

    def _execute_write(self, sql: str, params: tuple) -> None:
        if self._backend == "sqlite":
            conn = self._sqlite_conn()
            try:
                conn.execute(sql, params)
                conn.commit()
            finally:
                conn.close()
        else:
            with self._pg_conn() as conn:
                conn.execute(sql, params)
                conn.commit()
