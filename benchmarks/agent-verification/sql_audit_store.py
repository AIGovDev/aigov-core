"""
Persistent execution audit log backed by PostgreSQL or SQLite.

Records every authorization decision and tool-execution attempt durably, so
the audit trail survives process restarts and is accessible across workers.

CRITICAL: Audit writes are NOT transactional with nonce consumption.
==================================================================
In the current architecture, nonce consumption (ReplayRegistry.try_consume)
happens inside ConditionIOrchestrator and the audit write happens inside
ToolGateway after tools.execute() returns. These are two separate database
commits. If the process crashes after consuming the nonce but before writing
the audit record, the following are BOTH true:

  1. The nonce IS consumed — the authorization cannot be replayed (correct).
  2. The audit record is MISSING — no evidence the execution was attempted.

This is an inherent limitation of the current pipeline architecture. To make
audit writes transactional with nonce consumption, the nonce-store connection
would need to be threaded through the entire authorization pipeline so both
writes share one transaction. That is a larger architectural change.

NEVER claim exactly-once external side effects from nonce consumption.
======================================================================
Consuming a nonce atomically prevents double-authorization (replay). It does
NOT prevent double-execution of external side effects. Example failure path:

  1. Nonce consumed (committed to DB) → authorization is single-use.
  2. Tool execution starts (e.g., API call to GitHub).
  3. API call succeeds but response is lost (network fault).
  4. Gateway returns error; caller retries.
  5. Retry hits the replay check → DENY (correct).
  6. External side effect (the GitHub write) may have happened already.

External tools MUST be idempotent, or the caller must implement compensating
transactions. The gateway guarantees authorization single-use, NOT execution
single-use.

Security note: The audit log records decision metadata and hashes only.
Raw argument values and signing key bytes are never written.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
import time
from dataclasses import dataclass
from typing import Any, Literal


@dataclass
class AuditEntry:
    execution_id: str
    tenant_id: str
    tool_name: str
    action_type: str
    resource_id: str
    args_binding_hash: str
    key_id: str | None     # EAT key_id; None if blocked before token issuance
    decision: str           # ALLOW / DENY / INDETERMINATE / REQUIRES_REVIEW
    authorized: bool
    block_reason: str | None
    logged_at: float        # Unix timestamp

    def to_dict(self) -> dict[str, Any]:
        return {
            "execution_id": self.execution_id,
            "tenant_id": self.tenant_id,
            "tool_name": self.tool_name,
            "action_type": self.action_type,
            "resource_id": self.resource_id,
            "args_binding_hash": self.args_binding_hash,
            "key_id": self.key_id,
            "decision": self.decision,
            "authorized": self.authorized,
            "block_reason": self.block_reason,
            "logged_at": self.logged_at,
        }


class SqlAuditStore:
    """
    Persistent execution audit log.

    Backend: "sqlite" or "postgresql".

    Thread-safe: each write opens a fresh connection. For high-throughput
    production deployments, replace with a connection pool.

    Transaction gap (see module docstring): audit writes commit AFTER the
    nonce is consumed, in a separate transaction.
    """

    _SQLITE_CREATE = """
        CREATE TABLE IF NOT EXISTS aigov_audit_log (
            log_id       INTEGER PRIMARY KEY AUTOINCREMENT,
            execution_id TEXT    NOT NULL,
            tenant_id    TEXT    NOT NULL,
            tool_name    TEXT    NOT NULL,
            action_type  TEXT    NOT NULL,
            resource_id  TEXT    NOT NULL,
            args_hash    TEXT    NOT NULL,
            key_id       TEXT,
            decision     TEXT    NOT NULL,
            authorized   INTEGER NOT NULL,
            block_reason TEXT,
            logged_at    REAL    NOT NULL
        )
    """
    _SQLITE_IDX1 = "CREATE INDEX IF NOT EXISTS aigov_audit_exec ON aigov_audit_log(execution_id)"
    _SQLITE_IDX2 = "CREATE INDEX IF NOT EXISTS aigov_audit_tenant ON aigov_audit_log(tenant_id, logged_at DESC)"
    _SQLITE_INSERT = """
        INSERT INTO aigov_audit_log
            (execution_id, tenant_id, tool_name, action_type, resource_id,
             args_hash, key_id, decision, authorized, block_reason, logged_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """
    _SQLITE_FETCH_EXEC = "SELECT * FROM aigov_audit_log WHERE execution_id = ?"
    _SQLITE_FETCH_TENANT = "SELECT * FROM aigov_audit_log WHERE tenant_id = ? ORDER BY logged_at DESC LIMIT ?"

    _PG_CREATE = """
        CREATE TABLE IF NOT EXISTS aigov_audit_log (
            log_id       BIGSERIAL PRIMARY KEY,
            execution_id TEXT         NOT NULL,
            tenant_id    TEXT         NOT NULL,
            tool_name    TEXT         NOT NULL,
            action_type  TEXT         NOT NULL,
            resource_id  TEXT         NOT NULL,
            args_hash    TEXT         NOT NULL,
            key_id       TEXT,
            decision     TEXT         NOT NULL,
            authorized   BOOLEAN      NOT NULL,
            block_reason TEXT,
            logged_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW()
        )
    """
    _PG_IDX1 = "CREATE INDEX IF NOT EXISTS aigov_audit_exec ON aigov_audit_log(execution_id)"
    _PG_IDX2 = "CREATE INDEX IF NOT EXISTS aigov_audit_tenant ON aigov_audit_log(tenant_id, logged_at DESC)"
    _PG_INSERT = """
        INSERT INTO aigov_audit_log
            (execution_id, tenant_id, tool_name, action_type, resource_id,
             args_hash, key_id, decision, authorized, block_reason)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
    """
    _PG_FETCH_EXEC = "SELECT execution_id, tenant_id, tool_name, action_type, resource_id, args_hash, key_id, decision, authorized, block_reason, EXTRACT(EPOCH FROM logged_at) FROM aigov_audit_log WHERE execution_id = %s"
    _PG_FETCH_TENANT = "SELECT execution_id, tenant_id, tool_name, action_type, resource_id, args_hash, key_id, decision, authorized, block_reason, EXTRACT(EPOCH FROM logged_at) FROM aigov_audit_log WHERE tenant_id = %s ORDER BY logged_at DESC LIMIT %s"

    def __init__(
        self,
        backend: Literal["sqlite", "postgresql"] = "sqlite",
        path: str = ":memory:",
        dsn: str = "",
    ) -> None:
        self._backend = backend
        self._path = path
        self._dsn = dsn
        if backend == "sqlite":
            self._init_sqlite()
        elif backend == "postgresql":
            self._init_postgres()
        else:
            raise ValueError(f"Unknown backend {backend!r}")

    # ---- Init ----

    def _sqlite_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._path, timeout=5.0)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=5000")
        return conn

    def _init_sqlite(self) -> None:
        conn = self._sqlite_conn()
        try:
            conn.execute(self._SQLITE_CREATE)
            conn.execute(self._SQLITE_IDX1)
            conn.execute(self._SQLITE_IDX2)
            conn.commit()
        finally:
            conn.close()

    def _pg_conn(self):
        try:
            import psycopg
        except ImportError as exc:
            raise RuntimeError("psycopg[binary]>=3.3.9 required") from exc
        return psycopg.connect(self._dsn)

    def _init_postgres(self) -> None:
        with self._pg_conn() as conn:
            conn.execute(self._PG_CREATE)
            conn.execute(self._PG_IDX1)
            conn.execute(self._PG_IDX2)
            conn.commit()

    # ---- Write ----

    def record(
        self,
        execution_id: str,
        tenant_id: str,
        tool_name: str,
        action_type: str,
        resource_id: str,
        args_binding_hash: str,
        key_id: str | None,
        decision: str,
        authorized: bool,
        block_reason: str | None,
    ) -> None:
        """
        Append one audit record.

        Non-fatal: if the write fails (DB unavailable, constraint error), the
        exception is logged to stderr but NOT re-raised. The calling authorization
        pipeline continues regardless. Audit completeness is best-effort.

        Note: This commit is SEPARATE from the nonce-consumption commit. See
        module docstring for the atomicity gap.
        """
        try:
            self._do_record(execution_id, tenant_id, tool_name, action_type,
                            resource_id, args_binding_hash, key_id, decision,
                            authorized, block_reason)
        except Exception as exc:  # noqa: BLE001
            import sys
            print(f"[audit] WARNING: failed to write audit record for {execution_id}: {exc}",
                  file=sys.stderr)

    def _do_record(self, execution_id, tenant_id, tool_name, action_type,
                   resource_id, args_hash, key_id, decision, authorized, block_reason):
        if self._backend == "sqlite":
            conn = self._sqlite_conn()
            try:
                conn.execute(self._SQLITE_INSERT, (
                    execution_id, tenant_id, tool_name, action_type, resource_id,
                    args_hash, key_id, decision, int(authorized), block_reason, time.time(),
                ))
                conn.commit()
            finally:
                conn.close()
        else:
            with self._pg_conn() as conn:
                conn.execute(self._PG_INSERT, (
                    execution_id, tenant_id, tool_name, action_type, resource_id,
                    args_hash, key_id, decision, authorized, block_reason,
                ))
                conn.commit()

    # ---- Read (for tests and audit tooling) ----

    def get_by_execution_id(self, execution_id: str) -> list[AuditEntry]:
        if self._backend == "sqlite":
            conn = self._sqlite_conn()
            try:
                rows = conn.execute(self._SQLITE_FETCH_EXEC, (execution_id,)).fetchall()
            finally:
                conn.close()
        else:
            with self._pg_conn() as conn:
                rows = conn.execute(self._PG_FETCH_EXEC, (execution_id,)).fetchall()
        return [self._row_to_entry(r) for r in rows]

    def get_by_tenant(self, tenant_id: str, limit: int = 100) -> list[AuditEntry]:
        if self._backend == "sqlite":
            conn = self._sqlite_conn()
            try:
                rows = conn.execute(self._SQLITE_FETCH_TENANT, (tenant_id, limit)).fetchall()
            finally:
                conn.close()
        else:
            with self._pg_conn() as conn:
                rows = conn.execute(self._PG_FETCH_TENANT, (tenant_id, limit)).fetchall()
        return [self._row_to_entry(r) for r in rows]

    @staticmethod
    def _row_to_entry(row: tuple) -> AuditEntry:
        # Columns: execution_id, tenant_id, tool_name, action_type, resource_id,
        #          args_hash, key_id, decision, authorized, block_reason, logged_at
        # (log_id is first for sqlite; skip it)
        if len(row) == 12:  # sqlite: log_id included
            row = row[1:]
        return AuditEntry(
            execution_id=row[0],
            tenant_id=row[1],
            tool_name=row[2],
            action_type=row[3],
            resource_id=row[4],
            args_binding_hash=row[5],
            key_id=row[6],
            decision=row[7],
            authorized=bool(row[8]),
            block_reason=row[9],
            logged_at=float(row[10]),
        )

    def entry_count(self) -> int:
        if self._backend == "sqlite":
            conn = self._sqlite_conn()
            try:
                return conn.execute("SELECT COUNT(*) FROM aigov_audit_log").fetchone()[0]
            finally:
                conn.close()
        else:
            with self._pg_conn() as conn:
                return conn.execute("SELECT COUNT(*) FROM aigov_audit_log").fetchone()[0]
