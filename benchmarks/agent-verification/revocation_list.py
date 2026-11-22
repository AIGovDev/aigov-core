"""
Approval-level revocation list for Condition I.

Distinct from PolicyRecord.revoked (policy-level revocation at fixture time).
RevocationList handles runtime revocation: an approval is issued and valid,
but then revoked before it is consumed (e.g., approver's access is terminated
between issuance and execution).

Implementations:
  InMemoryRevocationStore — threading.Lock + dict. NOT distributed-safe.
                            For single-process tests only.
  SqlRevocationStore      — SQLite or PostgreSQL backed. Revocations persist
                            across process restarts and are shared across workers.

Security invariants:
  - Revocation is tenant-scoped: same approval_id in different tenants
    is treated as independent.
  - Revocations are write-once: first revocation wins (idempotent).
  - Fail-closed: in production, an unreachable revocation store should be
    treated as INDETERMINATE by the caller (not ALLOW).
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


# ---------------------------------------------------------------------------
# Store backends
# ---------------------------------------------------------------------------


class InMemoryRevocationStore:
    """
    In-memory revocation store. NOT distributed-safe. For local tests only.

    Revocations in one process are not visible to other processes.
    For multi-worker deployments, use SqlRevocationStore.
    """

    is_distributed_safe: bool = False

    def __init__(self) -> None:
        self._entries: dict[str, RevocationEntry] = {}
        self._lock = threading.Lock()

    @staticmethod
    def _key(approval_id: str, tenant_id: str) -> str:
        return json.dumps({"a": approval_id, "t": tenant_id}, sort_keys=True)

    def revoke(
        self,
        approval_id: str,
        tenant_id: str,
        reason: str,
        revoked_at: float | None = None,
    ) -> None:
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
        return self._key(approval_id, tenant_id) in self._entries

    def get_entry(self, approval_id: str, tenant_id: str) -> RevocationEntry | None:
        return self._entries.get(self._key(approval_id, tenant_id))

    def all_entries(self) -> list[RevocationEntry]:
        with self._lock:
            return list(self._entries.values())


class SqlRevocationStore:
    """
    SQL-backed revocation store. Persistent and shared across workers.

    Backends:
      "sqlite"      — Single-machine multi-process safe. File-backed.
      "postgresql"  — Fully distributed-safe across hosts.

    Table schema (created automatically):
      aigov_revocations(approval_id TEXT, tenant_id TEXT, revoked_at REAL,
                         reason TEXT, PRIMARY KEY (approval_id, tenant_id))
    """

    _SQLITE_CREATE = """
        CREATE TABLE IF NOT EXISTS aigov_revocations (
            approval_id TEXT NOT NULL,
            tenant_id   TEXT NOT NULL,
            revoked_at  REAL NOT NULL,
            reason      TEXT NOT NULL,
            PRIMARY KEY (approval_id, tenant_id)
        )
    """
    _SQLITE_INSERT = """
        INSERT OR IGNORE INTO aigov_revocations
            (approval_id, tenant_id, revoked_at, reason)
        VALUES (?, ?, ?, ?)
    """
    _SQLITE_CHECK = """
        SELECT 1 FROM aigov_revocations
        WHERE approval_id = ? AND tenant_id = ?
    """
    _SQLITE_FETCH = """
        SELECT approval_id, tenant_id, revoked_at, reason
        FROM aigov_revocations
        WHERE approval_id = ? AND tenant_id = ?
    """
    _SQLITE_ALL = "SELECT approval_id, tenant_id, revoked_at, reason FROM aigov_revocations"
    _SQLITE_DELETE = "DELETE FROM aigov_revocations"

    _PG_CREATE = """
        CREATE TABLE IF NOT EXISTS aigov_revocations (
            approval_id TEXT NOT NULL,
            tenant_id   TEXT NOT NULL,
            revoked_at  REAL NOT NULL,
            reason      TEXT NOT NULL,
            PRIMARY KEY (approval_id, tenant_id)
        )
    """
    _PG_INSERT = """
        INSERT INTO aigov_revocations (approval_id, tenant_id, revoked_at, reason)
        VALUES (%s, %s, %s, %s)
        ON CONFLICT (approval_id, tenant_id) DO NOTHING
    """
    _PG_CHECK = "SELECT 1 FROM aigov_revocations WHERE approval_id = %s AND tenant_id = %s"
    _PG_FETCH = "SELECT approval_id, tenant_id, revoked_at, reason FROM aigov_revocations WHERE approval_id = %s AND tenant_id = %s"
    _PG_ALL   = "SELECT approval_id, tenant_id, revoked_at, reason FROM aigov_revocations"
    _PG_DELETE = "DELETE FROM aigov_revocations"

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

    @property
    def is_distributed_safe(self) -> bool:
        return self._backend == "postgresql"

    # ---- SQLite ----

    def _sqlite_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._path, timeout=5.0)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=5000")
        return conn

    def _init_sqlite(self) -> None:
        conn = self._sqlite_conn()
        try:
            conn.execute(self._SQLITE_CREATE)
            conn.commit()
        finally:
            conn.close()

    # ---- PostgreSQL ----

    def _pg_conn(self):  # type: ignore[return]
        try:
            import psycopg
        except ImportError as exc:
            raise RuntimeError(
                "psycopg[binary]>=3.3.9 required for PostgreSQL revocation backend."
            ) from exc
        return psycopg.connect(self._dsn)

    def _init_postgres(self) -> None:
        with self._pg_conn() as conn:
            conn.execute(self._PG_CREATE)
            conn.commit()

    # ---- Unified operations ----

    def revoke(
        self,
        approval_id: str,
        tenant_id: str,
        reason: str,
        revoked_at: float | None = None,
    ) -> None:
        if revoked_at is None:
            revoked_at = time.time()
        if self._backend == "sqlite":
            conn = self._sqlite_conn()
            try:
                conn.execute(self._SQLITE_INSERT, (approval_id, tenant_id, revoked_at, reason))
                conn.commit()
            finally:
                conn.close()
        else:
            with self._pg_conn() as conn:
                conn.execute(self._PG_INSERT, (approval_id, tenant_id, revoked_at, reason))
                conn.commit()

    def is_revoked(self, approval_id: str, tenant_id: str) -> bool:
        if self._backend == "sqlite":
            conn = self._sqlite_conn()
            try:
                row = conn.execute(self._SQLITE_CHECK, (approval_id, tenant_id)).fetchone()
                return row is not None
            finally:
                conn.close()
        else:
            with self._pg_conn() as conn:
                row = conn.execute(self._PG_CHECK, (approval_id, tenant_id)).fetchone()
                return row is not None

    def get_entry(self, approval_id: str, tenant_id: str) -> RevocationEntry | None:
        if self._backend == "sqlite":
            conn = self._sqlite_conn()
            try:
                row = conn.execute(self._SQLITE_FETCH, (approval_id, tenant_id)).fetchone()
            finally:
                conn.close()
        else:
            with self._pg_conn() as conn:
                row = conn.execute(self._PG_FETCH, (approval_id, tenant_id)).fetchone()
        if row is None:
            return None
        return RevocationEntry(
            approval_id=row[0], tenant_id=row[1], revoked_at=row[2], reason=row[3]
        )

    def all_entries(self) -> list[RevocationEntry]:
        if self._backend == "sqlite":
            conn = self._sqlite_conn()
            try:
                rows = conn.execute(self._SQLITE_ALL).fetchall()
            finally:
                conn.close()
        else:
            with self._pg_conn() as conn:
                rows = conn.execute(self._PG_ALL).fetchall()
        return [RevocationEntry(r[0], r[1], r[2], r[3]) for r in rows]

    def reset(self) -> None:
        if self._backend == "sqlite":
            conn = self._sqlite_conn()
            try:
                conn.execute(self._SQLITE_DELETE)
                conn.commit()
            finally:
                conn.close()
        else:
            with self._pg_conn() as conn:
                conn.execute(self._PG_DELETE)
                conn.commit()


# ---------------------------------------------------------------------------
# Public API — RevocationList
# ---------------------------------------------------------------------------


class RevocationList:
    """
    Approval-level revocation list backed by a pluggable store.

    Default backend is InMemoryRevocationStore (not distributed-safe; for tests).
    For production, inject a SqlRevocationStore("postgresql", dsn=...) backend.

    Public API is unchanged from the original: revoke(), is_revoked(),
    get_revocation_entry(), state_hash(), entry_count().
    """

    def __init__(self, backend=None) -> None:  # backend: RevocationStore | None
        if backend is None:
            backend = InMemoryRevocationStore()
        self._backend = backend

    @property
    def is_distributed_safe(self) -> bool:
        return self._backend.is_distributed_safe

    def revoke(
        self,
        approval_id: str,
        tenant_id: str,
        reason: str,
        revoked_at: float | None = None,
    ) -> None:
        """
        Add an approval to the revocation list.
        Idempotent: revoking an already-revoked approval is a no-op.
        """
        self._backend.revoke(approval_id, tenant_id, reason, revoked_at)

    def is_revoked(self, approval_id: str, tenant_id: str) -> bool:
        """Return True if the approval has been explicitly revoked."""
        return self._backend.is_revoked(approval_id, tenant_id)

    def get_revocation_entry(
        self, approval_id: str, tenant_id: str
    ) -> RevocationEntry | None:
        """Return the revocation entry if present, else None."""
        return self._backend.get_entry(approval_id, tenant_id)

    def state_hash(self) -> str:
        """
        Deterministic SHA-256 hash of the current revocation state.
        Changes whenever an entry is added.
        """
        entries = sorted(
            self._backend.all_entries(),
            key=lambda e: (e.tenant_id, e.approval_id),
        )
        rows = [e.to_dict() for e in entries]
        canonical = json.dumps(rows, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode()).hexdigest()

    def entry_count(self) -> int:
        """Number of revoked approvals."""
        return len(self._backend.all_entries())
