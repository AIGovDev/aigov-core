"""
Shared atomic nonce store for replay protection.

Provides check-and-consume semantics across processes and workers.

Implementations:
  InMemoryNonceStore  — threading.Lock + set. NOT distributed-safe.
                        Explicitly for single-process unit tests only.
  SqlNonceStore       — SQLite or PostgreSQL backed. Atomic via
                        INSERT ... ON CONFLICT DO NOTHING with a UNIQUE
                        constraint on the nonce key.
                        SQLite: single-machine multi-process safe (file locking).
                        PostgreSQL: fully distributed-safe across workers/hosts.

Usage in production:
  Replace ReplayRegistry's default InMemoryNonceStore with SqlNonceStore
  backed by the deployment's PostgreSQL database:

    store = SqlNonceStore(dsn="postgresql://…", backend="postgresql")
    registry = ReplayRegistry(backend=store)
    gateway = ToolGateway(…, replay_registry=registry)

Security invariant:
  try_consume(key) is atomic: exactly one caller wins for any given key.
  Any subsequent call with the same key returns False — replay detected.
"""

from __future__ import annotations

import sqlite3
import threading
import time
from typing import Literal


class NonceStoreError(Exception):
    """Raised when a nonce store operation fails (e.g. database unreachable)."""


class InMemoryNonceStore:
    """
    In-memory nonce store. NOT distributed-safe. For local tests only.

    Thread-safe within one process (threading.Lock). Two processes each
    have their own store and cannot detect cross-process replays.

    Use SqlNonceStore for any multi-worker or persistent deployment.
    """

    is_distributed_safe: bool = False

    def __init__(self) -> None:
        self._consumed: set[str] = set()
        self._lock = threading.Lock()

    def try_consume(self, key: str) -> bool:
        """Atomically check-and-consume. Returns True on first consume, False on replay."""
        with self._lock:
            if key in self._consumed:
                return False
            self._consumed.add(key)
            return True

    def is_consumed(self, key: str) -> bool:
        with self._lock:
            return key in self._consumed

    def reset(self) -> None:
        with self._lock:
            self._consumed.clear()

    @property
    def consumed_count(self) -> int:
        with self._lock:
            return len(self._consumed)


class SqlNonceStore:
    """
    SQL-backed nonce store providing atomic check-and-consume across processes.

    Backends:
      "sqlite"      — Single-machine multi-process safe. Uses INSERT OR IGNORE
                      with WAL mode + 5-second busy timeout. is_distributed_safe
                      is False because cross-host safety requires a shared server.
      "postgresql"  — Fully distributed-safe. Uses INSERT … ON CONFLICT DO NOTHING.
                      Requires psycopg[binary]>=3.3.9 (`pip install psycopg[binary]`).
                      Pass dsn= with the connection string.

    Table schema (created automatically on first connection):
      CREATE TABLE IF NOT EXISTS aigov_consumed_nonces (
          nonce_key   TEXT PRIMARY KEY,
          consumed_at REAL NOT NULL
      );

    PostgreSQL variant uses TIMESTAMPTZ and NOW() for consumed_at.
    """

    _SQLITE_CREATE = """
        CREATE TABLE IF NOT EXISTS aigov_consumed_nonces (
            nonce_key   TEXT PRIMARY KEY,
            consumed_at REAL NOT NULL
        )
    """
    _SQLITE_CONSUME = """
        INSERT OR IGNORE INTO aigov_consumed_nonces (nonce_key, consumed_at)
        VALUES (?, ?)
    """
    _SQLITE_CHECK = "SELECT 1 FROM aigov_consumed_nonces WHERE nonce_key = ?"
    _SQLITE_DELETE = "DELETE FROM aigov_consumed_nonces"

    _PG_CREATE = """
        CREATE TABLE IF NOT EXISTS aigov_consumed_nonces (
            nonce_key   TEXT PRIMARY KEY,
            consumed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    """
    _PG_CONSUME = """
        INSERT INTO aigov_consumed_nonces (nonce_key)
        VALUES (%s)
        ON CONFLICT (nonce_key) DO NOTHING
    """
    _PG_CHECK = "SELECT 1 FROM aigov_consumed_nonces WHERE nonce_key = %s"
    _PG_DELETE = "DELETE FROM aigov_consumed_nonces"

    def __init__(
        self,
        backend: Literal["sqlite", "postgresql"] = "sqlite",
        path: str = ":memory:",   # for sqlite; ignored for postgresql
        dsn: str = "",             # for postgresql; ignored for sqlite
    ) -> None:
        self._backend = backend
        self._path = path
        self._dsn = dsn

        if backend == "sqlite":
            self._init_sqlite()
        elif backend == "postgresql":
            self._init_postgres()
        else:
            raise ValueError(f"Unknown backend {backend!r}; expected 'sqlite' or 'postgresql'")

    # -------------------------------------------------------------------------
    # Public properties
    # -------------------------------------------------------------------------

    @property
    def is_distributed_safe(self) -> bool:
        """
        True for PostgreSQL (shared server enforces atomicity across hosts).
        False for SQLite (file-level locking only; not safe across machines).
        """
        return self._backend == "postgresql"

    # -------------------------------------------------------------------------
    # Public interface
    # -------------------------------------------------------------------------

    def try_consume(self, key: str) -> bool:
        """
        Atomically check and consume the nonce key.

        Returns True if key was not previously seen (first consume).
        Returns False if key was already consumed (replay detected).
        Never raises for expected database conditions; raises NonceStoreError
        only on unrecoverable I/O failures.
        """
        if self._backend == "sqlite":
            return self._sqlite_try_consume(key)
        return self._pg_try_consume(key)

    def is_consumed(self, key: str) -> bool:
        if self._backend == "sqlite":
            return self._sqlite_is_consumed(key)
        return self._pg_is_consumed(key)

    def reset(self) -> None:
        """Clear all consumed nonces. Use for test isolation between runs."""
        if self._backend == "sqlite":
            self._sqlite_reset()
        else:
            self._pg_reset()

    # -------------------------------------------------------------------------
    # SQLite implementation
    # -------------------------------------------------------------------------

    def _init_sqlite(self) -> None:
        conn = self._sqlite_conn()
        try:
            conn.execute(self._SQLITE_CREATE)
            conn.commit()
        finally:
            conn.close()

    def _sqlite_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._path, timeout=5.0)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=5000")
        return conn

    def _sqlite_try_consume(self, key: str) -> bool:
        conn = self._sqlite_conn()
        try:
            cursor = conn.execute(self._SQLITE_CONSUME, (key, time.time()))
            conn.commit()
            return cursor.rowcount == 1
        except sqlite3.OperationalError as exc:
            raise NonceStoreError(f"SQLite error consuming nonce: {exc}") from exc
        finally:
            conn.close()

    def _sqlite_is_consumed(self, key: str) -> bool:
        conn = self._sqlite_conn()
        try:
            row = conn.execute(self._SQLITE_CHECK, (key,)).fetchone()
            return row is not None
        finally:
            conn.close()

    def _sqlite_reset(self) -> None:
        conn = self._sqlite_conn()
        try:
            conn.execute(self._SQLITE_DELETE)
            conn.commit()
        finally:
            conn.close()

    # -------------------------------------------------------------------------
    # PostgreSQL implementation
    # -------------------------------------------------------------------------

    def _init_postgres(self) -> None:
        try:
            with self._pg_conn() as conn:
                conn.execute(self._PG_CREATE)
                conn.commit()
        except NonceStoreError:
            raise
        except Exception as exc:
            raise NonceStoreError(f"PostgreSQL init failed: {exc}") from exc

    def _pg_conn(self):  # type: ignore[return]
        try:
            import psycopg
        except ImportError as exc:
            raise NonceStoreError(
                "psycopg[binary]>=3.3.9 required for PostgreSQL backend. "
                "Install with: pip install 'psycopg[binary]>=3.3.9'"
            ) from exc
        return psycopg.connect(self._dsn)

    def _pg_try_consume(self, key: str) -> bool:
        try:
            with self._pg_conn() as conn:
                cursor = conn.execute(self._PG_CONSUME, (key,))
                conn.commit()
                return cursor.rowcount == 1
        except Exception as exc:  # noqa: BLE001
            raise NonceStoreError(f"PostgreSQL error consuming nonce: {exc}") from exc

    def _pg_is_consumed(self, key: str) -> bool:
        with self._pg_conn() as conn:
            row = conn.execute(self._PG_CHECK, (key,)).fetchone()
            return row is not None

    def _pg_reset(self) -> None:
        with self._pg_conn() as conn:
            conn.execute(self._PG_DELETE)
            conn.commit()
