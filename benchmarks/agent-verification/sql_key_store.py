"""
SQL-backed signing key store for distributed worker key sharing.

Multiple worker processes that point to the same SQL database automatically
share key additions, rotations, and retirements. This is the persistence
layer behind SqlRotatingKeyProvider.

Backends:
  "sqlite"      — Single-machine multi-process safe (WAL mode + file locking).
                  is_distributed_safe = False (not safe across machines).
  "postgresql"  — Fully distributed-safe across hosts.
                  Requires psycopg[binary]>=3.3.9.

Schema:
    aigov_signing_keys(
        key_id     TEXT PRIMARY KEY,
        key_bytes  BLOB NOT NULL,          -- raw HMAC key bytes (≥32)
        is_current INTEGER NOT NULL,       -- 1 = current signing key
        created_at REAL    NOT NULL,       -- Unix timestamp
        retired_at REAL                    -- NULL = active; non-NULL = retired
    )

Security notes:
  • Key bytes are stored in the database. For production deployments that
    already have a KMS (AWS KMS, HashiCorp Vault, Vercel KMS), store only the
    key_id reference in this table and fetch key material from the KMS in
    SqlRotatingKeyProvider.get_verification_key(). The table schema supports
    this by making key_bytes a required field here, but a KMS-aware subclass
    can override get/set to never persist raw bytes.
  • Retiring a key (retire_key) sets retired_at. The provider returns None
    for retired keys from get_verification_key(), immediately invalidating all
    tokens issued under that key. Drain in-flight requests before retiring.
  • set_current() is atomic within a transaction: the old current key's
    is_current flag is cleared before the new key's flag is set.
"""

from __future__ import annotations

import sqlite3
import time
from typing import Literal


class KeyStoreError(Exception):
    """Raised when a key store operation fails."""


class SqlKeyStore:
    """
    SQL-backed key registry shared across processes.

    Thread-safe: each operation opens and closes its own connection.
    PostgreSQL transactions provide atomicity for multi-host deployments.
    """

    _SQLITE_CREATE = """
        CREATE TABLE IF NOT EXISTS aigov_signing_keys (
            key_id      TEXT    PRIMARY KEY,
            key_bytes   BLOB    NOT NULL,
            is_current  INTEGER NOT NULL DEFAULT 0,
            created_at  REAL    NOT NULL,
            retired_at  REAL
        )
    """
    _SQLITE_INSERT = """
        INSERT INTO aigov_signing_keys (key_id, key_bytes, is_current, created_at)
        VALUES (?, ?, 0, ?)
    """
    _SQLITE_SET_CURRENT_CLEAR = "UPDATE aigov_signing_keys SET is_current = 0 WHERE is_current = 1"
    _SQLITE_SET_CURRENT       = "UPDATE aigov_signing_keys SET is_current = 1 WHERE key_id = ?"
    _SQLITE_RETIRE            = "UPDATE aigov_signing_keys SET retired_at = ? WHERE key_id = ?"
    _SQLITE_CURRENT_ID        = "SELECT key_id FROM aigov_signing_keys WHERE is_current = 1"
    _SQLITE_GET_KEY           = "SELECT key_bytes, retired_at FROM aigov_signing_keys WHERE key_id = ?"
    _SQLITE_ACTIVE_IDS        = "SELECT key_id FROM aigov_signing_keys WHERE retired_at IS NULL"
    _SQLITE_CHECK_ID          = "SELECT 1 FROM aigov_signing_keys WHERE key_id = ?"

    _PG_CREATE = """
        CREATE TABLE IF NOT EXISTS aigov_signing_keys (
            key_id      TEXT      PRIMARY KEY,
            key_bytes   BYTEA     NOT NULL,
            is_current  BOOLEAN   NOT NULL DEFAULT FALSE,
            created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            retired_at  TIMESTAMPTZ
        )
    """
    _PG_INSERT = """
        INSERT INTO aigov_signing_keys (key_id, key_bytes)
        VALUES (%s, %s)
    """
    _PG_SET_CURRENT_CLEAR = "UPDATE aigov_signing_keys SET is_current = FALSE WHERE is_current = TRUE"
    _PG_SET_CURRENT       = "UPDATE aigov_signing_keys SET is_current = TRUE WHERE key_id = %s"
    _PG_RETIRE            = "UPDATE aigov_signing_keys SET retired_at = NOW() WHERE key_id = %s"
    _PG_CURRENT_ID        = "SELECT key_id FROM aigov_signing_keys WHERE is_current = TRUE"
    _PG_GET_KEY           = "SELECT key_bytes, retired_at FROM aigov_signing_keys WHERE key_id = %s"
    _PG_ACTIVE_IDS        = "SELECT key_id FROM aigov_signing_keys WHERE retired_at IS NULL"
    _PG_CHECK_ID          = "SELECT 1 FROM aigov_signing_keys WHERE key_id = %s"

    def __init__(
        self,
        backend: Literal["sqlite", "postgresql"] = "sqlite",
        path: str = "",        # SQLite file path; "" or ":memory:" for in-process
        dsn: str = "",         # PostgreSQL DSN; ignored for sqlite
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

    # -------------------------------------------------------------------------
    # Public properties
    # -------------------------------------------------------------------------

    @property
    def is_distributed_safe(self) -> bool:
        return self._backend == "postgresql"

    # -------------------------------------------------------------------------
    # Key management
    # -------------------------------------------------------------------------

    def add_key(
        self,
        key_id: str,
        key_bytes: bytes,
        make_current: bool = False,
    ) -> None:
        """
        Register a new signing key.

        make_current=True atomically clears the old current flag and sets
        this key as current. If no key is current, the first key added is
        automatically made current regardless of make_current.

        Raises KeyStoreError if key_id already exists.
        """
        if len(key_bytes) < 32:
            raise KeyStoreError(f"Key {key_id!r} must be at least 32 bytes")
        if self._backend == "sqlite":
            self._sqlite_add_key(key_id, key_bytes, make_current)
        else:
            self._pg_add_key(key_id, key_bytes, make_current)

    def retire_key(self, key_id: str) -> None:
        """
        Retire a key. All tokens issued under this key will fail verification.

        The key's key_bytes remain stored for audit trail purposes; they are
        no longer returned by get_key_bytes().

        Cannot retire the current signing key; call set_current() to rotate
        to a new key first. Drain in-flight requests before retiring.
        """
        current = self.current_key_id()
        if current == key_id:
            raise KeyStoreError(
                f"Cannot retire current signing key {key_id!r}. "
                "Rotate to a new key with set_current() first."
            )
        if self._backend == "sqlite":
            self._sqlite_retire(key_id)
        else:
            self._pg_retire(key_id)

    def set_current(self, key_id: str) -> None:
        """
        Make key_id the current signing key. It must exist and not be retired.

        Atomic: clears old is_current flag and sets new one in one transaction.
        All processes reading the store after this call see the new current key.
        """
        if self._backend == "sqlite":
            self._sqlite_set_current(key_id)
        else:
            self._pg_set_current(key_id)

    def current_key_id(self) -> str:
        """Return the key_id of the current signing key."""
        if self._backend == "sqlite":
            return self._sqlite_current_id()
        return self._pg_current_id()

    def get_key_bytes(self, key_id: str) -> bytes | None:
        """
        Return raw key bytes for key_id.

        Returns None if the key does not exist or has been retired.
        Never raises for expected conditions.
        """
        if self._backend == "sqlite":
            return self._sqlite_get_key(key_id)
        return self._pg_get_key(key_id)

    def active_key_ids(self) -> list[str]:
        """Return all non-retired key IDs (available for verification)."""
        if self._backend == "sqlite":
            return self._sqlite_active_ids()
        return self._pg_active_ids()

    # -------------------------------------------------------------------------
    # SQLite
    # -------------------------------------------------------------------------

    def _sqlite_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._path or ":memory:", timeout=5.0)
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

    def _sqlite_add_key(self, key_id: str, key_bytes: bytes, make_current: bool) -> None:
        conn = self._sqlite_conn()
        try:
            # Check existence
            if conn.execute(self._SQLITE_CHECK_ID, (key_id,)).fetchone():
                raise KeyStoreError(f"Key {key_id!r} already exists")
            conn.execute(self._SQLITE_INSERT, (key_id, key_bytes, time.time()))
            # Make current if requested or if this is the first key
            has_current = bool(conn.execute(self._SQLITE_CURRENT_ID).fetchone())
            if make_current or not has_current:
                conn.execute(self._SQLITE_SET_CURRENT_CLEAR)
                conn.execute(self._SQLITE_SET_CURRENT, (key_id,))
            conn.commit()
        finally:
            conn.close()

    def _sqlite_retire(self, key_id: str) -> None:
        conn = self._sqlite_conn()
        try:
            conn.execute(self._SQLITE_RETIRE, (time.time(), key_id))
            conn.commit()
        finally:
            conn.close()

    def _sqlite_set_current(self, key_id: str) -> None:
        conn = self._sqlite_conn()
        try:
            row = conn.execute("SELECT retired_at FROM aigov_signing_keys WHERE key_id = ?",
                               (key_id,)).fetchone()
            if row is None:
                raise KeyStoreError(f"Key {key_id!r} not found")
            if row[0] is not None:
                raise KeyStoreError(f"Key {key_id!r} is retired; cannot set as current")
            conn.execute(self._SQLITE_SET_CURRENT_CLEAR)
            conn.execute(self._SQLITE_SET_CURRENT, (key_id,))
            conn.commit()
        finally:
            conn.close()

    def _sqlite_current_id(self) -> str:
        conn = self._sqlite_conn()
        try:
            row = conn.execute(self._SQLITE_CURRENT_ID).fetchone()
        finally:
            conn.close()
        if row is None:
            raise KeyStoreError("No current signing key configured")
        return row[0]

    def _sqlite_get_key(self, key_id: str) -> bytes | None:
        conn = self._sqlite_conn()
        try:
            row = conn.execute(self._SQLITE_GET_KEY, (key_id,)).fetchone()
        finally:
            conn.close()
        if row is None:
            return None
        key_bytes, retired_at = row
        return None if retired_at is not None else bytes(key_bytes)

    def _sqlite_active_ids(self) -> list[str]:
        conn = self._sqlite_conn()
        try:
            rows = conn.execute(self._SQLITE_ACTIVE_IDS).fetchall()
        finally:
            conn.close()
        return [r[0] for r in rows]

    # -------------------------------------------------------------------------
    # PostgreSQL
    # -------------------------------------------------------------------------

    def _pg_conn(self):  # type: ignore[return]
        try:
            import psycopg
        except ImportError as exc:
            raise KeyStoreError(
                "psycopg[binary]>=3.3.9 required for PostgreSQL backend"
            ) from exc
        return psycopg.connect(self._dsn)

    def _init_postgres(self) -> None:
        try:
            with self._pg_conn() as conn:
                conn.execute(self._PG_CREATE)
                conn.commit()
        except KeyStoreError:
            raise
        except Exception as exc:
            raise KeyStoreError(f"PostgreSQL init failed: {exc}") from exc

    def _pg_add_key(self, key_id: str, key_bytes: bytes, make_current: bool) -> None:
        try:
            with self._pg_conn() as conn:
                if conn.execute(self._PG_CHECK_ID, (key_id,)).fetchone():
                    raise KeyStoreError(f"Key {key_id!r} already exists")
                conn.execute(self._PG_INSERT, (key_id, key_bytes))
                has_current = bool(conn.execute(self._PG_CURRENT_ID).fetchone())
                if make_current or not has_current:
                    conn.execute(self._PG_SET_CURRENT_CLEAR)
                    conn.execute(self._PG_SET_CURRENT, (key_id,))
                conn.commit()
        except KeyStoreError:
            raise
        except Exception as exc:
            raise KeyStoreError(f"PostgreSQL add_key failed: {exc}") from exc

    def _pg_retire(self, key_id: str) -> None:
        try:
            with self._pg_conn() as conn:
                conn.execute(self._PG_RETIRE, (key_id,))
                conn.commit()
        except KeyStoreError:
            raise
        except Exception as exc:
            raise KeyStoreError(f"PostgreSQL retire_key failed: {exc}") from exc

    def _pg_set_current(self, key_id: str) -> None:
        try:
            with self._pg_conn() as conn:
                row = conn.execute(
                    "SELECT retired_at FROM aigov_signing_keys WHERE key_id = %s",
                    (key_id,)
                ).fetchone()
                if row is None:
                    raise KeyStoreError(f"Key {key_id!r} not found")
                if row[0] is not None:
                    raise KeyStoreError(f"Key {key_id!r} is retired")
                conn.execute(self._PG_SET_CURRENT_CLEAR)
                conn.execute(self._PG_SET_CURRENT, (key_id,))
                conn.commit()
        except KeyStoreError:
            raise
        except Exception as exc:
            raise KeyStoreError(f"PostgreSQL set_current failed: {exc}") from exc

    def _pg_current_id(self) -> str:
        try:
            with self._pg_conn() as conn:
                row = conn.execute(self._PG_CURRENT_ID).fetchone()
        except Exception as exc:
            raise KeyStoreError(f"PostgreSQL current_key_id failed: {exc}") from exc
        if row is None:
            raise KeyStoreError("No current signing key configured")
        return row[0]

    def _pg_get_key(self, key_id: str) -> bytes | None:
        try:
            with self._pg_conn() as conn:
                row = conn.execute(self._PG_GET_KEY, (key_id,)).fetchone()
        except Exception as exc:
            raise KeyStoreError(f"PostgreSQL get_key_bytes failed: {exc}") from exc
        if row is None:
            return None
        key_bytes, retired_at = row
        return None if retired_at is not None else bytes(key_bytes)

    def _pg_active_ids(self) -> list[str]:
        try:
            with self._pg_conn() as conn:
                rows = conn.execute(self._PG_ACTIVE_IDS).fetchall()
        except Exception as exc:
            raise KeyStoreError(f"PostgreSQL active_key_ids failed: {exc}") from exc
        return [r[0] for r in rows]
