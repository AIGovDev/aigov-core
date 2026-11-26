"""
KMS-backed signing key provider — raw key bytes never stored in SQL.

Architecture:
  SqlKeyMetadataStore  — SQL holds only: key_id, is_current, created_at, retired_at.
                         No key_bytes column. SQL compromise exposes rotation state only.
  KMSClientBase        — Abstract interface for key-material retrieval.
  EnvKMSClient         — Simulation-grade KMS backed by environment variables.
                         Production: replace with VercelKMSClient / AWSKMSClient / VaultClient.
  KMSBackedRotatingKeyProvider — Combines metadata store + KMS client.
                                 is_managed=True; suppresses RuntimeWarning.

Production key provisioning:
  1. Generate key bytes out-of-band (never in this process).
  2. Load into the KMS (Vercel KMS, AWS Secrets Manager, HashiCorp Vault, etc.).
  3. Register the key_id in SqlKeyMetadataStore: metadata_store.add_key("v1").
  4. The provider fetches bytes at runtime via kms_client.get_key("v1").

EnvKMSClient (local simulation):
  Read from env: AIGOV_SIGNING_KEY_{KEY_ID}=<base64url-encoded bytes, ≥32 bytes>
  Example: export AIGOV_SIGNING_KEY_v1=$(python3 -c "import os,base64; print(base64.b64encode(os.urandom(32)).decode())")
  Missing or short env var → returns None → token verification fails (key not available).

Security properties:
  • SQL database compromise reveals key_id rotation state, NOT key material.
  • KMS unavailability (missing env var) blocks token issuance fail-closed.
  • Retiring a key (set retired_at in SQL) immediately makes get_verification_key
    return None for all workers sharing the metadata store — tokens rejected.
  • Zero-downtime rotation: add new key_id to both SQL and KMS; set_current in SQL;
    all workers sign with new key; old key still verifiable; retire when drained.
"""

from __future__ import annotations

import base64
import os
import sqlite3
import threading
import time
from typing import Literal


class KMSUnavailableError(Exception):
    """Raised when the KMS cannot provide key material (unavailable, misconfigured)."""


class KeyMetadataError(Exception):
    """Raised when a key metadata operation fails."""


# ---------------------------------------------------------------------------
# KMS client base and implementations
# ---------------------------------------------------------------------------


class KMSClientBase:
    """
    Abstract KMS client interface.

    Implementations fetch key material from external secure stores. They must
    never return key bytes from an in-process dict (that defeats the separation).

    get_key(key_id) returns raw key bytes (≥32) or None if the key is unknown.
    """

    def get_key(self, key_id: str) -> bytes | None:
        raise NotImplementedError


class EnvKMSClient(KMSClientBase):
    """
    Environment-variable-backed KMS simulation.

    Key bytes are read from the process environment at call time — never cached.
    Each call re-reads the environment so key removal (env var deletion) is
    immediately reflected.

    Env var format:
        AIGOV_SIGNING_KEY_{KEY_ID} = base64-encoded bytes (standard or URL-safe)

    Limitations (simulation only):
        - Env vars are readable by any code in the process. Use only for
          development and staging with randomly generated keys.
        - Production deployments must use a real KMS that enforces access control
          at the OS or hardware boundary (AWS KMS, HashiCorp Vault, Vercel KMS).

    Generating a key for local use:
        python3 -c "import os,base64; print(base64.b64encode(os.urandom(32)).decode())"
    Then: export AIGOV_SIGNING_KEY_v1=<output>
    """

    # Prefix for env var lookup
    ENV_PREFIX: str = "AIGOV_SIGNING_KEY_"

    def __init__(self, env: dict[str, str] | None = None) -> None:
        """
        env: optional dict override for testing (e.g., monkeypatched os.environ).
             Defaults to os.environ when None.
        """
        self._env = env  # None → use os.environ at call time

    def get_key(self, key_id: str) -> bytes | None:
        """
        Return key bytes for key_id, or None if unavailable.

        Reads the env var AIGOV_SIGNING_KEY_{KEY_ID}. Returns None if:
          • The env var is not set
          • The value is not valid base64
          • The decoded bytes are shorter than 32 bytes

        Never raises for expected conditions (missing key → None).
        """
        env = self._env if self._env is not None else os.environ
        raw = env.get(f"{self.ENV_PREFIX}{key_id}", "")
        if not raw:
            return None
        try:
            key_bytes = base64.b64decode(raw + "==")  # lenient padding
        except Exception:
            try:
                key_bytes = base64.urlsafe_b64decode(raw + "==")
            except Exception:
                return None
        return key_bytes if len(key_bytes) >= 32 else None

    @staticmethod
    def env_key_name(key_id: str) -> str:
        """Return the env var name for key_id."""
        return f"{EnvKMSClient.ENV_PREFIX}{key_id}"

    @staticmethod
    def encode_key(key_bytes: bytes) -> str:
        """Encode key bytes as base64 for use in an env var."""
        return base64.b64encode(key_bytes).decode()


# ---------------------------------------------------------------------------
# SQL metadata store (no key_bytes)
# ---------------------------------------------------------------------------


class SqlKeyMetadataStore:
    """
    SQL-backed key metadata store. Stores key rotation state ONLY — no key bytes.

    Two workers sharing the same database automatically see each other's
    key additions, rotations (set_current), and retirements.

    Backends: "sqlite" (single-machine) and "postgresql" (distributed).
    """

    _SQLITE_CREATE = """
        CREATE TABLE IF NOT EXISTS aigov_key_metadata (
            key_id      TEXT    PRIMARY KEY,
            is_current  INTEGER NOT NULL DEFAULT 0,
            created_at  REAL    NOT NULL,
            retired_at  REAL
        )
    """
    _SQLITE_INSERT            = "INSERT INTO aigov_key_metadata (key_id, created_at) VALUES (?, ?)"
    _SQLITE_SET_CLEAR         = "UPDATE aigov_key_metadata SET is_current = 0 WHERE is_current = 1"
    _SQLITE_SET_CURRENT       = "UPDATE aigov_key_metadata SET is_current = 1 WHERE key_id = ?"
    _SQLITE_RETIRE            = "UPDATE aigov_key_metadata SET retired_at = ? WHERE key_id = ?"
    _SQLITE_CURRENT_ID        = "SELECT key_id FROM aigov_key_metadata WHERE is_current = 1"
    _SQLITE_GET_RETIRED_AT    = "SELECT retired_at FROM aigov_key_metadata WHERE key_id = ?"
    _SQLITE_CHECK_ID          = "SELECT 1 FROM aigov_key_metadata WHERE key_id = ?"
    _SQLITE_ACTIVE_IDS        = "SELECT key_id FROM aigov_key_metadata WHERE retired_at IS NULL"

    _PG_CREATE = """
        CREATE TABLE IF NOT EXISTS aigov_key_metadata (
            key_id      TEXT      PRIMARY KEY,
            is_current  BOOLEAN   NOT NULL DEFAULT FALSE,
            created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            retired_at  TIMESTAMPTZ
        )
    """
    _PG_INSERT            = "INSERT INTO aigov_key_metadata (key_id) VALUES (%s)"
    _PG_SET_CLEAR         = "UPDATE aigov_key_metadata SET is_current = FALSE WHERE is_current = TRUE"
    _PG_SET_CURRENT       = "UPDATE aigov_key_metadata SET is_current = TRUE WHERE key_id = %s"
    _PG_RETIRE            = "UPDATE aigov_key_metadata SET retired_at = NOW() WHERE key_id = %s"
    _PG_CURRENT_ID        = "SELECT key_id FROM aigov_key_metadata WHERE is_current = TRUE"
    _PG_GET_RETIRED_AT    = "SELECT retired_at FROM aigov_key_metadata WHERE key_id = %s"
    _PG_CHECK_ID          = "SELECT 1 FROM aigov_key_metadata WHERE key_id = %s"
    _PG_ACTIVE_IDS        = "SELECT key_id FROM aigov_key_metadata WHERE retired_at IS NULL"

    def __init__(
        self,
        backend: Literal["sqlite", "postgresql"] = "sqlite",
        path: str = "",
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

    # ---- Public API ----

    def add_key(self, key_id: str, make_current: bool = False) -> None:
        """Register a new key_id in the metadata store. No key bytes stored."""
        if self._backend == "sqlite":
            self._sqlite_add(key_id, make_current)
        else:
            self._pg_add(key_id, make_current)

    def set_current(self, key_id: str) -> None:
        """Make key_id the current signing key (atomic)."""
        if self._backend == "sqlite":
            self._sqlite_set_current(key_id)
        else:
            self._pg_set_current(key_id)

    def retire_key(self, key_id: str) -> None:
        """Retire a key — it will no longer be valid for verification."""
        current = self.current_key_id()
        if current == key_id:
            raise KeyMetadataError(
                f"Cannot retire current signing key {key_id!r}. Rotate first."
            )
        if self._backend == "sqlite":
            self._sqlite_retire(key_id)
        else:
            self._pg_retire(key_id)

    def current_key_id(self) -> str:
        if self._backend == "sqlite":
            return self._sqlite_current_id()
        return self._pg_current_id()

    def is_retired(self, key_id: str) -> bool:
        """Return True if key_id is retired or unknown."""
        if self._backend == "sqlite":
            return self._sqlite_is_retired(key_id)
        return self._pg_is_retired(key_id)

    def active_key_ids(self) -> list[str]:
        if self._backend == "sqlite":
            return self._sqlite_active_ids()
        return self._pg_active_ids()

    # ---- SQLite ----

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

    def _sqlite_add(self, key_id: str, make_current: bool) -> None:
        conn = self._sqlite_conn()
        try:
            if conn.execute(self._SQLITE_CHECK_ID, (key_id,)).fetchone():
                raise KeyMetadataError(f"Key {key_id!r} already exists")
            conn.execute(self._SQLITE_INSERT, (key_id, time.time()))
            has_current = bool(conn.execute(self._SQLITE_CURRENT_ID).fetchone())
            if make_current or not has_current:
                conn.execute(self._SQLITE_SET_CLEAR)
                conn.execute(self._SQLITE_SET_CURRENT, (key_id,))
            conn.commit()
        finally:
            conn.close()

    def _sqlite_set_current(self, key_id: str) -> None:
        conn = self._sqlite_conn()
        try:
            row = conn.execute(self._SQLITE_GET_RETIRED_AT, (key_id,)).fetchone()
            if row is None:
                raise KeyMetadataError(f"Key {key_id!r} not found")
            if row[0] is not None:
                raise KeyMetadataError(f"Key {key_id!r} is retired")
            conn.execute(self._SQLITE_SET_CLEAR)
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

    def _sqlite_current_id(self) -> str:
        conn = self._sqlite_conn()
        try:
            row = conn.execute(self._SQLITE_CURRENT_ID).fetchone()
        finally:
            conn.close()
        if row is None:
            raise KeyMetadataError("No current signing key configured")
        return row[0]

    def _sqlite_is_retired(self, key_id: str) -> bool:
        conn = self._sqlite_conn()
        try:
            row = conn.execute(self._SQLITE_GET_RETIRED_AT, (key_id,)).fetchone()
        finally:
            conn.close()
        if row is None:
            return True  # unknown key → treat as retired
        return row[0] is not None

    def _sqlite_active_ids(self) -> list[str]:
        conn = self._sqlite_conn()
        try:
            rows = conn.execute(self._SQLITE_ACTIVE_IDS).fetchall()
        finally:
            conn.close()
        return [r[0] for r in rows]

    # ---- PostgreSQL ----

    def _pg_conn(self):  # type: ignore[return]
        try:
            import psycopg
        except ImportError as exc:
            raise KeyMetadataError("psycopg[binary]>=3.3.9 required") from exc
        return psycopg.connect(self._dsn)

    def _init_postgres(self) -> None:
        try:
            with self._pg_conn() as conn:
                conn.execute(self._PG_CREATE)
                conn.commit()
        except KeyMetadataError:
            raise
        except Exception as exc:
            raise KeyMetadataError(f"PostgreSQL init failed: {exc}") from exc

    def _pg_add(self, key_id: str, make_current: bool) -> None:
        try:
            with self._pg_conn() as conn:
                if conn.execute(self._PG_CHECK_ID, (key_id,)).fetchone():
                    raise KeyMetadataError(f"Key {key_id!r} already exists")
                conn.execute(self._PG_INSERT, (key_id,))
                has_current = bool(conn.execute(self._PG_CURRENT_ID).fetchone())
                if make_current or not has_current:
                    conn.execute(self._PG_SET_CLEAR)
                    conn.execute(self._PG_SET_CURRENT, (key_id,))
                conn.commit()
        except KeyMetadataError:
            raise
        except Exception as exc:
            raise KeyMetadataError(f"PostgreSQL add_key failed: {exc}") from exc

    def _pg_set_current(self, key_id: str) -> None:
        try:
            with self._pg_conn() as conn:
                row = conn.execute(self._PG_GET_RETIRED_AT, (key_id,)).fetchone()
                if row is None:
                    raise KeyMetadataError(f"Key {key_id!r} not found")
                if row[0] is not None:
                    raise KeyMetadataError(f"Key {key_id!r} is retired")
                conn.execute(self._PG_SET_CLEAR)
                conn.execute(self._PG_SET_CURRENT, (key_id,))
                conn.commit()
        except KeyMetadataError:
            raise
        except Exception as exc:
            raise KeyMetadataError(f"PostgreSQL set_current failed: {exc}") from exc

    def _pg_retire(self, key_id: str) -> None:
        try:
            with self._pg_conn() as conn:
                conn.execute(self._PG_RETIRE, (key_id,))
                conn.commit()
        except KeyMetadataError:
            raise
        except Exception as exc:
            raise KeyMetadataError(f"PostgreSQL retire failed: {exc}") from exc

    def _pg_current_id(self) -> str:
        try:
            with self._pg_conn() as conn:
                row = conn.execute(self._PG_CURRENT_ID).fetchone()
        except Exception as exc:
            raise KeyMetadataError(f"PostgreSQL current_key_id failed: {exc}") from exc
        if row is None:
            raise KeyMetadataError("No current signing key configured")
        return row[0]

    def _pg_is_retired(self, key_id: str) -> bool:
        try:
            with self._pg_conn() as conn:
                row = conn.execute(self._PG_GET_RETIRED_AT, (key_id,)).fetchone()
        except Exception as exc:
            raise KeyMetadataError(f"PostgreSQL is_retired failed: {exc}") from exc
        if row is None:
            return True
        return row[0] is not None

    def _pg_active_ids(self) -> list[str]:
        try:
            with self._pg_conn() as conn:
                rows = conn.execute(self._PG_ACTIVE_IDS).fetchall()
        except Exception as exc:
            raise KeyMetadataError(f"PostgreSQL active_key_ids failed: {exc}") from exc
        return [r[0] for r in rows]


# ---------------------------------------------------------------------------
# KMS-backed rotating provider
# ---------------------------------------------------------------------------


class KMSBackedRotatingKeyProvider:
    """
    Production signing key provider.

    Key bytes come exclusively from the KMS (EnvKMSClient or a real KMS).
    SQL stores only rotation metadata — no key material in the database.

    is_managed = True: suppresses the ToolGateway RuntimeWarning that fires
    for InMemoryKeyProvider.

    KMS unavailability semantics:
      signing_key: raises KMSUnavailableError → token issuance fails closed
      get_verification_key: returns None → token verification fails (rejected)

    Both behaviors are fail-closed: a tool call cannot proceed without key
    material, and a token signed with an unavailable key is rejected.
    """

    is_managed: bool = True

    def __init__(
        self,
        metadata_store: SqlKeyMetadataStore,
        kms_client: KMSClientBase,
    ) -> None:
        self._meta = metadata_store
        self._kms = kms_client

    @property
    def key_id(self) -> str:
        """The key ID currently used for signing new tokens."""
        return self._meta.current_key_id()

    @property
    def signing_key(self) -> bytes:
        """
        Key bytes for the current signing key, fetched from KMS.

        Raises KMSUnavailableError if the KMS cannot provide key material.
        This propagates up through token issuance, blocking execution fail-closed.
        """
        kid = self._meta.current_key_id()
        key = self._kms.get_key(kid)
        if key is None:
            raise KMSUnavailableError(
                f"KMS returned None for current key_id={kid!r}. "
                "Ensure the env var AIGOV_SIGNING_KEY_{kid} is set, or the KMS is reachable."
            )
        return key

    def get_verification_key(self, key_id: str) -> bytes | None:
        """
        Return key bytes for key_id from KMS, or None if unavailable/retired.

        Checks retirement in SQL first: a retired key returns None immediately
        without calling the KMS (retirement takes effect instantly).
        """
        if self._meta.is_retired(key_id):
            return None
        return self._kms.get_key(key_id)

    @property
    def active_key_ids(self) -> list[str]:
        """Non-retired key IDs from SQL metadata."""
        return self._meta.active_key_ids()

    @property
    def is_distributed_safe(self) -> bool:
        """True when the metadata store uses a PostgreSQL backend."""
        return self._meta.is_distributed_safe
