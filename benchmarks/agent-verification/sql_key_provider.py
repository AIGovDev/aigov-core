"""
SqlRotatingKeyProvider — shared key provider backed by SqlKeyStore.

Implements the same interface as RotatingKeyProvider but reads all key
operations from a SQL database, making it safe to share across worker
processes. Any process that uses a SqlKeyStore pointing at the same
database automatically sees key additions, rotations, and retirements
performed by any other process.

is_managed = True: suppresses the ToolGateway RuntimeWarning that fires
when InMemoryKeyProvider is used in production.

Zero-downtime rotation recipe:
  1. Add new key to the store (store.add_key("v2", key_bytes)).
  2. Set it current (store.set_current("v2")).
     All processes now sign new tokens with v2.
     All processes still verify old tokens signed with v1.
  3. Wait for all in-flight v1 tokens to expire (≤ EAT TTL, typically 500ms).
  4. Retire the old key (store.retire_key("v1")).
     All processes now reject tokens signed with v1.

Production note:
  For a true KMS-backed provider, replace SqlKeyStore's key_bytes column
  with a KMS reference and override get_key_bytes() to call the KMS at
  verification time. The SqlKeyStore still manages metadata (rotation state,
  retirement timestamps). The provider interface is unchanged.
"""

from __future__ import annotations

from sql_key_store import SqlKeyStore, KeyStoreError


class SqlRotatingKeyProvider:
    """
    Multi-key provider backed by a shared SqlKeyStore.

    is_managed = True: informs ToolGateway that this provider is production-
    suitable. The RuntimeWarning that fires for InMemoryKeyProvider is
    suppressed when is_managed is True.

    Thread-safe: all state is in the SQL store (no in-process cache).
    Every property read hits the database, which is correct for correctness
    (a retired key is immediately invisible to this provider). If the extra
    round-trips are unacceptable for high-throughput workloads, add a short
    TTL cache here — but never cache retirement state.
    """

    is_managed: bool = True

    def __init__(self, store: SqlKeyStore) -> None:
        self._store = store

    @property
    def key_id(self) -> str:
        """The key ID currently used for signing new tokens."""
        return self._store.current_key_id()

    @property
    def signing_key(self) -> bytes:
        """The key bytes currently used for signing new tokens."""
        kid = self._store.current_key_id()
        key = self._store.get_key_bytes(kid)
        if key is None:
            raise KeyStoreError(f"Current key {kid!r} returned None bytes (retired?)")
        return key

    def get_verification_key(self, key_id: str) -> bytes | None:
        """
        Return key bytes for key_id, or None if unknown / retired.

        None immediately invalidates all tokens signed with key_id.
        """
        return self._store.get_key_bytes(key_id)

    @property
    def active_key_ids(self) -> list[str]:
        """All non-retired key IDs (available for verification)."""
        return self._store.active_key_ids()

    @property
    def is_distributed_safe(self) -> bool:
        """True when backed by a PostgreSQL store."""
        return self._store.is_distributed_safe
