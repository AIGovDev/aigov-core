"""TEST-ONLY anchor in SQLite, with the same contract as ``registry_anchor.PostgresAnchor``. Not shipped.

It exists so that unit tests can exercise the registry logic without a database. Production never uses it.
"""

from __future__ import annotations

import contextlib
import sqlite3
from collections.abc import Iterator
from pathlib import Path

from aigov_py.trusted.registry_anchor import GENESIS, AnchorError, AnchorState


class SqliteAnchor:
    """Test and single-host anchor with the same contract. A separate file from the registry's log."""

    def __init__(self, path: Path, registry_id: str) -> None:
        self._path = Path(path)
        self._id = registry_id

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._path, isolation_level=None, timeout=30)
        conn.execute(
            "CREATE TABLE IF NOT EXISTS key_registry_anchor (registry_id TEXT PRIMARY KEY, seq INTEGER NOT NULL, "
            "head_hash TEXT NOT NULL)"
        )
        return conn

    def current(self) -> AnchorState | None:
        conn = self._connect()
        try:
            row = conn.execute("SELECT seq, head_hash FROM key_registry_anchor WHERE registry_id = ?", (self._id,)).fetchone()
            return AnchorState(int(row[0]), str(row[1])) if row else None
        finally:
            conn.close()

    def init(self) -> None:
        conn = self._connect()
        try:
            cur = conn.execute(
                "INSERT OR IGNORE INTO key_registry_anchor (registry_id, seq, head_hash) VALUES (?, 0, ?)",
                (self._id, GENESIS),
            )
            if cur.rowcount != 1:
                raise AnchorError("anchor_exists", "the anchor is already initialized")
        finally:
            conn.close()

    @contextlib.contextmanager
    def exclusive(self) -> Iterator[_SqliteTx]:
        conn = self._connect()
        conn.execute("BEGIN IMMEDIATE")
        try:
            yield _SqliteTx(conn, self._id)
            conn.execute("COMMIT")
        except BaseException:
            conn.execute("ROLLBACK")
            raise
        finally:
            conn.close()


class _SqliteTx:
    def __init__(self, conn: sqlite3.Connection, registry_id: str) -> None:
        self._conn = conn
        self._id = registry_id

    def current(self) -> AnchorState | None:
        row = self._conn.execute("SELECT seq, head_hash FROM key_registry_anchor WHERE registry_id = ?", (self._id,)).fetchone()
        return AnchorState(int(row[0]), str(row[1])) if row else None

    def set(self, new: AnchorState, *, expected: AnchorState | None) -> None:
        if expected is None:
            raise AnchorError("anchor_missing", "the anchor must be initialized before it is advanced")
        cur = self._conn.execute(
            "UPDATE key_registry_anchor SET seq = ?, head_hash = ? WHERE registry_id = ? AND seq = ? AND head_hash = ?",
            (new.seq, new.head_hash, self._id, expected.seq, expected.head_hash),
        )
        if cur.rowcount != 1:
            raise AnchorError("anchor_conflict", "the anchor moved since it was read; nothing was committed")
