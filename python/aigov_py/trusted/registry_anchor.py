"""Independent monotonic anchor for the trusted key registry (PostgreSQL).

The anchor records, for one registry, the sequence number and head hash of the last event that was committed. It lives in
the PostgreSQL database that Core already uses (table ``key_registry_anchor``, created by migration
``0004_key_registry_anchor``), outside the registry's files. A writer of the log cannot change it by editing those files.
Readers require the log to match the anchor exactly. Anything else fails closed.

Writers take a row lock (``SELECT ... FOR UPDATE``) for the whole append-and-commit, so writers on different hosts serialize.
This module contains no schema statements: the table is created by the migration, and a missing table is refused.

Write protocol (see ``KeyRegistry._submit``): take the anchor's exclusive transaction, verify the log against the anchor,
append the event (fsync), compare-and-swap the anchor to the new head, commit. A crash between the append and the commit
rolls the transaction back and leaves the log one event ahead of the anchor. Readers refuse that state
(``anchor_log_ahead``) until ``reconcile`` verifies the extra event and anchors it.
"""

from __future__ import annotations

import contextlib
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any

GENESIS = "GENESIS"

class AnchorError(Exception):
    """The anchor could not be read or written. Callers treat this as a refusal."""

    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class AnchorState:
    seq: int
    head_hash: str


class _Tx:
    """A transaction on the anchor row. ``set`` is a compare-and-swap against the state the caller read."""

    def __init__(self, conn: Any, registry_id: str, placeholder: str) -> None:
        self._conn = conn
        self._id = registry_id
        self._ph = placeholder

    def current(self) -> AnchorState | None:
        cur = self._conn.cursor()
        cur.execute(
            f"SELECT seq, head_hash FROM key_registry_anchor WHERE registry_id = {self._ph} "
            + ("FOR UPDATE" if self._ph == "%s" else ""),
            (self._id,),
        )
        row = cur.fetchone()
        return AnchorState(int(row[0]), str(row[1])) if row else None

    def set(self, new: AnchorState, *, expected: AnchorState | None) -> None:
        cur = self._conn.cursor()
        if expected is None:
            raise AnchorError("anchor_missing", "the anchor must be initialized before it is advanced")
        cur.execute(
            f"UPDATE key_registry_anchor SET seq = {self._ph}, head_hash = {self._ph} "
            f"WHERE registry_id = {self._ph} AND seq = {self._ph} AND head_hash = {self._ph}",
            (new.seq, new.head_hash, self._id, expected.seq, expected.head_hash),
        )
        if cur.rowcount != 1:
            raise AnchorError("anchor_conflict", "the anchor moved since it was read; nothing was committed")


class PostgresAnchor:
    """The production anchor. ``url`` is a PostgreSQL URL; the registry id scopes the row."""

    def __init__(self, url: str, registry_id: str) -> None:
        if not url:
            raise AnchorError("anchor_not_configured", "a PostgreSQL URL is required for the registry anchor")
        self._url = url
        self._id = registry_id

    def _connect(self) -> Any:
        try:
            import psycopg  # optional extra: runs-postgres
        except ImportError as exc:  # pragma: no cover - depends on the environment
            raise AnchorError("anchor_unavailable", "psycopg is not installed") from exc
        try:
            return psycopg.connect(self._url, autocommit=False)
        except Exception as exc:
            raise AnchorError("anchor_unavailable", type(exc).__name__) from exc

    def current(self) -> AnchorState | None:
        conn = self._connect()
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT seq, head_hash FROM key_registry_anchor WHERE registry_id = %s", (self._id,))
                row = cur.fetchone()
            conn.commit()
            return AnchorState(int(row[0]), str(row[1])) if row else None
        finally:
            conn.close()

    def init(self) -> None:
        """Create the anchor row at genesis. Refused if the row already exists or the table is missing (migration)."""
        conn = self._connect()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO key_registry_anchor (registry_id, seq, head_hash) VALUES (%s, 0, %s) "
                    "ON CONFLICT (registry_id) DO NOTHING",
                    (self._id, GENESIS),
                )
                if cur.rowcount != 1:
                    raise AnchorError("anchor_exists", "the anchor is already initialized")
            conn.commit()
        except AnchorError:
            conn.rollback()
            raise
        except Exception as exc:
            conn.rollback()
            if type(exc).__name__ == "UndefinedTable":
                raise AnchorError("anchor_table_missing", "apply migration 0004_key_registry_anchor first") from exc
            raise AnchorError("anchor_unavailable", type(exc).__name__) from exc
        finally:
            conn.close()

    @contextlib.contextmanager
    def exclusive(self) -> Iterator[_Tx]:
        conn = self._connect()
        try:
            yield _Tx(conn, self._id, "%s")
            conn.commit()
        except BaseException:
            conn.rollback()
            raise
        finally:
            conn.close()
