"""Execution store: the executor's single-use record of each authorization.

A reservation is made before any side effect, atomically (``BEGIN IMMEDIATE``). A second reservation of the same
authorization fails, which is how replay is refused at the executor. The store is local SQLite, so it is one host.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any


class ExecutionStoreSchemaError(RuntimeError):
    """The executor store's table is missing. Apply the migration first; the SDK never creates it."""


def executor_store_migration() -> str:
    """The version-1 migration text. An operator applies it once, before the store is first used."""
    from importlib.resources import files

    return (
        files("aigov_py.trusted") / "migrations" / "0001_executor_store.sql"
    ).read_text(encoding="utf-8")


class ExecutionStore:
    """The executor's single-use record. A reservation is made before any side effect, atomically.

    The table must already exist (see ``executor_store_migration``). This class does not create it.
    """

    def __init__(self, path: Path) -> None:
        self._path = Path(path)
        with self._conn() as c:
            found = c.execute(
                "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'executions'"
            ).fetchone()
        if found is None:
            raise ExecutionStoreSchemaError(
                f"executor store {self._path} has no 'executions' table. Apply executor_store_migration() "
                "to it once, before first use."
            )

    def _conn(self) -> sqlite3.Connection:
        return sqlite3.connect(self._path, timeout=10.0, isolation_level=None)

    def reserve(
        self,
        *,
        authorization_id: str,
        run_id: str,
        tool: str,
        digest: str,
        signed_json: str,
        now: str,
    ) -> bool:
        """Atomically reserve. Returns False if this authorization was already reserved (a replay)."""
        c = self._conn()
        try:
            c.execute("BEGIN IMMEDIATE")
            try:
                c.execute(
                    "INSERT INTO executions (authorization_id, run_id, tool_name, args_digest, state, reserved_at_utc, "
                    "signed_authorization_json) VALUES (?,?,?,?,?,?,?)",
                    (
                        authorization_id,
                        run_id,
                        tool,
                        digest,
                        "reserved",
                        now,
                        signed_json,
                    ),
                )
            except sqlite3.IntegrityError:
                c.execute("ROLLBACK")
                return False
            c.execute("COMMIT")
            return True
        finally:
            c.close()

    def finish(
        self,
        authorization_id: str,
        *,
        outcome: str,
        result_digest_hex: str | None,
        now: str,
    ) -> None:
        with self._conn() as c:
            c.execute(
                "UPDATE executions SET state=?, finished_at_utc=?, outcome=?, result_digest=? WHERE authorization_id=?",
                (
                    "executed" if outcome == "success" else "failed",
                    now,
                    outcome,
                    result_digest_hex,
                    authorization_id,
                ),
            )

    def record_receipt(self, authorization_id: str, receipt_event_id: str) -> None:
        with self._conn() as c:
            c.execute(
                "UPDATE executions SET receipt_event_id=? WHERE authorization_id=?",
                (receipt_event_id, authorization_id),
            )

    def row(self, authorization_id: str) -> dict[str, Any] | None:
        with self._conn() as c:
            cur = c.execute(
                "SELECT * FROM executions WHERE authorization_id=?", (authorization_id,)
            )
            names = [d[0] for d in cur.description]
            r = cur.fetchone()
        return None if r is None else dict(zip(names, r, strict=True))
