"""The executor's durable store: one execution per authorization, its lifecycle, and an append-only history.

What the store guarantees:

- A reservation is atomic. A second reservation of the same authorization fails, whichever process makes it.
- Every state change is one transaction (``BEGIN IMMEDIATE``), and the transition is checked against
  ``lifecycle.ALLOWED`` inside that transaction. An illegal transition is refused, and nothing is written.
- Every change appends one row to ``execution_events``. The table cannot be updated or deleted (triggers), and each row
  carries a hash of its content and of the previous row. ``verify_history`` recomputes the chain.
- The store never creates or upgrades its schema. It refuses to open a file whose schema version is not exactly
  ``SCHEMA_VERSION``. Migrations are applied out of band by ``python -m aigov_py.trusted.store_admin``.

The store is a local SQLite file. One host. See ``docs/trusted-execution-sdk.md``, section "The executor store".
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path
from typing import Any

from .lifecycle import (
    TERMINAL,
    UNRESOLVED,
    InvalidTransition,
    ReceiptState,
    State,
    check_receipt_transition,
    check_transition,
)

SCHEMA_VERSION = 2
TABLE = "executions"


class ExecutionStoreError(RuntimeError):
    """Base class for store errors."""


class ExecutionStoreSchemaError(ExecutionStoreError):
    """The store's schema is missing or is not the version this SDK requires."""


class SchemaMissing(ExecutionStoreSchemaError):
    """The file does not exist, or has no executor schema. Apply the migrations with the operator tool first."""


class SchemaVersionMismatch(ExecutionStoreSchemaError):
    """The schema exists but is a different version. Upgrade with the operator tool, or use a matching SDK."""

    def __init__(self, found: int, expected: int, hint: str) -> None:
        super().__init__(
            f"executor store schema is version {found}, this SDK needs {expected}. {hint}"
        )
        self.found = found
        self.expected = expected


class ExecutionStoreIntegrityError(ExecutionStoreError):
    """A history chain does not verify: a row was altered or removed outside the store."""


ZERO = "0" * 64


def _chain_hash(
    seq: int,
    authorization_id: str,
    event: str,
    from_state: str | None,
    to_state: str,
    actor: str,
    ts_utc: str,
    detail_json: str,
    prev_hash: str | None,
) -> str:
    body = json.dumps(
        {
            "seq": seq,
            "authorization_id": authorization_id,
            "event": event,
            "from_state": from_state,
            "to_state": to_state,
            "actor": actor,
            "ts_utc": ts_utc,
            "detail_json": detail_json,
            "prev_hash": prev_hash,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


class ExecutionStore:
    """The executor's durable record of executions. Open an existing, migrated file."""

    def __init__(self, path: Path, *, fault: Any = None) -> None:
        self._path = Path(path)
        self._fault = fault
        self._check_schema()

    @property
    def path(self) -> Path:
        return self._path

    # --- connection and schema ----------------------------------------------------------------------------------

    def _open(self) -> sqlite3.Connection:
        uri = f"file:{self._path}?mode=rw"
        try:
            return sqlite3.connect(uri, uri=True, timeout=10.0, isolation_level=None)
        except sqlite3.OperationalError as exc:
            raise SchemaMissing(
                f"executor store {self._path} does not exist. Create and migrate it with: "
                f"python -m aigov_py.trusted.store_admin migrate --db {self._path}"
            ) from exc

    def _check_schema(self) -> None:
        c = self._open()
        try:
            version = c.execute("PRAGMA user_version").fetchone()[0]
            has_table = (
                c.execute(
                    "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?",
                    (TABLE,),
                ).fetchone()
                is not None
            )
        finally:
            c.close()
        if version == SCHEMA_VERSION:
            return
        if version == 0 and not has_table:
            raise SchemaMissing(
                f"executor store {self._path} has no executor schema. Apply the migrations first: "
                "python -m aigov_py.trusted.store_admin migrate --db <path>"
            )
        if version < SCHEMA_VERSION:
            raise SchemaVersionMismatch(
                version,
                SCHEMA_VERSION,
                "Upgrade in place: python -m aigov_py.trusted.store_admin migrate --db <path> "
                "(a backup is taken first).",
            )
        raise SchemaVersionMismatch(
            version,
            SCHEMA_VERSION,
            "This file was written by a newer SDK. Use that SDK, or a matching version.",
        )

    def _txn(self) -> _Txn:
        return _Txn(self._open())

    # --- history -------------------------------------------------------------------------------------------------

    def _append(
        self,
        c: sqlite3.Connection,
        *,
        authorization_id: str,
        event: str,
        from_state: str | None,
        to_state: str,
        actor: str,
        ts_utc: str,
        detail: dict[str, Any],
    ) -> None:
        detail_json = json.dumps(detail, sort_keys=True, separators=(",", ":"))
        last = c.execute(
            "SELECT event_seq, event_hash FROM execution_events WHERE event_hash IS NOT NULL "
            "ORDER BY event_seq DESC LIMIT 1"
        ).fetchone()
        prev_hash = last[1] if last else None
        seq = (
            c.execute(
                "SELECT COALESCE(MAX(event_seq), 0) + 1 FROM execution_events"
            ).fetchone()
        )[0]
        digest = _chain_hash(
            seq,
            authorization_id,
            event,
            from_state,
            to_state,
            actor,
            ts_utc,
            detail_json,
            prev_hash,
        )
        c.execute(
            "INSERT INTO execution_events (event_seq, authorization_id, event, from_state, to_state, actor, ts_utc, "
            "detail_json, prev_hash, event_hash) VALUES (?,?,?,?,?,?,?,?,?,?)",
            (
                seq,
                authorization_id,
                event,
                from_state,
                to_state,
                actor,
                ts_utc,
                detail_json,
                prev_hash,
                digest,
            ),
        )

    def verify_projection(self) -> tuple[bool, str]:
        """Each execution row must agree with its history: the state and receipt state must equal what the last
        transition in the history recorded. A row edited outside the store fails this check."""
        c = self._open()
        try:
            rows = c.execute(
                "SELECT authorization_id, state, receipt_state FROM executions"
            ).fetchall()
            mismatches = []
            for auth, state, receipt_state in rows:
                last = c.execute(
                    "SELECT to_state FROM execution_events WHERE authorization_id = ? "
                    "AND event NOT IN ('receipt_recorded', 'receipt_attached', 'lease_released') "
                    "ORDER BY event_seq DESC LIMIT 1",
                    (auth,),
                ).fetchone()
                if last is None or last[0] != state:
                    mismatches.append(
                        f"{auth}: row state {state} != history {last[0] if last else None}"
                    )
                    continue
                last_receipt = c.execute(
                    "SELECT event, detail_json FROM execution_events WHERE authorization_id = ? "
                    "AND event IN ('receipt_recorded') ORDER BY event_seq DESC LIMIT 1",
                    (auth,),
                ).fetchone()
                if receipt_state == "recorded" and last_receipt is None:
                    mismatches.append(
                        f"{auth}: receipt marked recorded with no receipt_recorded entry"
                    )
        finally:
            c.close()
        if mismatches:
            return False, "; ".join(mismatches[:5])
        return True, f"{len(rows)} executions agree with their history"

    def events(self, authorization_id: str) -> list[dict[str, Any]]:
        c = self._open()
        try:
            cur = c.execute(
                "SELECT event_seq, event, from_state, to_state, actor, ts_utc, detail_json, prev_hash, event_hash "
                "FROM execution_events WHERE authorization_id = ? ORDER BY event_seq",
                (authorization_id,),
            )
            names = [d[0] for d in cur.description]
            rows = [dict(zip(names, r, strict=True)) for r in cur.fetchall()]
        finally:
            c.close()
        for r in rows:
            r["detail"] = json.loads(r.pop("detail_json"))
        return rows

    def verify_history(self) -> tuple[bool, str]:
        """Recompute the hash chain over every chained event. Migrated events (no hash) are not part of the chain."""
        c = self._open()
        try:
            rows = c.execute(
                "SELECT event_seq, authorization_id, event, from_state, to_state, actor, ts_utc, detail_json, "
                "prev_hash, event_hash FROM execution_events ORDER BY event_seq"
            ).fetchall()
        finally:
            c.close()
        prev: str | None = None
        chained = 0
        for row in rows:
            seq, auth, event, frm, to, actor, ts, detail_json, prev_hash, event_hash = (
                row
            )
            if event_hash is None:
                if chained:
                    return False, f"unhashed event {seq} after the chain started"
                continue
            chained += 1
            if prev_hash != prev:
                return False, f"event {seq}: previous-hash link broken"
            expected = _chain_hash(
                seq, auth, event, frm, to, actor, ts, detail_json, prev_hash
            )
            if expected != event_hash:
                return False, f"event {seq}: content does not match its hash"
            prev = event_hash
        return True, f"{chained} chained events verified"

    # --- lifecycle writes ----------------------------------------------------------------------------------------

    def reserve(
        self,
        *,
        authorization_id: str,
        run_id: str,
        tool: str,
        digest: str,
        signed_json: str,
        now: str,
        executor_identity: str | None = None,
        policy_revision: str | None = None,
        arguments_json: str | None = None,
    ) -> bool:
        """Authorization received and reserved, atomically. Returns False if this authorization already has a record.

        ``arguments_json`` is stored so that a reservation that never started can be resumed after a crash. Its digest
        must match ``digest``; recovery checks that before acting.
        """
        with self._txn() as c:
            if c.execute(
                "SELECT 1 FROM executions WHERE authorization_id = ?",
                (authorization_id,),
            ).fetchone():
                return False
            c.execute(
                "INSERT INTO executions (authorization_id, run_id, tool_name, args_digest, state, reserved_at_utc, "
                "signed_authorization_json, executor_identity, policy_revision, receipt_state, arguments_json) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (
                    authorization_id,
                    run_id,
                    tool,
                    digest,
                    State.RESERVED.value,
                    now,
                    signed_json,
                    executor_identity,
                    policy_revision,
                    ReceiptState.NONE.value,
                    arguments_json,
                ),
            )
            self._append(
                c,
                authorization_id=authorization_id,
                event="reserved",
                from_state=None,
                to_state=State.RESERVED.value,
                actor=executor_identity or "executor",
                ts_utc=now,
                detail={
                    "authorization_received": True,
                    "run_id": run_id,
                    "tool_name": tool,
                    "args_binding_hash": digest,
                    "policy_revision": policy_revision,
                },
            )
        return True

    def start(
        self,
        *,
        authorization_id: str,
        worker_id: str,
        now: str,
        lease_until: str,
        lease_seconds: int | None = None,
    ) -> bool:
        """Mark the side effect as about to begin. Written before the performer is called. Returns False if another
        worker has already started this execution, or it is not reserved."""
        with self._txn() as c:
            row = c.execute(
                "SELECT state FROM executions WHERE authorization_id = ?",
                (authorization_id,),
            ).fetchone()
            if row is None:
                raise ExecutionStoreError(f"no execution for {authorization_id}")
            try:
                check_transition(row[0], State.STARTED)
            except InvalidTransition:
                return False
            c.execute(
                "UPDATE executions SET state = ?, worker_id = ?, lease_until_utc = ? WHERE authorization_id = ?",
                (State.STARTED.value, worker_id, lease_until, authorization_id),
            )
            self._append(
                c,
                authorization_id=authorization_id,
                event="started",
                from_state=row[0],
                to_state=State.STARTED.value,
                actor=worker_id,
                ts_utc=now,
                detail={"lease_until_utc": lease_until},
            )
        return True

    def finish(
        self,
        *,
        authorization_id: str,
        outcome: str,
        result_digest_hex: str | None,
        now: str,
        receipt_event_id: str,
        worker_id: str = "executor",
        fence: int | None = None,
    ) -> None:
        """Record the definite outcome and the pending receipt, in one transaction."""
        with self._txn() as c:
            state = _state_of(c, authorization_id)
            target = State.SUCCEEDED if outcome == "success" else State.FAILED
            check_transition(state, target)
            c.execute(
                "UPDATE executions SET state = ?, outcome = ?, result_digest = ?, finished_at_utc = ?, "
                "receipt_state = ?, receipt_event_id_pending = ?, lease_until_utc = NULL WHERE authorization_id = ?",
                (
                    target.value,
                    outcome,
                    result_digest_hex,
                    now,
                    ReceiptState.PENDING.value,
                    receipt_event_id,
                    authorization_id,
                ),
            )
            self._append(
                c,
                authorization_id=authorization_id,
                event="finished",
                from_state=state,
                to_state=target.value,
                actor=worker_id,
                ts_utc=now,
                detail={
                    "outcome": outcome,
                    "result_digest": result_digest_hex,
                    "receipt_event_id": receipt_event_id,
                },
            )

    def mark_outcome_unknown(
        self,
        *,
        authorization_id: str,
        now: str,
        actor: str,
        reason: str,
        fence: int | None = None,
    ) -> None:
        """A started execution has no definite outcome. Records outcome_unknown, then reconciliation_required.
        Neither state is ever retried automatically."""
        with self._txn() as c:
            state = _state_of(c, authorization_id)
            check_transition(state, State.OUTCOME_UNKNOWN)
            c.execute(
                "UPDATE executions SET state = ?, lease_until_utc = NULL WHERE authorization_id = ?",
                (State.OUTCOME_UNKNOWN.value, authorization_id),
            )
            self._append(
                c,
                authorization_id=authorization_id,
                event="outcome_unknown",
                from_state=state,
                to_state=State.OUTCOME_UNKNOWN.value,
                actor=actor,
                ts_utc=now,
                detail={"reason": reason},
            )
            check_transition(State.OUTCOME_UNKNOWN.value, State.RECONCILIATION_REQUIRED)
            c.execute(
                "UPDATE executions SET state = ? WHERE authorization_id = ?",
                (State.RECONCILIATION_REQUIRED.value, authorization_id),
            )
            self._append(
                c,
                authorization_id=authorization_id,
                event="reconciliation_required",
                from_state=State.OUTCOME_UNKNOWN.value,
                to_state=State.RECONCILIATION_REQUIRED.value,
                actor=actor,
                ts_utc=now,
                detail={"automatic_retry": False},
            )

    def fail_before_start(
        self,
        *,
        authorization_id: str,
        now: str,
        actor: str,
        reason: str,
        receipt_event_id: str,
    ) -> None:
        """A reserved execution was refused before any side effect (revoked, expired, not authorized)."""
        with self._txn() as c:
            state = _state_of(c, authorization_id)
            check_transition(state, State.FAILED)
            c.execute(
                "UPDATE executions SET state = ?, outcome = ?, finished_at_utc = ?, receipt_state = ?, "
                "receipt_event_id_pending = ? WHERE authorization_id = ?",
                (
                    State.FAILED.value,
                    f"not_executed:{reason}",
                    now,
                    ReceiptState.PENDING.value,
                    receipt_event_id,
                    authorization_id,
                ),
            )
            self._append(
                c,
                authorization_id=authorization_id,
                event="refused_before_start",
                from_state=state,
                to_state=State.FAILED.value,
                actor=actor,
                ts_utc=now,
                detail={"reason": reason, "receipt_event_id": receipt_event_id},
            )

    def attach_pending_receipt(
        self, *, authorization_id: str, receipt_event_id: str, now: str
    ) -> None:
        """Give a finished execution with no receipt a pending receipt. Used when recovering rows written before v2
        and when a receipt was never written. The receipt content is derived from the row; nothing is executed."""
        with self._txn() as c:
            row = c.execute(
                "SELECT state, receipt_state FROM executions WHERE authorization_id = ?",
                (authorization_id,),
            ).fetchone()
            if row is None:
                raise ExecutionStoreError(f"no execution for {authorization_id}")
            if State(row[0]) not in TERMINAL:
                raise ExecutionStoreError(
                    "only a finished execution can receive a receipt"
                )
            check_receipt_transition(row[1], ReceiptState.PENDING)
            c.execute(
                "UPDATE executions SET receipt_state = ?, receipt_event_id_pending = ? WHERE authorization_id = ?",
                (ReceiptState.PENDING.value, receipt_event_id, authorization_id),
            )
            self._append(
                c,
                authorization_id=authorization_id,
                event="receipt_attached",
                from_state=row[0],
                to_state=row[0],
                actor="recovery",
                ts_utc=now,
                detail={"receipt_event_id": receipt_event_id},
            )

    def record_receipt_recorded(
        self, *, authorization_id: str, receipt_event_id: str, now: str
    ) -> None:
        """Core acknowledged the receipt. Pending -> recorded. The id must be the one stored when the outcome was written."""
        with self._txn() as c:
            row = c.execute(
                "SELECT receipt_state, receipt_event_id_pending FROM executions WHERE authorization_id = ?",
                (authorization_id,),
            ).fetchone()
            if row is None:
                raise ExecutionStoreError(f"no execution for {authorization_id}")
            check_receipt_transition(row[0], ReceiptState.RECORDED)
            if row[1] != receipt_event_id:
                raise ExecutionStoreError(
                    "receipt id does not match the pending receipt for this execution"
                )
            c.execute(
                "UPDATE executions SET receipt_state = ?, receipt_event_id = ? WHERE authorization_id = ?",
                (ReceiptState.RECORDED.value, receipt_event_id, authorization_id),
            )
            self._append(
                c,
                authorization_id=authorization_id,
                event="receipt_recorded",
                from_state=None,
                to_state=_state_of(c, authorization_id),
                actor="executor",
                ts_utc=now,
                detail={"receipt_event_id": receipt_event_id},
            )

    def record_receipt(self, authorization_id: str, receipt_event_id: str) -> None:
        """Backward-compatible form of ``record_receipt_recorded`` for callers that do not track the time."""
        from datetime import UTC, datetime

        self.record_receipt_recorded(
            authorization_id=authorization_id,
            receipt_event_id=receipt_event_id,
            now=datetime.now(UTC).isoformat(),
        )

    def reconcile(
        self,
        *,
        authorization_id: str,
        outcome: str,
        evidence: dict[str, Any],
        now: str,
        actor: str,
        receipt_event_id: str,
    ) -> None:
        """Apply an already-verified reconciliation. reconciliation_required -> reconciled, with the evidence appended.

        The caller verifies the signed evidence (``reconcile.verify_reconciliation``). This method repeats the state
        check inside the transaction, and refuses evidence it has already seen.
        """
        with self._txn() as c:
            state = _state_of(c, authorization_id)
            check_transition(state, State.RECONCILED)
            digest = evidence["evidence_sha256"]
            seen = c.execute(
                "SELECT 1 FROM execution_events WHERE json_extract(detail_json, '$.evidence_sha256') = ?",
                (digest,),
            ).fetchone()
            if seen:
                raise ExecutionStoreError("this evidence has already been applied")
            c.execute(
                "UPDATE executions SET state = ?, reconciled_outcome = ?, receipt_state = ?, "
                "receipt_event_id_pending = ?, finished_at_utc = ? WHERE authorization_id = ?",
                (
                    State.RECONCILED.value,
                    outcome,
                    ReceiptState.PENDING.value,
                    receipt_event_id,
                    now,
                    authorization_id,
                ),
            )
            self._append(
                c,
                authorization_id=authorization_id,
                event="reconciled",
                from_state=state,
                to_state=State.RECONCILED.value,
                actor=actor,
                ts_utc=now,
                detail={**evidence, "receipt_event_id": receipt_event_id},
            )
            if self._fault is not None:
                self._fault(
                    "reconcile_before_commit"
                )  # test hook: a crash here must leave nothing behind

    def escalate(
        self,
        *,
        authorization_id: str,
        actor: str,
        now: str,
        reason: str,
        evidence: dict[str, Any],
    ) -> None:
        """Flag an unresolved execution for manual investigation. Changes no state; appends to the history."""
        with self._txn() as c:
            state = _state_of(c, authorization_id)
            if State(state) not in UNRESOLVED:
                raise ExecutionStoreError(
                    f"execution is {state}; only unresolved executions are escalated"
                )
            self._append(
                c,
                authorization_id=authorization_id,
                event="escalated",
                from_state=state,
                to_state=state,
                actor=actor,
                ts_utc=now,
                detail={"reason": reason, **evidence},
            )

    def unwind_lease(self, *, authorization_id: str, now: str, actor: str) -> None:
        """Remove a stale lease marker without a state change. Used when recovery has resolved the row another way."""
        with self._txn() as c:
            c.execute(
                "UPDATE executions SET lease_until_utc = NULL WHERE authorization_id = ?",
                (authorization_id,),
            )
            self._append(
                c,
                authorization_id=authorization_id,
                event="lease_released",
                from_state=_state_of(c, authorization_id),
                to_state=_state_of(c, authorization_id),
                actor=actor,
                ts_utc=now,
                detail={},
            )

    # --- reads ---------------------------------------------------------------------------------------------------

    def row(self, authorization_id: str) -> dict[str, Any] | None:
        c = self._open()
        try:
            cur = c.execute(
                "SELECT * FROM executions WHERE authorization_id = ?",
                (authorization_id,),
            )
            names = [d[0] for d in cur.description]
            r = cur.fetchone()
        finally:
            c.close()
        return None if r is None else dict(zip(names, r, strict=True))

    def rows_in(self, states: frozenset[State]) -> list[dict[str, Any]]:
        marks = ",".join("?" for _ in states)
        c = self._open()
        try:
            cur = c.execute(
                f"SELECT * FROM executions WHERE state IN ({marks}) ORDER BY reserved_at_utc, authorization_id",
                tuple(s.value for s in states),
            )
            names = [d[0] for d in cur.description]
            return [dict(zip(names, r, strict=True)) for r in cur.fetchall()]
        finally:
            c.close()

    def unresolved(self) -> list[dict[str, Any]]:
        return self.rows_in(UNRESOLVED)

    def pending_receipts(self) -> list[dict[str, Any]]:
        c = self._open()
        try:
            cur = c.execute(
                "SELECT * FROM executions WHERE receipt_state = ? ORDER BY reserved_at_utc",
                (ReceiptState.PENDING.value,),
            )
            names = [d[0] for d in cur.description]
            return [dict(zip(names, r, strict=True)) for r in cur.fetchall()]
        finally:
            c.close()

    def missing_receipts(self) -> list[dict[str, Any]]:
        """Finished executions with no receipt at all (for example a legacy row, or one whose outcome was never recorded)."""
        c = self._open()
        try:
            cur = c.execute(
                "SELECT * FROM executions WHERE receipt_state = ? AND state IN (?, ?, ?) ORDER BY reserved_at_utc",
                (
                    ReceiptState.NONE.value,
                    State.SUCCEEDED.value,
                    State.FAILED.value,
                    State.RECONCILED.value,
                ),
            )
            names = [d[0] for d in cur.description]
            return [dict(zip(names, r, strict=True)) for r in cur.fetchall()]
        finally:
            c.close()

    def all_rows(self) -> list[dict[str, Any]]:
        c = self._open()
        try:
            cur = c.execute(
                "SELECT * FROM executions ORDER BY reserved_at_utc, authorization_id"
            )
            names = [d[0] for d in cur.description]
            return [dict(zip(names, r, strict=True)) for r in cur.fetchall()]
        finally:
            c.close()

    def event_timestamps(self) -> list[tuple[str, str, str]]:
        """(authorization_id, event, ts_utc) for every history entry, in order. For latency reporting."""
        c = self._open()
        try:
            return [
                (a, e, t)
                for a, e, t in c.execute(
                    "SELECT authorization_id, event, ts_utc FROM execution_events ORDER BY event_seq"
                ).fetchall()
            ]
        finally:
            c.close()

    def is_terminal(self, authorization_id: str) -> bool:
        row = self.row(authorization_id)
        return row is not None and State(row["state"]) in TERMINAL


class _Txn:
    """``BEGIN IMMEDIATE`` ... ``COMMIT``, or ``ROLLBACK`` on any exception. Serialises writers across processes."""

    def __init__(self, conn: sqlite3.Connection) -> None:
        self._c = conn

    def __enter__(self) -> sqlite3.Connection:
        self._c.execute("BEGIN IMMEDIATE")
        return self._c

    def __exit__(self, exc_type, exc, tb) -> bool:  # type: ignore[no-untyped-def]
        try:
            if exc_type is None:
                self._c.execute("COMMIT")
            else:
                self._c.execute("ROLLBACK")
        finally:
            self._c.close()
        return False


def _state_of(c: sqlite3.Connection, authorization_id: str) -> str:
    row = c.execute(
        "SELECT state FROM executions WHERE authorization_id = ?", (authorization_id,)
    ).fetchone()
    if row is None:
        raise ExecutionStoreError(f"no execution for {authorization_id}")
    return row[0]
