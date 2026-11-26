"""The executor's durable store on PostgreSQL: shared by several executor processes and hosts, one tenant per store object.

It offers the same methods as ``store.ExecutionStore`` (the SQLite store, for one host and local development), with these
differences, each enforced in the database or in one transaction:

- Atomic claim. ``reserve`` inserts the authorization under its primary key (``ON CONFLICT DO NOTHING``). A second
  reservation of the same authorization, from any process, returns False. The authorization id is unique across tenants.
- Fencing. ``start`` increments the execution's fence counter and returns the new value. The owner must present that
  token to ``finish`` and ``mark_outcome_unknown``. A worker whose token is stale (its execution has changed hands, or
  recovery has moved it on) is refused with ``StaleWorker`` and writes nothing.
- Leases on database time. ``lease_until`` is set from the database clock (``now()``). Expiry is decided by the database,
  so a worker whose host clock is wrong can neither keep a lease alive nor make another worker's lease look expired.
- Append-only history. ``execution_events`` refuses UPDATE, DELETE, and TRUNCATE (migration 0001). Every write appends one
  hash-chained row, under the chain's advisory lock, so the chain has one order.
- Tenant isolation. Every query is scoped by the store's tenant. Another tenant's execution looks like no execution.
- Idempotent receipt recording: recording the same receipt id twice is a no-op; a different id is refused.

Lock order, the same in every transaction: the execution's row (``SELECT ... FOR UPDATE`` or the insert), then the chain's
advisory lock. Writers never take the chain lock first, so two transactions cannot wait on each other in a cycle.

Not provided here: exactly-once external side effects. The database guarantees that one execution row exists per
authorization, and that only the fence owner can finish it. It cannot make an external system apply an action once. See
``docs/trusted-execution-sdk.md`` and ``docs/architecture/distributed-execution.md``.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime
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
from .store import (
    ExecutionStoreError,
    ExecutionStoreSchemaError,
    SchemaMissing,
    SchemaVersionMismatch,
    ExecutionStoreIntegrityError,
)

SCHEMA_VERSION_PG = 1
# A fixed key for the chain's advisory lock: every history append takes it, after the execution's row lock.
CHAIN_LOCK_KEY = 0x6578656375746F72  # "executor" as 64-bit


class StaleWorker(ExecutionStoreError):
    """The caller's fence token is not the current one for this execution. Nothing was written."""


class StoreUnavailable(ExecutionStoreError):
    """The database could not be reached or a transaction could not complete. The caller must not assume an outcome."""


def _chain_hash(
    tenant: str,
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
            "tenant_id": tenant,
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


def _import_psycopg() -> Any:
    try:
        import psycopg  # optional extra: runs-postgres
    except ImportError as exc:  # pragma: no cover - environment dependent
        raise ExecutionStoreError("psycopg is not installed (pip install 'psycopg[binary]')") from exc
    return psycopg


class PostgresExecutionStore:
    """The executor store for one tenant, in a PostgreSQL database that has the version-1 schema applied."""

    def __init__(self, url: str, *, tenant: str, fault: Any = None, connect_timeout: int = 5) -> None:
        if not url:
            raise ExecutionStoreError("a PostgreSQL URL is required for the shared executor store")
        if not tenant or not tenant.strip():
            raise ExecutionStoreError("a tenant is required: every execution belongs to one tenant")
        self._url = url
        self._tenant = tenant
        self._fault = fault
        self._connect_timeout = connect_timeout
        self._check_schema()

    @property
    def tenant(self) -> str:
        return self._tenant

    @property
    def path(self) -> str:
        """A redacted description, for logs (the URL carries credentials)."""
        return f"postgresql:<redacted>/tenant={self._tenant}"

    # --- connection, schema, transactions ---------------------------------------------------------------------------

    def _connect(self) -> Any:
        psycopg = _import_psycopg()
        try:
            return psycopg.connect(self._url, autocommit=False, connect_timeout=self._connect_timeout)
        except Exception as exc:
            raise StoreUnavailable(f"executor store unavailable: {type(exc).__name__}") from exc

    def _check_schema(self) -> None:
        conn = self._connect()
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT to_regclass('public.executor_schema_migrations') IS NOT NULL")
                if not cur.fetchone()[0]:
                    raise SchemaMissing("the executor schema is not applied. Run: store_admin migrate-pg --url <url>")
                cur.execute("SELECT COALESCE(MAX(version), 0) FROM executor_schema_migrations")
                version = int(cur.fetchone()[0])
            conn.commit()
        finally:
            conn.close()
        if version == SCHEMA_VERSION_PG:
            return
        if version < SCHEMA_VERSION_PG:
            raise SchemaVersionMismatch(version, SCHEMA_VERSION_PG, "Apply the pending migrations: store_admin migrate-pg.")
        raise SchemaVersionMismatch(version, SCHEMA_VERSION_PG, "This database was migrated by a newer SDK.")

    @contextmanager
    def _txn(self) -> Iterator[Any]:
        conn = self._connect()
        try:
            cur = conn.cursor()
            yield cur
            conn.commit()
        except BaseException as exc:
            try:
                conn.rollback()
            except Exception:  # noqa: BLE001 - the original error is what matters
                pass
            if isinstance(exc, ExecutionStoreError):
                raise
            psycopg = _import_psycopg()
            if isinstance(exc, psycopg.OperationalError):
                raise StoreUnavailable(f"executor store interrupted: {type(exc).__name__}") from exc
            raise
        finally:
            conn.close()

    def _read(self, sql: str, params: tuple[Any, ...]) -> list[tuple[Any, ...]]:
        with self._txn() as cur:
            cur.execute(sql, params)
            return cur.fetchall() if cur.description else []

    def _names(self, cur: Any) -> list[str]:
        return [d[0] for d in cur.description]

    def _state_of(self, cur: Any, authorization_id: str, *, lock: bool = False) -> tuple[str, int, str | None]:
        """(state, fence, worker_id) for this tenant's execution, or raises ``no execution``."""
        cur.execute(
            "SELECT state, fence, worker_id FROM executions WHERE authorization_id = %s AND tenant_id = %s"
            + (" FOR UPDATE" if lock else ""),
            (authorization_id, self._tenant),
        )
        row = cur.fetchone()
        if row is None:
            raise ExecutionStoreError(f"no execution for {authorization_id}")
        return row[0], int(row[1]), row[2]

    def _lock_chain(self, cur: Any) -> None:
        cur.execute("SELECT pg_advisory_xact_lock(%s)", (CHAIN_LOCK_KEY,))

    def _append(
        self,
        cur: Any,
        *,
        authorization_id: str,
        event: str,
        from_state: str | None,
        to_state: str,
        actor: str,
        ts_utc: str,
        detail: dict[str, Any],
    ) -> None:
        self._lock_chain(cur)
        detail_json = json.dumps(detail, sort_keys=True, separators=(",", ":"))
        cur.execute("SELECT event_seq, event_hash FROM execution_events ORDER BY event_seq DESC LIMIT 1")
        last = cur.fetchone()
        prev_hash = last[1] if last else None
        seq = (last[0] + 1) if last else 1
        digest = _chain_hash(
            self._tenant, seq, authorization_id, event, from_state, to_state, actor, ts_utc, detail_json, prev_hash
        )
        cur.execute(
            "INSERT INTO execution_events (event_seq, tenant_id, authorization_id, event, from_state, to_state, actor, "
            "ts_utc, detail_json, prev_hash, event_hash) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
            (seq, self._tenant, authorization_id, event, from_state, to_state, actor, ts_utc, detail_json, prev_hash, digest),
        )

    def _fault_point(self, name: str) -> None:
        if self._fault is not None:
            self._fault(name)

    # --- lifecycle writes -------------------------------------------------------------------------------------------

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
        """Reserve the authorization, atomically. False if any tenant already has a record for it."""
        with self._txn() as cur:
            cur.execute(
                "INSERT INTO executions (authorization_id, tenant_id, run_id, tool_name, args_digest, state, "
                "reserved_at_utc, signed_authorization_json, executor_identity, policy_revision, receipt_state, "
                "arguments_json) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) "
                "ON CONFLICT (authorization_id) DO NOTHING RETURNING authorization_id",
                (
                    authorization_id,
                    self._tenant,
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
            if cur.fetchone() is None:
                return False
            self._append(
                cur,
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
        lease_until: str | None = None,
        lease_seconds: int = 300,
    ) -> int | None:
        """Claim a reserved execution. Returns the fence token, or None if it is not reserved (another worker has it).

        The lease is ``now()`` of the database plus ``lease_seconds``. The caller's clock plays no part in it.
        """
        with self._txn() as cur:
            cur.execute(
                "UPDATE executions SET state = %s, worker_id = %s, fence = fence + 1, "
                "lease_until = now() + make_interval(secs => %s) "
                "WHERE authorization_id = %s AND tenant_id = %s AND state = %s RETURNING fence, lease_until",
                (
                    State.STARTED.value,
                    worker_id,
                    int(lease_seconds),
                    authorization_id,
                    self._tenant,
                    State.RESERVED.value,
                ),
            )
            row = cur.fetchone()
            if row is None:
                return None
            fence = int(row[0])
            self._append(
                cur,
                authorization_id=authorization_id,
                event="started",
                from_state=State.RESERVED.value,
                to_state=State.STARTED.value,
                actor=worker_id,
                ts_utc=now,
                detail={"fence": fence, "lease_seconds": int(lease_seconds)},
            )
        return fence

    def _owned(self, cur: Any, authorization_id: str, fence: int | None, worker_id: str | None) -> str:
        """Check ownership under the row lock: the state, and that ``fence`` is current. Returns the state."""
        state, current_fence, owner = self._state_of(cur, authorization_id, lock=True)
        if fence is None:
            # No token is no claim: the caller is not the owner of this execution.
            raise StaleWorker("a fence token is required to change a started execution")
        if state != State.STARTED.value or current_fence != fence:
            raise StaleWorker(
                f"fence {fence} is not the current claim of {authorization_id} (state {state}, fence {current_fence})"
            )
        if worker_id is not None and owner != worker_id:
            raise StaleWorker(f"{worker_id} does not hold {authorization_id}")
        return state

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
        """Record the definite outcome and the pending receipt, in one transaction. Refused unless ``fence`` is current."""
        with self._txn() as cur:
            state = self._owned(cur, authorization_id, fence, None)
            target = State.SUCCEEDED if outcome == "success" else State.FAILED
            check_transition(state, target)
            cur.execute(
                "UPDATE executions SET state = %s, outcome = %s, result_digest = %s, finished_at_utc = %s, "
                "receipt_state = %s, receipt_event_id_pending = %s, lease_until = NULL "
                "WHERE authorization_id = %s AND tenant_id = %s",
                (
                    target.value,
                    outcome,
                    result_digest_hex,
                    now,
                    ReceiptState.PENDING.value,
                    receipt_event_id,
                    authorization_id,
                    self._tenant,
                ),
            )
            self._append(
                cur,
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
                    "fence": fence,
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
        """A started execution has no definite outcome. Records outcome_unknown, then reconciliation_required. Never
        retried automatically. Refused unless ``fence`` is current."""
        with self._txn() as cur:
            state = self._owned(cur, authorization_id, fence, None)
            check_transition(state, State.OUTCOME_UNKNOWN)
            cur.execute(
                "UPDATE executions SET state = %s, lease_until = NULL WHERE authorization_id = %s AND tenant_id = %s",
                (State.OUTCOME_UNKNOWN.value, authorization_id, self._tenant),
            )
            self._append(
                cur,
                authorization_id=authorization_id,
                event="outcome_unknown",
                from_state=state,
                to_state=State.OUTCOME_UNKNOWN.value,
                actor=actor,
                ts_utc=now,
                detail={"reason": reason},
            )
            self._record_reconciliation_required(cur, authorization_id, now, actor)

    def expire_lease(self, *, authorization_id: str, now: str, actor: str) -> bool:
        """Recovery: a started execution whose lease has passed (on database time) becomes outcome_unknown, then
        reconciliation_required. Returns False if the lease has not expired, or the execution is no longer started."""
        with self._txn() as cur:
            cur.execute(
                "SELECT state FROM executions WHERE authorization_id = %s AND tenant_id = %s FOR UPDATE",
                (authorization_id, self._tenant),
            )
            row = cur.fetchone()
            if row is None:
                raise ExecutionStoreError(f"no execution for {authorization_id}")
            if row[0] != State.STARTED.value:
                return False
            cur.execute(
                "SELECT lease_until IS NOT NULL AND lease_until < now() FROM executions "
                "WHERE authorization_id = %s AND tenant_id = %s",
                (authorization_id, self._tenant),
            )
            if not cur.fetchone()[0]:
                return False
            cur.execute(
                "UPDATE executions SET state = %s, lease_until = NULL WHERE authorization_id = %s AND tenant_id = %s",
                (State.OUTCOME_UNKNOWN.value, authorization_id, self._tenant),
            )
            self._append(
                cur,
                authorization_id=authorization_id,
                event="outcome_unknown",
                from_state=State.STARTED.value,
                to_state=State.OUTCOME_UNKNOWN.value,
                actor=actor,
                ts_utc=now,
                detail={"reason": "started without a recorded outcome; lease expired (database clock)"},
            )
            self._record_reconciliation_required(cur, authorization_id, now, actor)
        return True

    def _record_reconciliation_required(self, cur: Any, authorization_id: str, now: str, actor: str) -> None:
        check_transition(State.OUTCOME_UNKNOWN.value, State.RECONCILIATION_REQUIRED)
        cur.execute(
            "UPDATE executions SET state = %s WHERE authorization_id = %s AND tenant_id = %s",
            (State.RECONCILIATION_REQUIRED.value, authorization_id, self._tenant),
        )
        self._append(
            cur,
            authorization_id=authorization_id,
            event="reconciliation_required",
            from_state=State.OUTCOME_UNKNOWN.value,
            to_state=State.RECONCILIATION_REQUIRED.value,
            actor=actor,
            ts_utc=now,
            detail={"automatic_retry": False},
        )

    def fail_before_start(
        self, *, authorization_id: str, now: str, actor: str, reason: str, receipt_event_id: str
    ) -> None:
        """A reserved execution was refused before any side effect."""
        with self._txn() as cur:
            state, _fence, _owner = self._state_of(cur, authorization_id, lock=True)
            check_transition(state, State.FAILED)
            cur.execute(
                "UPDATE executions SET state = %s, outcome = %s, finished_at_utc = %s, receipt_state = %s, "
                "receipt_event_id_pending = %s WHERE authorization_id = %s AND tenant_id = %s",
                (
                    State.FAILED.value,
                    f"not_executed:{reason}",
                    now,
                    ReceiptState.PENDING.value,
                    receipt_event_id,
                    authorization_id,
                    self._tenant,
                ),
            )
            self._append(
                cur,
                authorization_id=authorization_id,
                event="refused_before_start",
                from_state=state,
                to_state=State.FAILED.value,
                actor=actor,
                ts_utc=now,
                detail={"reason": reason, "receipt_event_id": receipt_event_id},
            )

    def attach_pending_receipt(self, *, authorization_id: str, receipt_event_id: str, now: str) -> None:
        with self._txn() as cur:
            state, _f, _o = self._state_of(cur, authorization_id, lock=True)
            cur.execute(
                "SELECT receipt_state FROM executions WHERE authorization_id = %s AND tenant_id = %s",
                (authorization_id, self._tenant),
            )
            receipt_state = cur.fetchone()[0]
            if State(state) not in TERMINAL:
                raise ExecutionStoreError("only a finished execution can receive a receipt")
            check_receipt_transition(receipt_state, ReceiptState.PENDING)
            cur.execute(
                "UPDATE executions SET receipt_state = %s, receipt_event_id_pending = %s "
                "WHERE authorization_id = %s AND tenant_id = %s",
                (ReceiptState.PENDING.value, receipt_event_id, authorization_id, self._tenant),
            )
            self._append(
                cur,
                authorization_id=authorization_id,
                event="receipt_attached",
                from_state=state,
                to_state=state,
                actor="recovery",
                ts_utc=now,
                detail={"receipt_event_id": receipt_event_id},
            )

    def record_receipt_recorded(self, *, authorization_id: str, receipt_event_id: str, now: str) -> None:
        """Core acknowledged the receipt. Idempotent: recording the same id again changes nothing."""
        with self._txn() as cur:
            state, _f, _o = self._state_of(cur, authorization_id, lock=True)
            cur.execute(
                "SELECT receipt_state, receipt_event_id_pending FROM executions WHERE authorization_id = %s AND tenant_id = %s",
                (authorization_id, self._tenant),
            )
            receipt_state, pending = cur.fetchone()
            if receipt_state == ReceiptState.RECORDED.value:
                cur.execute(
                    "SELECT receipt_event_id FROM executions WHERE authorization_id = %s AND tenant_id = %s",
                    (authorization_id, self._tenant),
                )
                if cur.fetchone()[0] == receipt_event_id:
                    return  # already recorded: a duplicate delivery changes nothing
                raise ExecutionStoreError("a different receipt is already recorded for this execution")
            check_receipt_transition(receipt_state, ReceiptState.RECORDED)
            if pending != receipt_event_id:
                raise ExecutionStoreError("receipt id does not match the pending receipt for this execution")
            cur.execute(
                "UPDATE executions SET receipt_state = %s, receipt_event_id = %s WHERE authorization_id = %s AND tenant_id = %s",
                (ReceiptState.RECORDED.value, receipt_event_id, authorization_id, self._tenant),
            )
            self._append(
                cur,
                authorization_id=authorization_id,
                event="receipt_recorded",
                from_state=None,
                to_state=state,
                actor="executor",
                ts_utc=now,
                detail={"receipt_event_id": receipt_event_id},
            )

    def record_receipt(self, authorization_id: str, receipt_event_id: str) -> None:
        from datetime import UTC

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
        """Apply verified reconciliation evidence. Refuses evidence that was already applied, in any tenant."""
        with self._txn() as cur:
            state, _f, _o = self._state_of(cur, authorization_id, lock=True)
            check_transition(state, State.RECONCILED)
            digest = evidence["evidence_sha256"]
            cur.execute(
                "SELECT 1 FROM execution_events WHERE detail_json::jsonb ->> 'evidence_sha256' = %s LIMIT 1",
                (digest,),
            )
            if cur.fetchone():
                raise ExecutionStoreError("this evidence has already been applied")
            cur.execute(
                "UPDATE executions SET state = %s, reconciled_outcome = %s, receipt_state = %s, "
                "receipt_event_id_pending = %s, finished_at_utc = %s WHERE authorization_id = %s AND tenant_id = %s",
                (
                    State.RECONCILED.value,
                    outcome,
                    ReceiptState.PENDING.value,
                    receipt_event_id,
                    now,
                    authorization_id,
                    self._tenant,
                ),
            )
            self._append(
                cur,
                authorization_id=authorization_id,
                event="reconciled",
                from_state=state,
                to_state=State.RECONCILED.value,
                actor=actor,
                ts_utc=now,
                detail={**evidence, "receipt_event_id": receipt_event_id},
            )
            self._fault_point("reconcile_before_commit")

    def escalate(self, *, authorization_id: str, actor: str, now: str, reason: str, evidence: dict[str, Any]) -> None:
        with self._txn() as cur:
            state, _f, _o = self._state_of(cur, authorization_id, lock=True)
            if State(state) not in UNRESOLVED:
                raise ExecutionStoreError(f"execution is {state}; only unresolved executions are escalated")
            self._append(
                cur,
                authorization_id=authorization_id,
                event="escalated",
                from_state=state,
                to_state=state,
                actor=actor,
                ts_utc=now,
                detail={"reason": reason, **evidence},
            )

    def unwind_lease(self, *, authorization_id: str, now: str, actor: str) -> None:
        with self._txn() as cur:
            state, _f, _o = self._state_of(cur, authorization_id, lock=True)
            cur.execute(
                "UPDATE executions SET lease_until = NULL WHERE authorization_id = %s AND tenant_id = %s",
                (authorization_id, self._tenant),
            )
            self._append(
                cur,
                authorization_id=authorization_id,
                event="lease_released",
                from_state=state,
                to_state=state,
                actor=actor,
                ts_utc=now,
                detail={},
            )

    # --- reads ------------------------------------------------------------------------------------------------------

    def _rows(self, where: str, params: tuple[Any, ...], order: str = "reserved_at_utc, authorization_id") -> list[dict[str, Any]]:
        with self._txn() as cur:
            cur.execute(
                f"SELECT * FROM executions WHERE tenant_id = %s AND {where} ORDER BY {order}",
                (self._tenant, *params),
            )
            names = self._names(cur)
            return [dict(zip(names, r, strict=True)) for r in cur.fetchall()]

    def row(self, authorization_id: str) -> dict[str, Any] | None:
        rows = self._rows("authorization_id = %s", (authorization_id,))
        return rows[0] if rows else None

    def rows_in(self, states: frozenset[State]) -> list[dict[str, Any]]:
        return self._rows("state = ANY(%s)", (sorted(s.value for s in states),))

    def unresolved(self) -> list[dict[str, Any]]:
        return self.rows_in(UNRESOLVED)

    def pending_receipts(self) -> list[dict[str, Any]]:
        return self._rows("receipt_state = %s", (ReceiptState.PENDING.value,))

    def missing_receipts(self) -> list[dict[str, Any]]:
        return self._rows(
            "receipt_state = %s AND state = ANY(%s)",
            (ReceiptState.NONE.value, [State.SUCCEEDED.value, State.FAILED.value, State.RECONCILED.value]),
        )

    def all_rows(self) -> list[dict[str, Any]]:
        return self._rows("TRUE", ())

    def events(self, authorization_id: str) -> list[dict[str, Any]]:
        with self._txn() as cur:
            cur.execute(
                "SELECT event_seq, event, from_state, to_state, actor, ts_utc, detail_json, prev_hash, event_hash "
                "FROM execution_events WHERE authorization_id = %s AND tenant_id = %s ORDER BY event_seq",
                (authorization_id, self._tenant),
            )
            names = self._names(cur)
            rows = [dict(zip(names, r, strict=True)) for r in cur.fetchall()]
        for r in rows:
            r["detail"] = json.loads(r.pop("detail_json"))
        return rows

    def verify_history(self) -> tuple[bool, str]:
        """Recompute the whole chain (every tenant's events share it). A row altered by any means fails here."""
        rows = self._read(
            "SELECT event_seq, tenant_id, authorization_id, event, from_state, to_state, actor, ts_utc, detail_json, "
            "prev_hash, event_hash FROM execution_events ORDER BY event_seq",
            (),
        )
        prev: str | None = None
        for row in rows:
            seq, tenant, auth, event, frm, to, actor, ts, detail_json, prev_hash, event_hash = row
            if prev_hash != prev:
                return False, f"event {seq}: previous-hash link broken"
            expected = _chain_hash(tenant, seq, auth, event, frm, to, actor, ts, detail_json, prev_hash)
            if expected != event_hash:
                return False, f"event {seq}: content does not match its hash"
            prev = event_hash
        return True, f"{len(rows)} chained events verified"

    def verify_projection(self) -> tuple[bool, str]:
        """Each of this tenant's executions must agree with the last state its history recorded."""
        rows = self._rows("TRUE", ())
        mismatches = []
        for r in rows:
            last = self._read(
                "SELECT to_state FROM execution_events WHERE authorization_id = %s AND tenant_id = %s "
                "AND event NOT IN ('receipt_recorded', 'receipt_attached', 'lease_released', 'escalated') "
                "ORDER BY event_seq DESC LIMIT 1",
                (r["authorization_id"], self._tenant),
            )
            if not last or last[0][0] != r["state"]:
                mismatches.append(f"{r['authorization_id']}: row state {r['state']} != history {last[0][0] if last else None}")
        if mismatches:
            return False, "; ".join(mismatches[:5])
        return True, f"{len(rows)} executions agree with their history"

    def event_timestamps(self) -> list[tuple[str, str, str]]:
        return [
            (a, e, t)
            for a, e, t in self._read(
                "SELECT authorization_id, event, ts_utc FROM execution_events WHERE tenant_id = %s ORDER BY event_seq",
                (self._tenant,),
            )
        ]

    def is_terminal(self, authorization_id: str) -> bool:
        row = self.row(authorization_id)
        return row is not None and State(row["state"]) in TERMINAL


__all__ = [
    "CHAIN_LOCK_KEY",
    "ExecutionStoreIntegrityError",
    "InvalidTransition",
    "PostgresExecutionStore",
    "SCHEMA_VERSION_PG",
    "StaleWorker",
    "StoreUnavailable",
]
