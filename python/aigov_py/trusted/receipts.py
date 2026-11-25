"""Execution receipt delivery: evidence only. Delivering a receipt never runs the side effect.

A receipt is written to the store with its event id in the same transaction as the outcome (state ``pending``). Delivery
submits that event to Core, and marks it ``recorded`` once Core acknowledges it.

Retrying is safe because of two rules:

- Core rejects a duplicate event id (409). A timeout may mean Core already stored the event. Both cases are settled by
  looking the event up in the run's export. The event is resubmitted only if the export does not contain it.
- Nothing here calls the performer. The receipt's content is derived from the stored row, so a resubmission is the same
  evidence, not new evidence.
"""

from __future__ import annotations

import hashlib
import logging
import time
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from aigov_py.canonical_json import canonical_bytes

from .core import CoreClient, CoreDecision, Decision, new_event
from .lifecycle import State
from .store import ExecutionStore

log = logging.getLogger("aigov_py.trusted.receipts")


def receipt_payload(row: dict[str, Any]) -> dict[str, Any]:
    """The receipt's content, derived only from the stored row.

    Core requires a non-empty result digest. An execution that produced no result data (a failure, a refusal before
    start, or a reconciled outcome) still has one: a digest of its recorded outcome. It is deterministic, so a
    resubmitted receipt is the same evidence.
    """
    outcome = row["outcome"] or ""
    if row["state"] == State.RECONCILED.value:
        outcome = f"reconciled:{row['reconciled_outcome']}"
    result_digest = (
        row["result_digest"]
        or hashlib.sha256(
            canonical_bytes(
                {"authorization_id": row["authorization_id"], "outcome": outcome}
            )
        ).hexdigest()
    )
    return {
        "execution_authorization_id": row["authorization_id"],
        "tool_name": row["tool_name"],
        "args_binding_hash": row["args_digest"],
        "outcome": outcome,
        "result_digest": result_digest,
    }


def receipt_in_export(core: CoreClient, run_id: str, event_id: str) -> bool | None:
    """True or False if Core answered. None if Core could not be asked."""
    try:
        export = core.export(run_id)
    except (OSError, RuntimeError):
        return None
    return any(e.get("event_id") == event_id for e in export.get("evidence_events", []))


def deliver(
    store: ExecutionStore,
    core: CoreClient,
    *,
    run_id: str,
    authorization_id: str,
    clock: Callable[[], float] = time.time,
    fault: Callable[[str], None] | None = None,
) -> bool:
    """Send one stored receipt to Core. Returns True once it is recorded. Never repeats the action."""
    row = store.row(authorization_id)
    if row is None or not row["receipt_event_id_pending"]:
        return False
    receipt_id = row["receipt_event_id_pending"]
    event = new_event(
        "execution_receipt",
        run_id,
        receipt_payload(row),
        event_id=receipt_id,
        actor=core.actor,
        system=core.system,
    )
    decision: CoreDecision = core.submit(event)
    if fault is not None:
        fault("after_receipt_submitted_before_ack")
    now = datetime.fromtimestamp(clock(), tz=UTC).isoformat()
    if decision.decision == Decision.ALLOW:
        store.record_receipt_recorded(
            authorization_id=authorization_id, receipt_event_id=receipt_id, now=now
        )
        log.info(
            '{"event": "receipt_recorded", "authorization_id": "%s"}', authorization_id
        )
        return True
    if receipt_in_export(core, run_id, receipt_id):
        store.record_receipt_recorded(
            authorization_id=authorization_id, receipt_event_id=receipt_id, now=now
        )
        log.info(
            '{"event": "receipt_recorded", "authorization_id": "%s", "via": "export"}',
            authorization_id,
        )
        return True
    log.info(
        '{"event": "receipt_pending", "authorization_id": "%s", "reason": "%s"}',
        authorization_id,
        decision.reason,
    )
    return False


def deliver_pending(
    store: ExecutionStore,
    core: CoreClient,
    *,
    run_id: str | None = None,
    clock: Callable[[], float] = time.time,
) -> list[dict[str, Any]]:
    """Resubmit every pending receipt (and the receipt of every finished execution that has none). No action runs."""
    results: list[dict[str, Any]] = []
    for row in store.pending_receipts():
        if run_id is not None and row["run_id"] != run_id:
            continue
        ok = deliver(
            store,
            core,
            run_id=row["run_id"],
            authorization_id=row["authorization_id"],
            clock=clock,
        )
        results.append(
            {
                "authorization_id": row["authorization_id"],
                "run_id": row["run_id"],
                "recorded": ok,
            }
        )
    return results
