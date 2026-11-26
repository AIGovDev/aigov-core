"""Structured operational visibility for the executor store, built from the store's own state and history.

No external monitoring is introduced. The report reads the durable store, so it is correct after a restart and needs no
running executor. Latency is computed from the timestamps the history already records:

- start latency: reserved -> started (how long a reservation waited before its side effect was allowed to begin)
- execution duration: started -> finished (the performer's own time, as the executor saw it)
- receipt delivery latency: finished -> receipt_recorded (evidence delivery, including retries)
"""

from __future__ import annotations

import statistics
from collections import Counter, defaultdict
from datetime import datetime
from typing import Any

from .lifecycle import TERMINAL, UNRESOLVED, ReceiptState, State
from .store import ExecutionStore

# Refusals that mean recovery could not proceed because of local state, not because of a policy decision.
RECOVERY_FAILURE_OUTCOMES = frozenset(
    {"not_executed:stored_arguments_unavailable", "not_executed:tool_not_registered"}
)


def _ms(a: str | None, b: str | None) -> float | None:
    if not a or not b:
        return None
    return round(
        (datetime.fromisoformat(b) - datetime.fromisoformat(a)).total_seconds()
        * 1000.0,
        3,
    )


def _percentiles(values: list[float]) -> dict[str, float | None]:
    if not values:
        return {"count": 0, "p50": None, "p95": None, "max": None}
    values = sorted(values)
    if len(values) == 1:
        p95 = values[0]
    else:
        p95 = statistics.quantiles(values, n=20, method="inclusive")[-1]
    return {
        "count": len(values),
        "p50": round(statistics.median(values), 3),
        "p95": round(p95, 3),
        "max": round(values[-1], 3),
    }


def report(store: ExecutionStore) -> dict[str, Any]:
    rows = store.all_rows()
    by_state = Counter(r["state"] for r in rows)
    unresolved = [
        {
            "authorization_id": r["authorization_id"],
            "run_id": r["run_id"],
            "state": r["state"],
            "tool_name": r["tool_name"],
            "reserved_at_utc": r["reserved_at_utc"],
            "lease_until_utc": r["lease_until_utc"],
        }
        for r in rows
        if State(r["state"]) in UNRESOLVED
    ]
    pending = [
        r["authorization_id"]
        for r in rows
        if r["receipt_state"] == ReceiptState.PENDING.value
    ]
    missing = [
        r["authorization_id"]
        for r in rows
        if r["receipt_state"] == ReceiptState.NONE.value
        and r["state"] in {s.value for s in TERMINAL}
    ]
    reconciliation_backlog = [
        r["authorization_id"]
        for r in rows
        if r["state"] == State.RECONCILIATION_REQUIRED.value
    ]
    recovery_failures = [
        r["authorization_id"]
        for r in rows
        if (r["outcome"] or "") in RECOVERY_FAILURE_OUTCOMES
    ]

    events_by_auth: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for auth, event, ts in store.event_timestamps():
        events_by_auth[auth].append({"event": event, "ts": ts})

    start_latency, duration, receipt_latency = [], [], []
    for auth, evs in events_by_auth.items():
        first = {}
        for e in evs:
            first.setdefault(e["event"], e["ts"])
        if (v := _ms(first.get("reserved"), first.get("started"))) is not None:
            start_latency.append(v)
        if (v := _ms(first.get("started"), first.get("finished"))) is not None:
            duration.append(v)
        if (v := _ms(first.get("finished"), first.get("receipt_recorded"))) is not None:
            receipt_latency.append(v)

    chain_ok, chain_detail = store.verify_history()
    projection_ok, projection_detail = store.verify_projection()
    return {
        "schema": "govai.executor_report.v1",
        "schema_version": 2,
        "executions": len(rows),
        "by_state": dict(sorted(by_state.items())),
        "pending_executions": len(
            [r for r in rows if State(r["state"]) in {State.RESERVED, State.STARTED}]
        ),
        "unknown_outcomes": by_state.get(State.OUTCOME_UNKNOWN.value, 0),
        "reconciliation_backlog": len(reconciliation_backlog),
        "reconciliation_backlog_ids": reconciliation_backlog,
        "missing_receipts": missing,
        "pending_receipts": pending,
        "recovery_failures": recovery_failures,
        "unresolved": unresolved,
        "latency_ms": {
            "reserve_to_start": _percentiles(start_latency),
            "execution": _percentiles(duration),
            "receipt_delivery": _percentiles(receipt_latency),
        },
        "history": {
            "chain_verified": chain_ok,
            "detail": chain_detail,
            "projection_agrees": projection_ok,
            "projection_detail": projection_detail,
        },
    }
