"""The execution lifecycle: states, permitted transitions, and receipt delivery states.

One execution per authorization. It moves through the states below. A transition that is not in ``ALLOWED`` is refused,
and the store refuses it inside the same transaction that would have recorded it.

    reserved -> started -> succeeded | failed | outcome_unknown
    reserved -> failed                       (refused before any side effect: revoked, expired, or not authorized)
    outcome_unknown -> reconciliation_required -> reconciled

Terminal states: succeeded, failed, reconciled. An outcome_unknown execution is never retried automatically. It needs
signed evidence from an authorized reconciler (see ``reconcile.py``).

Receipt delivery is a separate dimension. A finished execution has a receipt with state ``pending`` (written locally in
the same transaction as the outcome), and it becomes ``recorded`` once Core acknowledges it. Receipt delivery is evidence
delivery. It never repeats the external action.
"""

from __future__ import annotations

import enum


class State(str, enum.Enum):
    RESERVED = "reserved"
    STARTED = "started"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    OUTCOME_UNKNOWN = "outcome_unknown"
    RECONCILIATION_REQUIRED = "reconciliation_required"
    RECONCILED = "reconciled"


class ReceiptState(str, enum.Enum):
    NONE = "none"
    PENDING = "pending"
    RECORDED = "recorded"


TERMINAL: frozenset[State] = frozenset(
    {State.SUCCEEDED, State.FAILED, State.RECONCILED}
)
UNRESOLVED: frozenset[State] = frozenset(
    {
        State.RESERVED,
        State.STARTED,
        State.OUTCOME_UNKNOWN,
        State.RECONCILIATION_REQUIRED,
    }
)
FINISHED: frozenset[State] = frozenset(
    {State.SUCCEEDED, State.FAILED, State.RECONCILED}
)

ALLOWED: dict[State, frozenset[State]] = {
    State.RESERVED: frozenset({State.STARTED, State.FAILED}),
    State.STARTED: frozenset({State.SUCCEEDED, State.FAILED, State.OUTCOME_UNKNOWN}),
    State.OUTCOME_UNKNOWN: frozenset({State.RECONCILIATION_REQUIRED}),
    State.RECONCILIATION_REQUIRED: frozenset({State.RECONCILED}),
    State.SUCCEEDED: frozenset(),
    State.FAILED: frozenset(),
    State.RECONCILED: frozenset(),
}

RECEIPT_ALLOWED: dict[ReceiptState, frozenset[ReceiptState]] = {
    ReceiptState.NONE: frozenset({ReceiptState.PENDING}),
    ReceiptState.PENDING: frozenset({ReceiptState.RECORDED}),
    ReceiptState.RECORDED: frozenset(),
}


class InvalidTransition(Exception):
    """A requested state change is not permitted from the current state."""

    def __init__(self, current: str, requested: str) -> None:
        super().__init__(f"transition {current} -> {requested} is not permitted")
        self.current = current
        self.requested = requested


def check_transition(current: str, requested: State) -> None:
    try:
        cur = State(current)
    except ValueError as exc:
        raise InvalidTransition(current, requested.value) from exc
    if requested not in ALLOWED[cur]:
        raise InvalidTransition(current, requested.value)


def check_receipt_transition(current: str, requested: ReceiptState) -> None:
    try:
        cur = ReceiptState(current)
    except ValueError as exc:
        raise InvalidTransition(
            f"receipt:{current}", f"receipt:{requested.value}"
        ) from exc
    if requested not in RECEIPT_ALLOWED[cur]:
        raise InvalidTransition(f"receipt:{current}", f"receipt:{requested.value}")
