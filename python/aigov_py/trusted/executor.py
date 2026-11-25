"""The executor: verifies Core's authorization, runs the side effect at most once, records the outcome durably, and
delivers an execution receipt. Recovers after a crash without repeating an action whose outcome is unknown.

Order of operations for one call. Each step can refuse, and a refusal before the reservation performs no side effect:

1. Verify the signature with the pinned public key, the domain, the audience, the run, the tool, the argument digest
   (recomputed from the arguments the executor will use), and the expiry with a small clock allowance.
2. Ask Core for the authorization's current status with the executor's own key. Revoked, expired, or unreachable means
   refuse.
3. Reserve the authorization in the durable store (atomic, single use). The arguments are stored with the reservation.
4. Mark the execution started, with a lease. This is committed before the performer is called.
5. Call the performer (the side effect).
6. Record the outcome and a pending receipt in one transaction.
7. Deliver the receipt to Core, then mark it recorded when Core acknowledges it.

Recovery (``recover``) resumes what can be resumed and nothing else:

- reserved, never started: the side effect cannot have begun, so it is verified again and then performed once.
- started, lease expired: the outcome is unknown. It is recorded as outcome_unknown and then reconciliation_required.
  It is never retried automatically.
- finished with a pending or missing receipt: the receipt is delivered again. The action is not repeated.

Not claimed: exactly-once execution across an external system. The executor cannot see the external system's state,
and a crash inside the side effect leaves an outcome that only signed reconciliation evidence can resolve.
"""

from __future__ import annotations

import hashlib
import json
import logging
import threading
import time
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from aigov_py.canonical_json import canonical_bytes, canonical_dumps

from . import receipts
from .authorization import (
    CLOCK_SKEW_SECONDS,
    Refused,
    verify_authorization_signature,
    verify_authorization_with_registry,
)
from .core import CoreClient
from .lifecycle import State
from .store import ExecutionStore
from .tools import ToolSpec, args_binding_hash

Performer = Callable[[str, dict[str, Any], str], dict[str, Any]]
FaultHook = Callable[[str], None]
log = logging.getLogger("aigov_py.trusted.executor")

FAULT_POINTS = (
    "before_reserve",
    "after_reserve",
    "before_side_effect",
    "after_side_effect_before_finish",
    "after_finish_before_receipt_submit",
    "after_receipt_submitted_before_ack",
    "recovery_before_resume",
    "recovery_before_receipt",
)


def execution_key(authorization_id: str) -> str:
    """The idempotency key given to the performer for an authorization. Stable across retries and resumes."""
    return "exe_" + hashlib.sha256(authorization_id.encode("utf-8")).hexdigest()[:32]


def result_digest(result: Any) -> str:
    return hashlib.sha256(canonical_bytes(result)).hexdigest()


def _now_iso(clock: Callable[[], float]) -> str:
    return datetime.fromtimestamp(clock(), tz=UTC).isoformat()


def _parse(ts: str) -> datetime:
    return datetime.fromisoformat(ts)


@dataclass
class ExecutionOutcome:
    executed: bool
    reason: str
    authorization_id: str | None
    receipt_recorded: bool = False
    verify_ms: float = 0.0
    status_ms: float = 0.0
    execute_ms: float = 0.0
    receipt_ms: float = 0.0
    end_to_end_ms: float = 0.0
    timings: dict[str, float] = field(default_factory=dict)
    execution_state: str | None = None


@dataclass
class RecoveryAction:
    authorization_id: str
    run_id: str
    from_state: str
    action: str
    detail: str = ""

    def as_dict(self) -> dict[str, str]:
        return {
            "authorization_id": self.authorization_id,
            "run_id": self.run_id,
            "from_state": self.from_state,
            "action": self.action,
            "detail": self.detail,
        }


class Executor:
    """Runs each authorized call at most once, and recovers its durable state after a restart.

    ``performer(tool, arguments, execution_id)`` performs the side effect and returns
    ``{"success": bool, "data": ..., "blocked_reason": str | None}``. Raising an exception means the outcome is unknown:
    the execution is not retried, and it waits for reconciliation.

    ``fault`` is a test hook called at each boundary in ``FAULT_POINTS``. Production code leaves it unset.
    ``lease_seconds`` must exceed the longest side effect. A started execution whose lease has not expired is never
    treated as dead by recovery.
    """

    def __init__(
        self,
        *,
        core: CoreClient,
        public_key_b64: str | None = None,
        registry: Any = None,
        audience: str,
        store: ExecutionStore,
        tools: Mapping[str, ToolSpec],
        performer: Performer,
        clock: Callable[[], float] = time.time,
        worker_id: str | None = None,
        lease_seconds: int = 300,
        fault: FaultHook | None = None,
    ) -> None:
        if not callable(performer):
            raise TypeError("performer must be callable: it performs the side effect")
        if lease_seconds < 1:
            raise ValueError("lease_seconds must be at least 1")
        if public_key_b64 is None and registry is None:
            raise ValueError("provide public_key_b64 (pinned key) or registry (trusted key registry)")
        self._core = core
        self._pub = public_key_b64
        self._registry = registry
        self._audience = audience
        self._store = store
        self._tools = dict(tools)
        self._performer = performer
        self._clock = clock
        self._worker = worker_id or f"worker-{uuid.uuid4().hex[:8]}"
        self._lease = lease_seconds
        self._fault: FaultHook = fault or (lambda point: None)
        self._lock = threading.Lock()

    @property
    def store(self) -> ExecutionStore:
        return self._store

    @property
    def worker_id(self) -> str:
        return self._worker

    def _point(self, name: str) -> None:
        if name not in FAULT_POINTS:
            raise ValueError(f"unknown fault point {name!r}")
        self._fault(name)

    def _emit(self, event: str, **fields: Any) -> None:
        log.info(
            json.dumps(
                {"event": event, "worker": self._worker, **fields}, sort_keys=True
            )
        )

    # --- verification ----------------------------------------------------------------------------------------------

    def _verify(
        self, run_id: str, tool: str, arguments: dict[str, Any], signed: dict[str, Any]
    ) -> tuple[dict, str, ToolSpec]:
        spec = self._tools.get(tool)
        if spec is None:
            raise Refused("tool_not_registered")
        if self._registry is not None:
            verify_authorization_with_registry(
                signed, self._registry, now=datetime.fromtimestamp(self._clock(), tz=UTC)
            )
        else:
            verify_authorization_signature(signed, self._pub)
        payload = signed["payload"]
        if payload.get("executor_audience") != self._audience:
            raise Refused("authorization_audience_mismatch")
        if payload.get("run_id") != run_id:
            raise Refused("authorization_run_mismatch")
        if payload.get("tool_name") != tool:
            raise Refused("authorization_tool_mismatch")
        digest = args_binding_hash(spec, arguments)
        if payload.get("args_binding_hash") != digest:
            raise Refused("authorization_arguments_mismatch")
        expires = _parse(payload["expires_at_utc"])
        if self._clock() > expires.timestamp() + CLOCK_SKEW_SECONDS:
            raise Refused("authorization_expired")
        return payload, digest, spec

    def _core_status(self, run_id: str, auth_id: str) -> str:
        """The authorization's state in Core. Raises Refused if Core cannot be asked or does not say authorized."""
        try:
            code, body = self._core.status(run_id, auth_id)
        except OSError as exc:
            raise Refused("core_unavailable") from exc
        if code != 200 or not isinstance(body, dict):
            raise Refused(f"core_status_http_{code}")
        if body.get("state") != "authorized":
            raise Refused(f"authorization_{body.get('state')}")
        return "authorized"

    # --- the execution path ----------------------------------------------------------------------------------------

    def execute(
        self,
        *,
        run_id: str,
        tool: str,
        arguments: dict[str, Any],
        signed: dict[str, Any],
    ) -> ExecutionOutcome:
        started = time.perf_counter()
        timings: dict[str, float] = {}
        auth_id = (
            (signed.get("payload") or {}).get("authorization_id")
            if isinstance(signed, dict)
            else None
        )
        try:
            t = time.perf_counter()
            payload, digest, _spec = self._verify(run_id, tool, arguments, signed)
            auth_id = payload["authorization_id"]
            timings["verify_ms"] = (time.perf_counter() - t) * 1000.0

            t = time.perf_counter()
            self._core_status(run_id, auth_id)
            timings["status_ms"] = (time.perf_counter() - t) * 1000.0

            self._point("before_reserve")
            now = _now_iso(self._clock)
            reserved = self._store.reserve(
                authorization_id=auth_id,
                run_id=run_id,
                tool=tool,
                digest=digest,
                signed_json=json.dumps(signed, sort_keys=True),
                now=now,
                executor_identity=self._audience,
                policy_revision=payload.get("policy_revision"),
                arguments_json=canonical_dumps(arguments),
            )
            if not reserved:
                raise Refused("authorization_replayed")
            self._emit("reserved", authorization_id=auth_id, run_id=run_id, tool=tool)
            self._point("after_reserve")

            outcome = self._perform(
                run_id=run_id,
                tool=tool,
                arguments=arguments,
                auth_id=auth_id,
                digest=digest,
                timings=timings,
            )
            outcome.end_to_end_ms = (time.perf_counter() - started) * 1000.0
            return outcome
        except Refused as r:
            return ExecutionOutcome(
                executed=False,
                reason=r.reason,
                authorization_id=auth_id if isinstance(auth_id, str) else None,
                verify_ms=timings.get("verify_ms", 0.0),
                status_ms=timings.get("status_ms", 0.0),
                end_to_end_ms=(time.perf_counter() - started) * 1000.0,
                timings=timings,
            )

    def _perform(
        self,
        *,
        run_id: str,
        tool: str,
        arguments: dict[str, Any],
        auth_id: str,
        digest: str,
        timings: dict[str, float],
    ) -> ExecutionOutcome:
        """From a reservation to a recorded receipt. Called by ``execute`` and by recovery."""
        now = _now_iso(self._clock)
        lease_until = (
            datetime.fromisoformat(now) + timedelta(seconds=self._lease)
        ).isoformat()
        if not self._store.start(
            authorization_id=auth_id,
            worker_id=self._worker,
            now=now,
            lease_until=lease_until,
        ):
            raise Refused("authorization_already_started")
        self._emit("started", authorization_id=auth_id, lease_until_utc=lease_until)
        self._point("before_side_effect")

        t = time.perf_counter()
        # A stable idempotency key: the same authorization always yields the same id, including after a resume. A downstream
        # system that deduplicates on this key makes retries of the same authorization safe.
        exec_id = execution_key(auth_id)
        try:
            result = self._performer(tool, arguments, exec_id)
        except Exception as exc:  # noqa: BLE001 - any failure after the side effect began is an unknown outcome
            self._store.mark_outcome_unknown(
                authorization_id=auth_id,
                now=_now_iso(self._clock),
                actor=self._worker,
                reason=f"performer raised {type(exc).__name__}",
            )
            self._emit(
                "outcome_unknown", authorization_id=auth_id, reason=type(exc).__name__
            )
            timings["execute_ms"] = (time.perf_counter() - t) * 1000.0
            return ExecutionOutcome(
                executed=False,
                reason="outcome_unknown",
                authorization_id=auth_id,
                timings=timings,
                execution_state=State.RECONCILIATION_REQUIRED.value,
            )
        timings["execute_ms"] = (time.perf_counter() - t) * 1000.0
        self._point("after_side_effect_before_finish")

        ok = bool(result.get("success"))
        outcome = "success" if ok else f"blocked:{result.get('blocked_reason')}"
        res_digest = result_digest(result.get("data")) if ok else None
        receipt_id = "execution_receipt-" + uuid.uuid4().hex
        self._store.finish(
            authorization_id=auth_id,
            outcome=outcome,
            result_digest_hex=res_digest,
            now=_now_iso(self._clock),
            receipt_event_id=receipt_id,
            worker_id=self._worker,
        )
        self._emit("finished", authorization_id=auth_id, outcome=outcome)
        self._point("after_finish_before_receipt_submit")

        t = time.perf_counter()
        delivered = self._deliver_receipt(run_id, auth_id)
        timings["receipt_ms"] = (time.perf_counter() - t) * 1000.0
        return ExecutionOutcome(
            executed=ok,
            reason="executed" if ok else outcome,
            authorization_id=auth_id,
            receipt_recorded=delivered,
            execute_ms=timings.get("execute_ms", 0.0),
            receipt_ms=timings.get("receipt_ms", 0.0),
            timings=timings,
            execution_state=(State.SUCCEEDED if ok else State.FAILED).value,
        )

    # --- receipts ----------------------------------------------------------------------------------------------------

    def _deliver_receipt(self, run_id: str, auth_id: str) -> bool:
        """Evidence delivery only. See ``receipts.deliver``."""
        return receipts.deliver(
            self._store,
            self._core,
            run_id=run_id,
            authorization_id=auth_id,
            clock=self._clock,
            fault=self._fault_point_only,
        )

    def _fault_point_only(self, name: str) -> None:
        self._point(name)

    # --- recovery ----------------------------------------------------------------------------------------------------

    def recover(
        self,
        *,
        run_id: str | None = None,
        arguments_for: Callable[[str], dict[str, Any]] | None = None,
    ) -> list[RecoveryAction]:
        """Bring every unresolved execution to the state its evidence supports. Safe to call at any time.

        ``arguments_for`` is not needed: the reservation stores its arguments. It is accepted for callers that want to
        supply them instead, and it must return the same arguments the digest was taken from.
        """
        actions: list[RecoveryAction] = []
        rows = {r["authorization_id"]: r for r in self._store.unresolved()}
        for r in self._store.pending_receipts() + self._store.missing_receipts():
            rows.setdefault(r["authorization_id"], r)
        for auth_id, row in sorted(rows.items()):
            if run_id is not None and row["run_id"] != run_id:
                continue
            state = row["state"]
            if state == State.RESERVED.value:
                actions.append(self._recover_reserved(row))
            elif state == State.STARTED.value:
                actions.append(self._recover_started(row))
            elif (
                state == State.RECONCILIATION_REQUIRED.value
                or state == State.OUTCOME_UNKNOWN.value
            ):
                actions.append(
                    RecoveryAction(
                        auth_id,
                        row["run_id"],
                        state,
                        "awaiting_reconciliation",
                        "no automatic retry",
                    )
                )
        for row in self._store.pending_receipts():
            if run_id is not None and row["run_id"] != run_id:
                continue
            self._point("recovery_before_receipt")
            delivered = self._deliver_receipt(row["run_id"], row["authorization_id"])
            actions.append(
                RecoveryAction(
                    row["authorization_id"],
                    row["run_id"],
                    row["state"],
                    "receipt_recorded" if delivered else "receipt_still_pending",
                    "evidence re-sent; the action was not repeated",
                )
            )
        for row in self._store.missing_receipts():
            if run_id is not None and row["run_id"] != run_id:
                continue
            new_id = "execution_receipt-" + uuid.uuid4().hex
            self._store.attach_pending_receipt(
                authorization_id=row["authorization_id"],
                receipt_event_id=new_id,
                now=_now_iso(self._clock),
            )
            row = self._store.row(row["authorization_id"]) or row
            delivered = self._deliver_receipt(row["run_id"], row["authorization_id"])
            actions.append(
                RecoveryAction(
                    row["authorization_id"],
                    row["run_id"],
                    row["state"],
                    "receipt_recorded" if delivered else "receipt_still_pending",
                    "receipt was missing; attached from the stored outcome",
                )
            )
        return actions

    def _recover_reserved(self, row: dict[str, Any]) -> RecoveryAction:
        auth_id, run_id = row["authorization_id"], row["run_id"]
        try:
            signed = json.loads(row["signed_authorization_json"])
            arguments = (
                json.loads(row["arguments_json"]) if row["arguments_json"] else None
            )
        except (TypeError, ValueError):
            return RecoveryAction(
                auth_id, run_id, row["state"], "deferred", "stored record unreadable"
            )
        spec = self._tools.get(row["tool_name"])
        if spec is None:
            return self._refuse_reserved(row, "tool_not_registered")
        if (
            arguments is None
            or args_binding_hash(spec, arguments) != row["args_digest"]
        ):
            # Without the original arguments the side effect cannot be performed. Refuse; never guess.
            self._point("recovery_before_resume")
            return self._refuse_reserved(row, "stored_arguments_unavailable")
        try:
            self._core_status(run_id, auth_id)
        except Refused as r:
            if r.reason == "core_unavailable":
                return RecoveryAction(
                    auth_id,
                    run_id,
                    row["state"],
                    "deferred",
                    "core_unavailable: nothing performed",
                )
            return self._refuse_reserved(row, r.reason)
        try:
            self._verify(run_id, row["tool_name"], arguments, signed)
        except Refused as r:
            return self._refuse_reserved(row, r.reason)
        self._point("recovery_before_resume")
        try:
            self._perform(
                run_id=run_id,
                tool=row["tool_name"],
                arguments=arguments,
                auth_id=auth_id,
                digest=row["args_digest"],
                timings={},
            )
        except Refused as r:
            return RecoveryAction(
                auth_id, run_id, row["state"], "not_resumed", r.reason
            )
        return RecoveryAction(
            auth_id,
            run_id,
            row["state"],
            "resumed_once",
            "reservation had not started; performed once",
        )

    def _refuse_reserved(self, row: dict[str, Any], reason: str) -> RecoveryAction:
        self._store.fail_before_start(
            authorization_id=row["authorization_id"],
            now=_now_iso(self._clock),
            actor=self._worker,
            reason=reason,
            receipt_event_id="execution_receipt-" + uuid.uuid4().hex,
        )
        self._deliver_receipt(row["run_id"], row["authorization_id"])
        return RecoveryAction(
            row["authorization_id"],
            row["run_id"],
            row["state"],
            "closed_without_action",
            reason,
        )

    def _recover_started(self, row: dict[str, Any]) -> RecoveryAction:
        auth_id, run_id = row["authorization_id"], row["run_id"]
        lease = row["lease_until_utc"]
        if lease and _parse(lease) > datetime.fromtimestamp(self._clock(), tz=UTC):
            return RecoveryAction(
                auth_id,
                run_id,
                row["state"],
                "skipped",
                "a live worker holds this execution",
            )
        self._store.mark_outcome_unknown(
            authorization_id=auth_id,
            now=_now_iso(self._clock),
            actor=self._worker,
            reason="started without a recorded outcome; lease expired",
        )
        return RecoveryAction(
            auth_id,
            run_id,
            row["state"],
            "outcome_unknown",
            "side effect may have run; reconciliation required; not retried",
        )


__all__ = [
    "FAULT_POINTS",
    "ExecutionOutcome",
    "Executor",
    "Performer",
    "RecoveryAction",
    "result_digest",
]
