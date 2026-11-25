"""The executor: verifies Core's authorization itself, reserves it once, performs the side effect, and records a receipt.

Order of operations for one call. Each step can refuse, and a refusal performs no side effect:

1. Verify the signature with the pinned public key, the domain, the audience, the run, the tool, the argument digest
   (recomputed from the arguments the executor will actually use), and the expiry with a small clock allowance.
2. Ask Core for the authorization's current status with the executor's own key. Revoked or unreachable means refuse.
3. Reserve the authorization in the local store. A second reservation is a replay, and is refused.
4. Perform the side effect, through the performer the integrator supplies.
5. Record the outcome and a result digest in the store, then submit an execution receipt to Core.

Not claimed: exactly-once execution across an external system. A crash after step 4 and before step 5 leaves a
reservation with no receipt, which an operator must reconcile against that system.
"""

from __future__ import annotations

import json
import threading
import time
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any

from aigov_py.canonical_json import canonical_bytes

from .authorization import CLOCK_SKEW_SECONDS, Refused, verify_authorization_signature
from .core import CoreClient, Decision, new_event
from .store import ExecutionStore
from .tools import ToolSpec, args_binding_hash

Performer = Callable[[str, dict[str, Any], str], dict[str, Any]]


def result_digest(result: Any) -> str:
    import hashlib

    return hashlib.sha256(canonical_bytes(result)).hexdigest()


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


class Executor:
    """Verifies Core's authorization independently, then performs the side effect once.

    ``performer(tool, arguments, execution_id)`` performs the side effect and returns
    ``{"success": bool, "data": ..., "blocked_reason": str | None}``. The executor never performs an action itself.
    """

    def __init__(
        self,
        *,
        core: CoreClient,
        public_key_b64: str,
        audience: str,
        store: ExecutionStore,
        tools: Mapping[str, ToolSpec],
        performer: Performer,
        clock: Callable[[], float] = time.time,
    ) -> None:
        if not callable(performer):
            raise TypeError("performer must be callable: it performs the side effect")
        self._core = core
        self._pub = public_key_b64
        self._audience = audience
        self._store = store
        self._tools = dict(tools)
        self._performer = performer
        self._clock = clock
        self._lock = threading.Lock()

    @property
    def store(self) -> ExecutionStore:
        return self._store

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
            spec = self._tools.get(tool)
            if spec is None:
                raise Refused("tool_not_registered")

            # 1. Local verification: signature, audience, binding to this request, expiry.
            t = time.perf_counter()
            verify_authorization_signature(signed, self._pub)
            payload = signed["payload"]
            auth_id = payload["authorization_id"]
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
            timings["verify_ms"] = (time.perf_counter() - t) * 1000.0

            # 2. Current status from Core, with the executor's own key. Revoked or unreachable means refuse.
            t = time.perf_counter()
            try:
                code, body = self._core.status(run_id, auth_id)
            except OSError as exc:
                raise Refused("core_unavailable") from exc
            if code != 200 or not isinstance(body, dict):
                raise Refused(f"core_status_http_{code}")
            if body.get("state") != "authorized":
                raise Refused(f"authorization_{body.get('state')}")
            timings["status_ms"] = (time.perf_counter() - t) * 1000.0

            # 3. Reserve (single use), then the side effect.
            now_iso = _now_iso(self._clock)
            if not self._store.reserve(
                authorization_id=auth_id,
                run_id=run_id,
                tool=tool,
                digest=digest,
                signed_json=json.dumps(signed, sort_keys=True),
                now=now_iso,
            ):
                raise Refused("authorization_replayed")
            t = time.perf_counter()
            result = self._performer(tool, arguments, "exe_" + uuid.uuid4().hex)
            ok = bool(result.get("success"))
            outcome = "success" if ok else f"blocked:{result.get('blocked_reason')}"
            res_digest = result_digest(result.get("data")) if ok else None
            self._store.finish(
                auth_id,
                outcome=outcome,
                result_digest_hex=res_digest,
                now=_now_iso(self._clock),
            )
            timings["execute_ms"] = (time.perf_counter() - t) * 1000.0

            # 4. Receipt: separate evidence that the side effect was attempted, with its outcome and result digest.
            t = time.perf_counter()
            receipt = self._core.submit(
                new_event(
                    "execution_receipt",
                    run_id,
                    {
                        "execution_authorization_id": auth_id,
                        "tool_name": tool,
                        "args_binding_hash": digest,
                        "outcome": outcome,
                        "result_digest": res_digest or "",
                    },
                    actor=self._core.actor,
                    system=self._core.system,
                )
            )
            receipt_ok = receipt.decision == Decision.ALLOW
            if receipt_ok and receipt.event_id:
                self._store.record_receipt(auth_id, receipt.event_id)
            timings["receipt_ms"] = (time.perf_counter() - t) * 1000.0
            return ExecutionOutcome(
                executed=ok,
                reason="executed" if ok else outcome,
                authorization_id=auth_id,
                receipt_recorded=receipt_ok,
                verify_ms=timings.get("verify_ms", 0.0),
                status_ms=timings.get("status_ms", 0.0),
                execute_ms=timings.get("execute_ms", 0.0),
                receipt_ms=timings.get("receipt_ms", 0.0),
                end_to_end_ms=(time.perf_counter() - started) * 1000.0,
                timings=timings,
            )
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


def _parse(ts: str):  # type: ignore[no-untyped-def]
    from datetime import datetime

    return datetime.fromisoformat(ts)


def _now_iso(clock: Callable[[], float]) -> str:
    from datetime import UTC, datetime

    return datetime.fromtimestamp(clock(), tz=UTC).isoformat()


__all__ = [
    "ExecutionOutcome",
    "Executor",
    "Performer",
    "args_binding_hash",
    "result_digest",
]
