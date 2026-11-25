"""Service-backed tool gate: every decision is made by AIGov Core over HTTP.

The agent process never decides authorization. For each tool call it submits an evidence event
to Core's ``POST /evidence``. Core evaluates the signed policy and either accepts the event
(``200``, with a ``record_hash``) or refuses it (``400 policy_violation``). Only an accepted event
allows the sandbox to run the call.

Decision mapping from Core's answer:

- accepted (200)                              -> ALLOW, with Core's record_hash
- refused, reason ``approval_not_found``      -> REQUIRE_APPROVAL (no human decision recorded yet)
- refused, any other policy reason            -> DENY, with Core's reason
- Core unreachable, timeout, or 5xx           -> INDETERMINATE (fail closed; nothing runs)

The reason is taken from Core's message (``... reason=<code>``). The reference does not invent it.

Core's answer is written to the ledger before the sandbox runs, so the write-ahead record lives in
Core. A refusal is also recorded as ``tool_call_blocked``, with Core's reason copied from its
response. That record is the reference's note of Core's refusal. Core's ``400`` is the decision.
"""

from __future__ import annotations

import json
import re
import time
import urllib.error
import urllib.request
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from aigov_py.runtime.client import RuntimeGovernanceClient
from aigov_py.runtime.exceptions import (
    MalformedResponse,
    ServiceHTTPError,
    TransportError,
)
from aigov_py.runtime.models import EvidenceEvent

from .gate import Decision

REASON_RE = re.compile(r"reason=([a-z_]+)")
REQUIRE_APPROVAL_REASONS = {"approval_not_found", "approval_missing"}


def utc_now_rfc3339() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass(frozen=True)
class CoreDecision:
    decision: Decision
    reason: str
    event_id: str | None
    record_hash: str | None
    http_status: int | None
    latency_ms: float


def _error_message(body: Any) -> str:
    if isinstance(body, dict):
        err = body.get("error")
        if isinstance(err, dict):
            return str(err.get("message", ""))
        return str(body.get("message", ""))
    return str(body)


def _reason_from_refusal(message: str) -> str:
    match = REASON_RE.search(message)
    if match:
        return match.group(1)
    return "policy_violation"


class CoreClient:
    """Thin wrapper over the SDK runtime client, plus the read-only verification calls."""

    def __init__(
        self, base_url: str, api_key: str, *, timeout_sec: float = 10.0
    ) -> None:
        self._base = base_url.rstrip("/")
        self._api_key = api_key
        self._sdk = RuntimeGovernanceClient(
            self._base, api_key=api_key, timeout_sec=timeout_sec
        )
        self._timeout = timeout_sec

    def submit(self, event: EvidenceEvent) -> CoreDecision:
        started = time.perf_counter()
        try:
            result = self._sdk.submit_evidence(event)
        except ServiceHTTPError as exc:
            latency = (time.perf_counter() - started) * 1000.0
            if exc.status_code == 400:
                message = _error_message(exc.body)
                reason = _reason_from_refusal(message)
                decision = (
                    Decision.REQUIRE_APPROVAL
                    if reason in REQUIRE_APPROVAL_REASONS
                    else Decision.DENY
                )
                return CoreDecision(
                    decision, reason, None, None, exc.status_code, latency
                )
            return CoreDecision(
                Decision.INDETERMINATE,
                f"core_http_{exc.status_code}",
                None,
                None,
                exc.status_code,
                latency,
            )
        except (TransportError, MalformedResponse) as exc:
            latency = (time.perf_counter() - started) * 1000.0
            return CoreDecision(
                Decision.INDETERMINATE,
                f"core_unavailable:{type(exc).__name__}",
                None,
                None,
                None,
                latency,
            )
        latency = (time.perf_counter() - started) * 1000.0
        return CoreDecision(
            Decision.ALLOW, "accepted", event.event_id, result.record_hash, 200, latency
        )

    def _get(self, path: str) -> tuple[int, Any]:
        req = urllib.request.Request(
            self._base + path,
            headers={
                "Authorization": f"Bearer {self._api_key}",
                "Accept": "application/json",
            },
            method="GET",
        )
        try:
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                return resp.status, json.loads(resp.read() or b"null")
        except urllib.error.HTTPError as exc:
            try:
                body = json.loads(exc.read() or b"null")
            except json.JSONDecodeError:
                body = None
            return exc.code, body

    def verify_run(self, run_id: str) -> tuple[bool, str]:
        """Core's own chain verification for one run (``GET /verify/{run_id}``)."""
        status, body = self._get(f"/verify/{run_id}")
        ok = status == 200 and isinstance(body, dict) and body.get("ok") is True
        return ok, str(body.get("message", "")) if isinstance(body, dict) else str(body)

    def export(self, run_id: str) -> dict[str, Any]:
        """Core's export for one run (``GET /api/export/{run_id}``)."""
        status, body = self._get(f"/api/export/{run_id}")
        if status != 200 or not isinstance(body, dict):
            raise RuntimeError(f"export failed for {run_id}: HTTP {status}")
        return body

    def ledger_record_hashes(self, run_id: str) -> dict[str, str]:
        """event_id -> record_hash, as Core's log chain holds them for this run."""
        chain = self.export(run_id).get("evidence_hashes", {}).get("log_chain", [])
        return {entry["event_id"]: entry["record_hash"] for entry in chain}


def new_event(
    event_type: str,
    run_id: str,
    payload: dict[str, Any],
    *,
    ts_utc: str | None = None,
    event_id: str | None = None,
) -> EvidenceEvent:
    return EvidenceEvent(
        event_id=event_id or f"{event_type}-{uuid.uuid4().hex}",
        event_type=event_type,
        ts_utc=ts_utc or utc_now_rfc3339(),
        actor="agent-reference",
        system="aigov-agent-reference",
        run_id=run_id,
        payload=payload,
    )
