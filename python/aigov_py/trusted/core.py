"""HTTP client for AIGov Core, with the decision mapping used by trusted execution.

Each client holds one API key, which is one principal. The agent, each approver, and the executor each use their own
client and key, so Core knows which principal made each call.

Decision mapping from Core's answer to one submission:

- accepted (``200``, with a ``record_hash``)          -> ALLOW. For a consequential call, the answer also carries
  Core's signed execution authorization.
- refused, reason ``approval_not_found``              -> REQUIRE_APPROVAL (no human decision recorded yet)
- refused by policy (``400``), or by role or tenant
  (``401``/``403``)                                    -> DENY, with Core's reason
- Core unreachable, timeout, or 5xx                   -> INDETERMINATE (fail closed; nothing runs)

The reason comes from Core's own message (``... reason=<code>``) or error code. This module does not decide it.
"""

from __future__ import annotations

import enum
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

DEFAULT_SOURCE = "aigov-sdk"

REASON_RE = re.compile(r"reason=([a-z_]+)")
REQUIRE_APPROVAL_REASONS = {"approval_not_found", "approval_missing"}


class Decision(str, enum.Enum):
    """The four outcomes of a submission. Values are the strings used in evidence and reports."""

    ALLOW = "ALLOW"
    DENY = "DENY"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"
    INDETERMINATE = "INDETERMINATE"


def utc_now_rfc3339() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass(frozen=True)
class CoreDecision:
    """Core's answer to one submission, mapped to a Decision. ``authorization`` is set for an allowed call."""

    decision: Decision
    reason: str
    event_id: str | None
    record_hash: str | None
    http_status: int | None
    latency_ms: float
    policy_revision: str | None = None
    authorization: dict[str, Any] | None = None


def _error(body: Any) -> tuple[str, str]:
    """Return (error_code, message) from a Core error body."""
    if isinstance(body, dict):
        err = body.get("error")
        if isinstance(err, dict):
            return str(err.get("code", "")), str(err.get("message", ""))
        return str(body.get("code", "")), str(body.get("message", ""))
    return "", str(body)


def _reason_from_refusal(message: str, code: str) -> str:
    match = REASON_RE.search(message)
    if match:
        return match.group(1)
    if code and code != "policy_violation":
        return code.lower()
    return "policy_violation"


class CoreClient:
    """One principal's view of Core. Use one client per API key.

    ``actor`` and ``system`` are informational labels written into the events this client submits. Core stamps the
    authenticated principal itself, so these labels do not affect authorization.
    """

    def __init__(
        self,
        base_url: str,
        api_key: str,
        *,
        timeout_sec: float = 10.0,
        actor: str = DEFAULT_SOURCE,
        system: str = DEFAULT_SOURCE,
    ) -> None:
        self._base = base_url.rstrip("/")
        self._api_key = api_key
        self._sdk = RuntimeGovernanceClient(
            self._base, api_key=api_key, timeout_sec=timeout_sec
        )
        self._timeout = timeout_sec
        self.actor = actor
        self.system = system
        # (event_type, latency_ms) for every evidence submission made through this client.
        self.samples: list[tuple[str, float]] = []

    @property
    def base_url(self) -> str:
        return self._base

    def submit(self, event: EvidenceEvent) -> CoreDecision:
        decision = self._submit(event)
        self.samples.append((event.event_type, decision.latency_ms))
        return decision

    def _submit(self, event: EvidenceEvent) -> CoreDecision:
        started = time.perf_counter()
        try:
            result = self._sdk.submit_evidence(event)
        except ServiceHTTPError as exc:
            latency = (time.perf_counter() - started) * 1000.0
            code, message = _error(exc.body)
            if exc.status_code == 400:
                reason = _reason_from_refusal(message, code)
                decision = (
                    Decision.REQUIRE_APPROVAL
                    if reason in REQUIRE_APPROVAL_REASONS
                    else Decision.DENY
                )
                return CoreDecision(decision, reason, None, None, 400, latency)
            if exc.status_code in (401, 403):
                return CoreDecision(
                    Decision.DENY,
                    code.lower() or f"http_{exc.status_code}",
                    None,
                    None,
                    exc.status_code,
                    latency,
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
        raw = result.raw if isinstance(result.raw, dict) else {}
        return CoreDecision(
            Decision.ALLOW,
            "accepted",
            event.event_id,
            result.record_hash,
            200,
            latency,
            policy_revision=str(raw.get("policy_version", "")) or None,
            authorization=raw.get("execution_authorization"),
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

    def status(self, run_id: str, authorization_id: str) -> tuple[int, Any]:
        """Executor status check (``GET /execution-authorizations/{run}/{id}/status``). Raises OSError if no answer."""
        return self._get(
            f"/execution-authorizations/{run_id}/{authorization_id}/status"
        )

    def health(self) -> bool:
        try:
            return self._get("/health")[0] == 200
        except OSError:
            return False

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
    actor: str = DEFAULT_SOURCE,
    system: str = DEFAULT_SOURCE,
) -> EvidenceEvent:
    return EvidenceEvent(
        event_id=event_id or f"{event_type}-{uuid.uuid4().hex}",
        event_type=event_type,
        ts_utc=ts_utc or utc_now_rfc3339(),
        actor=actor,
        system=system,
        run_id=run_id,
        payload=payload,
    )
