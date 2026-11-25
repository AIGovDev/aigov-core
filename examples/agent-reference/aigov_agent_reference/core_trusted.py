"""Trusted execution: separate agent, approver, and executor identities, and an executor that verifies Core's
signed authorization before any side effect.

Trust boundary (see ``docs/`` and the report for the full statement):

- The **agent** holds its own API key. It can request approvals and submit calls. It cannot approve, cannot
  revoke, cannot write a receipt, and cannot sign. Core refuses each of those by role.
- The **approver** holds its own API key and names an identity that must match the authenticated one.
- **Core** holds the authorization signing key (Ed25519, domain-separated, not given to any agent). It issues an
  authorization only after policy evaluation succeeds, and records the approval as consumed under the ledger lock.
- The **executor** holds its own API key and the pinned authorization public key. It verifies the signature, the
  audience, the expiry, and the argument digest. It asks Core for the current status. It reserves the authorization
  in its local store, and only then performs the side effect. It then records a receipt, which is separate evidence.

Not claimed: exactly-once execution across external systems. The executor reserves an authorization before it acts.
If it crashes after acting and before the receipt is recorded, the store shows a reservation with no receipt, and
an operator must reconcile it. Core cannot see that external action.
"""

from __future__ import annotations

import base64
import hashlib
import json
import sqlite3
import threading
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from aigov_py.canonical_json import canonical_bytes
from execution_token import ExecutionTokenAuthority
from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey
from sandboxed_tools import SandboxedGitHubTools, compute_args_binding_hash
from tool_gateway import TOOL_CAPABILITY_MAP

# Tool registry. Defaults are the in-process benchmark's tools. A deployment registers its own tools with
# ``register_tool``, and names the argument that carries the resource (the reference uses ``repo_id``).
TOOL_ACTIONS: dict[str, str] = dict(TOOL_CAPABILITY_MAP)
TOOL_RESOURCE_KEY: dict[str, str] = {}


def register_tool(tool: str, action: str, resource_key: str = "repo_id") -> None:
    """Register a tool, its action type, and the argument that names its resource."""
    TOOL_ACTIONS[tool] = action
    TOOL_RESOURCE_KEY[tool] = resource_key


def resource_of(tool: str, arguments: dict[str, Any]) -> str:
    return str(arguments.get(TOOL_RESOURCE_KEY.get(tool, "repo_id"), ""))


from .core_gate import CoreClient, CoreDecision, new_event
from .gate import Decision

TENANT = "acme-corp"
AUTH_DOMAIN = b"govai.execution_authorization.v1\x00"
AUTH_SCHEMA = "govai.execution_authorization.v1"
CLOCK_SKEW_SECONDS = 5


class Refused(Exception):
    """The executor refuses to act. ``reason`` is machine-readable."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


# ----------------------------------------------------------------------------------------------- verification


def verify_authorization_signature(signed: dict[str, Any], public_key_b64: str) -> None:
    """Raise ``Refused`` unless the signature is valid for this public key and domain."""
    payload = signed.get("payload")
    if not isinstance(payload, dict) or payload.get("schema") != AUTH_SCHEMA:
        raise Refused("authorization_schema_mismatch")
    try:
        sig = base64.b64decode(signed["signature"], validate=True)
        key = VerifyKey(base64.b64decode(public_key_b64, validate=True))
        key.verify(AUTH_DOMAIN + canonical_bytes(payload), sig)
    except (BadSignatureError, KeyError, ValueError, TypeError) as exc:
        raise Refused("authorization_signature_invalid") from exc


def args_digest(tool: str, arguments: dict[str, Any]) -> str:
    """Argument digest used by approvals and authorizations. Same function as the in-process benchmark."""
    return compute_args_binding_hash(
        tool, arguments, TOOL_ACTIONS[tool], resource_of(tool, arguments)
    )


def result_digest(result: Any) -> str:
    return hashlib.sha256(canonical_bytes(result)).hexdigest()


# ----------------------------------------------------------------------------------------------- local store


class ExecutionStore:
    """The executor's single-use record. A reservation is made before any side effect, atomically."""

    def __init__(self, path: Path) -> None:
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        with self._conn() as c:
            c.execute(
                """CREATE TABLE IF NOT EXISTS executions (
                    authorization_id TEXT PRIMARY KEY,
                    run_id TEXT NOT NULL,
                    tool_name TEXT NOT NULL,
                    args_digest TEXT NOT NULL,
                    state TEXT NOT NULL,
                    reserved_at_utc TEXT NOT NULL,
                    finished_at_utc TEXT,
                    outcome TEXT,
                    result_digest TEXT,
                    receipt_event_id TEXT,
                    signed_authorization_json TEXT NOT NULL
                )"""
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


# ----------------------------------------------------------------------------------------------- executor


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
    """Verifies Core's authorization independently, then performs the side effect once."""

    def __init__(
        self,
        *,
        core: CoreClient,
        public_key_b64: str,
        audience: str,
        store: ExecutionStore,
        clock: Callable[[], float] = time.time,
        performer: Callable[[str, dict[str, Any], str], dict[str, Any]] | None = None,
    ) -> None:
        """``performer(tool, arguments, execution_id)`` performs the side effect and returns
        ``{"success": bool, "data": ..., "blocked_reason": str | None}``. Without it, the executor uses the sandboxed
        GitHub-style tools of the in-process benchmark."""
        self._core = core
        self._pub = public_key_b64
        self._audience = audience
        self._store = store
        self._clock = clock
        self._performer = performer
        self._authority = ExecutionTokenAuthority()
        self._sandbox = SandboxedGitHubTools(token_authority=self._authority)
        self._lock = threading.Lock()

    @property
    def sandbox(self) -> SandboxedGitHubTools:
        return self._sandbox

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
            digest = args_digest(tool, arguments)
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
            if self._performer is not None:
                result = self._performer(tool, arguments, "exe_" + uuid.uuid4().hex)
            else:
                token = self._authority.issue(
                    execution_id="exe_" + uuid.uuid4().hex,
                    tool_name=tool,
                    args_binding_hash=digest,
                    action_type=TOOL_ACTIONS[tool],
                    resource_id=resource_of(tool, arguments),
                    tenant_id=TENANT,
                )
                result = self._sandbox.execute(
                    tool,
                    arguments,
                    execution_id=token.execution_id,
                    tenant_id=TENANT,
                    args_binding_hash=digest,
                    execution_token=token,
                    decision_label="executor_verified",
                    expected_action_type=TOOL_ACTIONS[tool],
                    expected_resource_id=resource_of(tool, arguments),
                )
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


# ----------------------------------------------------------------------------------------------- actors


class AgentActor:
    """The agent's own identity. Its key cannot approve, revoke, sign, or write receipts."""

    def __init__(self, core: CoreClient, run_id: str) -> None:
        self.core = core
        self.run_id = run_id

    def request_approval(
        self, tool: str, args: dict[str, Any], tool_call_id: str
    ) -> CoreDecision:
        return self.core.submit(
            new_event(
                "tool_approval_requested",
                self.run_id,
                {
                    "tool_name": tool,
                    "tool_call_id": tool_call_id,
                    "args_binding_hash": args_digest(tool, args),
                },
            )
        )

    def submit_write(
        self, tool: str, args: dict[str, Any], tool_call_id: str, approval_event_id: str
    ) -> CoreDecision:
        return self.core.submit(
            new_event(
                "consequential_tool_call",
                self.run_id,
                {
                    "tool_name": tool,
                    "tool_call_id": tool_call_id,
                    "approval_event_id": approval_event_id,
                    "args_binding_hash": args_digest(tool, args),
                },
            )
        )

    def read(self, tool: str, args: dict[str, Any], tool_call_id: str) -> CoreDecision:
        return self.core.submit(
            new_event(
                "tool_call",
                self.run_id,
                {
                    "tool_name": tool,
                    "tool_call_id": tool_call_id,
                    "args_binding_hash": args_digest(tool, args),
                },
            )
        )

    def record_block(self, tool: str, tool_call_id: str, reason: str) -> CoreDecision:
        return self.core.submit(
            new_event(
                "tool_call_blocked",
                self.run_id,
                {"tool_name": tool, "tool_call_id": tool_call_id, "reason": reason},
            )
        )


class ApproverActor:
    """A human approver's own identity. ``identity`` must match what is written into approvals."""

    def __init__(self, core: CoreClient, identity: str) -> None:
        self.core = core
        self.identity = identity

    def decide(
        self,
        *,
        run_id: str,
        request: CoreDecision,
        tool: str,
        args: dict[str, Any],
        tool_call_id: str,
        approve: bool,
        claimed_approver: str | None = None,
        ts_utc: str | None = None,
    ) -> CoreDecision:
        return self.core.submit(
            new_event(
                "human_approved",
                run_id,
                {
                    "approver": claimed_approver
                    if claimed_approver is not None
                    else self.identity,
                    "decision": "approve" if approve else "reject",
                    "scope": "tool_execution",
                    "tool_name": tool,
                    "tool_call_id": tool_call_id,
                    "args_binding_hash": args_digest(tool, args),
                    "policy_revision": request.policy_revision or "",
                    "request_event_id": request.event_id or "",
                },
                ts_utc=ts_utc,
            )
        )

    def revoke(
        self, *, run_id: str, approval_event_id: str, reason: str
    ) -> CoreDecision:
        return self.core.submit(
            new_event(
                "human_approval_revoked",
                run_id,
                {"approval_event_id": approval_event_id, "reason": reason},
            )
        )


def _parse(ts: str):  # type: ignore[no-untyped-def]
    from datetime import datetime

    return datetime.fromisoformat(ts)


def _now_iso(clock: Callable[[], float]) -> str:
    from datetime import UTC, datetime

    return datetime.fromtimestamp(clock(), tz=UTC).isoformat()


def load_state(path: Path) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def offline_evidence_checks(
    export: dict[str, Any],
    authorizations: list[dict[str, Any]],
    pub: str,
    audience: str,
    run_id: str,
) -> list[dict[str, Any]]:
    """Checks that need only the export and the pinned public key: no access to Core's database or keys."""
    checks: list[dict[str, Any]] = []
    chain = export.get("evidence_hashes", {}).get("log_chain", [])
    continuous = all(
        chain[i]["prev_hash"] == chain[i - 1]["record_hash"]
        for i in range(1, len(chain))
    )
    checks.append(
        {
            "name": "log_chain_links_are_continuous",
            "ok": continuous,
            "detail": f"{len(chain)} records",
        }
    )
    recorded = {entry["event_id"]: entry["record_hash"] for entry in chain}
    for signed in authorizations:
        payload = signed.get("payload", {})
        auth_id = payload.get("authorization_id", "")
        try:
            verify_authorization_signature(signed, pub)
            sig_ok, sig_detail = True, "valid for the pinned key and domain"
        except Exception as exc:  # noqa: BLE001 - report, do not raise, in an evidence check
            sig_ok, sig_detail = False, str(exc)
        checks.append(
            {
                "name": f"authorization_signature {auth_id}",
                "ok": sig_ok,
                "detail": sig_detail,
            }
        )
        bound = payload.get("consequential_record_hash") in recorded.values()
        checks.append(
            {
                "name": f"authorization_bound_to_ledger {auth_id}",
                "ok": bound,
                "detail": "consequential_record_hash is a record in the ledger export",
            }
        )
        checks.append(
            {
                "name": f"authorization_scope {auth_id}",
                "ok": payload.get("run_id") == run_id
                and payload.get("executor_audience") == audience,
                "detail": f"run and audience match ({audience})",
            }
        )
    receipts = [
        e
        for e in export.get("evidence_events", [])
        if e.get("event_type") == "execution_receipt"
    ]
    issued = {a.get("payload", {}).get("authorization_id") for a in authorizations}
    checks.append(
        {
            "name": "every_receipt_matches_an_issued_authorization",
            "ok": all(
                r["payload"].get("execution_authorization_id") in issued
                for r in receipts
            ),
            "detail": f"{len(receipts)} receipt(s)",
        }
    )
    checks.append(
        {
            "name": "one_receipt_per_authorization",
            "ok": len(
                {r["payload"].get("execution_authorization_id") for r in receipts}
            )
            == len(receipts),
            "detail": "no authorization has two receipts",
        }
    )
    return checks
