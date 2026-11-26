"""The pilot workflow: an enterprise agent performs consequential actions on synthetic customer records.

Each step names the requested action, asks AIGov Core for a decision, and, when Core authorizes a call, lets the
executor verify the authorization and perform the side effect. The steps and their acceptance checks map to the pilot's
acceptance criteria (see ``docs/customer-pilot.md``).

Every decision comes from Core. Every side effect comes from the executor, after it has verified Core's signed
authorization. The workflow itself does not decide anything.
"""

from __future__ import annotations

import hashlib
import json
import time
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from aigov_py.canonical_json import canonical_bytes
from aigov_py.trusted import (
    AgentActor,
    ApproverActor,
    CoreClient,
    Decision,
    ExecutionStore,
    Executor,
    migrate,
    offline_evidence_checks,
)
from pilot_config import (
    AGENT_IDENTITY,
    APPROVER_IDENTITIES,
    PILOT_TOOLS,
    TENANT,
)


def _apply_migration(path: Path) -> None:
    """Apply the executor store migration (out of band, before first use). Customers do this with their own tooling."""
    path.parent.mkdir(parents=True, exist_ok=True)
    migrate(path, backup_dir=None)


CUSTOMERS: dict[str, dict[str, Any]] = {
    "CUST-1001": {
        "name": "Ada Example",
        "email": "ada@customer.example.test",
        "tier": "gold",
        "consent_marketing": True,
        "country": "DE",
    },
    "CUST-1002": {
        "name": "Ben Sample",
        "email": "ben@customer.example.test",
        "tier": "silver",
        "consent_marketing": False,
        "country": "FR",
    },
    "CUST-1003": {
        "name": "Cora Demo",
        "email": "cora@customer.example.test",
        "tier": "bronze",
        "consent_marketing": True,
        "country": "NL",
    },
}


class RecordStore:
    """Synthetic customer records and the side effects the executor performs on them."""

    def __init__(self, out_dir: Path) -> None:
        self.records = json.loads(json.dumps(CUSTOMERS))
        self.exports_dir = out_dir / "exports"
        self.exports_dir.mkdir(parents=True, exist_ok=True)
        self.deleted: list[str] = []

    def digest(self, customer_id: str) -> str:
        return hashlib.sha256(canonical_bytes(self.records[customer_id])).hexdigest()

    def performer(
        self, tool: str, arguments: dict[str, Any], execution_id: str
    ) -> dict[str, Any]:
        cid = str(arguments.get("customer_id", ""))
        if cid not in self.records:
            return {
                "success": False,
                "data": None,
                "blocked_reason": "unknown_customer",
            }
        if tool == "read_customer_record":
            rec = self.records[cid]
            return {
                "success": True,
                "data": {"customer_id": cid, "name": rec["name"], "tier": rec["tier"]},
            }
        if tool == "export_customer_data":
            path = self.exports_dir / f"{cid}-{execution_id}.json"
            path.write_text(
                json.dumps(
                    {
                        "customer_id": cid,
                        "record": self.records[cid],
                        "purpose": arguments.get("purpose", ""),
                    },
                    indent=2,
                    sort_keys=True,
                )
            )
            return {
                "success": True,
                "data": {
                    "export_file": f"exports/{path.name}",
                    "fields": sorted(self.records[cid]),
                },
            }
        if tool == "update_customer_record":
            before = self.digest(cid)
            changes = dict(arguments.get("changes", {}))
            self.records[cid].update(changes)
            return {
                "success": True,
                "data": {
                    "updated_fields": sorted(changes),
                    "before": before,
                    "after": self.digest(cid),
                },
            }
        if tool == "delete_customer_record":
            self.deleted.append(cid)
            del self.records[cid]
            return {"success": True, "data": {"deleted": cid}}
        return {"success": False, "data": None, "blocked_reason": "unsupported_tool"}


@dataclass
class Step:
    step: int
    title: str
    requested_action: str
    arguments: dict[str, Any]
    core_decision: str
    core_reason: str
    authorization_id: str | None = None
    authorization_expires_at: str | None = None
    approval_event_id: str | None = None
    executed: bool = False
    executor_reason: str | None = None
    receipt_recorded: bool = False
    result: dict[str, Any] | None = None
    core_event_id: str | None = None
    core_record_hash: str | None = None
    timings_ms: dict[str, float] = field(default_factory=dict)
    checks: list[dict[str, Any]] = field(default_factory=list)

    def check(self, name: str, ok: bool, detail: str = "") -> None:
        self.checks.append({"name": name, "ok": bool(ok), "detail": detail})


@dataclass
class PilotRun:
    run_id: str
    core_url: str
    steps: list[Step]
    acceptance: list[dict[str, Any]]
    timings_ms: dict[str, float]
    started_utc: str
    finished_utc: str
    policy_revision: str | None
    authorizations: list[dict[str, Any]]
    core_verify: dict[str, Any]
    export_summary: dict[str, Any]
    evidence_checks: list[dict[str, Any]]


def _ms(start: float) -> float:
    return round((time.perf_counter() - start) * 1000.0, 3)


def run_pilot(core_url: str, state: dict[str, Any], out_dir: Path) -> PilotRun:
    """Run the workflow against a running Core. Writes evidence files under ``out_dir``."""
    out_dir.mkdir(parents=True, exist_ok=True)
    keys = state["keys"]
    ids = state["approver_identities"]
    pub = state["authorization_public_key"]
    audience = state["executor_audience"]
    run_id = f"pilot-{uuid.uuid4().hex[:12]}"
    started = time.time()
    t_all = time.perf_counter()

    agent = AgentActor(CoreClient(core_url, keys["agent"]), run_id, PILOT_TOOLS)
    steward = ApproverActor(
        CoreClient(core_url, keys["steward"]), ids["steward"], PILOT_TOOLS
    )
    owner = ApproverActor(
        CoreClient(core_url, keys["owner"]), ids["owner"], PILOT_TOOLS
    )
    outsider = ApproverActor(
        CoreClient(core_url, keys["outsider"]), ids["outsider"], PILOT_TOOLS
    )
    agent_as_approver = ApproverActor(
        CoreClient(core_url, keys["agent"]), AGENT_IDENTITY, PILOT_TOOLS
    )
    executor_core = CoreClient(core_url, keys["executor"])
    _apply_migration(out_dir / "executor.sqlite")
    records = RecordStore(out_dir)
    executor = Executor(
        core=executor_core,
        public_key_b64=pub,
        audience=audience,
        store=ExecutionStore(out_dir / "executor.sqlite"),
        tools=PILOT_TOOLS,
        performer=records.performer,
    )

    steps: list[Step] = []
    authorizations: list[dict[str, Any]] = []
    policy_revision: str | None = None

    def record_decision(step: Step, outcome: Any) -> None:
        step.core_decision = outcome.decision.value
        step.core_reason = outcome.reason
        step.core_event_id = outcome.event_id
        step.core_record_hash = outcome.record_hash
        if outcome.authorization:
            payload = outcome.authorization.get("payload", {})
            step.authorization_id = payload.get("authorization_id")
            step.authorization_expires_at = payload.get("expires_at_utc")
            authorizations.append(outcome.authorization)

    def execute(
        step: Step,
        tool: str,
        args: dict[str, Any],
        authorization: dict[str, Any] | None,
    ) -> None:
        t = time.perf_counter()
        out = executor.execute(
            run_id=run_id, tool=tool, arguments=args, signed=authorization or {}
        )
        step.timings_ms["executor_ms"] = _ms(t)
        step.executed = out.executed
        step.executor_reason = out.reason
        step.receipt_recorded = out.receipt_recorded
        if out.executed:
            step.result = _receipt_summary(executor, step.authorization_id)

    # 1. Read a customer record (no approval needed; still authorized by Core and run by the executor).
    s = Step(
        1,
        "Read a customer record",
        "read_customer_record",
        {"customer_id": "CUST-1001"},
        "",
        "",
    )
    t = time.perf_counter()
    d = agent.read("read_customer_record", s.arguments, "tc-read-1001")
    s.timings_ms["core_ms"] = _ms(t)
    record_decision(s, d)
    execute(s, "read_customer_record", s.arguments, d.authorization)
    s.check(
        "core_authorizes_read",
        d.decision == Decision.ALLOW and bool(d.authorization),
        d.reason,
    )
    s.check(
        "executor_ran_read_once",
        s.executed and s.receipt_recorded,
        s.executor_reason or "",
    )
    steps.append(s)
    policy_revision = d.policy_revision or policy_revision

    # 2. Request a sensitive export. It must not run without a human approval.
    export_args = {"customer_id": "CUST-1001", "purpose": "subject access request"}
    s = Step(
        2,
        "Request a sensitive data export (needs human approval)",
        "export_customer_data",
        export_args,
        "",
        "",
    )
    req_export = agent.request_approval(
        "export_customer_data", export_args, "tc-export-1001"
    )
    t = time.perf_counter()
    d = agent.submit_write(
        "export_customer_data", export_args, "tc-export-1001", req_export.event_id or ""
    )
    s.timings_ms["core_ms"] = _ms(t)
    record_decision(s, d)
    s.approval_event_id = req_export.event_id
    s.check(
        "export_held_for_approval",
        d.decision == Decision.REQUIRE_APPROVAL and not d.authorization,
        d.reason,
    )
    s.check(
        "no_export_before_approval",
        not any(p.name.startswith("CUST-1001") for p in records.exports_dir.iterdir()),
    )
    steps.append(s)

    # 3. Unauthorized action: the agent tries to delete the record.
    delete_args = {"customer_id": "CUST-1001"}
    s = Step(
        3,
        "Attempt an unauthorized action (delete a customer record)",
        "delete_customer_record",
        delete_args,
        "",
        "",
    )
    req_delete = agent.request_approval(
        "delete_customer_record", delete_args, "tc-delete-1001"
    )
    t = time.perf_counter()
    d = agent.submit_write(
        "delete_customer_record",
        delete_args,
        "tc-delete-1001",
        req_delete.event_id or "",
    )
    s.timings_ms["core_ms"] = _ms(t)
    record_decision(s, d)
    s.check(
        "unauthorized_action_refused",
        d.decision == Decision.DENY and d.reason == "tool_not_permitted",
        d.reason,
    )
    s.check(
        "record_not_deleted", "CUST-1001" in records.records and not records.deleted
    )
    steps.append(s)

    # 4. Approval impersonation: three attempts, each refused by Core.
    s = Step(
        4,
        "Approval impersonation attempts (agent self-approval, outsider, identity claim)",
        "approve export_customer_data",
        export_args,
        "",
        "",
    )
    t = time.perf_counter()
    d_self = agent_as_approver.decide(
        run_id=run_id,
        request=req_export,
        tool="export_customer_data",
        args=export_args,
        tool_call_id="tc-export-1001",
        approve=True,
    )
    d_out = outsider.decide(
        run_id=run_id,
        request=req_export,
        tool="export_customer_data",
        args=export_args,
        tool_call_id="tc-export-1001",
        approve=True,
    )
    d_claim = steward.decide(
        run_id=run_id,
        request=req_export,
        tool="export_customer_data",
        args=export_args,
        tool_call_id="tc-export-1001",
        approve=True,
        claimed_approver=ids["owner"],
    )
    s.timings_ms["core_ms"] = _ms(t)
    s.core_decision = "DENY"
    s.core_reason = f"self={d_self.reason}; outsider={d_out.reason}; claimed_identity={d_claim.reason}"
    s.check(
        "agent_self_approval_refused",
        d_self.decision == Decision.DENY and d_self.reason == "role_not_permitted",
        d_self.reason,
    )
    s.check(
        "outsider_approval_refused",
        d_out.decision == Decision.DENY and d_out.reason == "approver_not_allowlisted",
        d_out.reason,
    )
    s.check(
        "claimed_identity_refused",
        d_claim.decision == Decision.DENY
        and d_claim.reason == "approver_identity_mismatch",
        d_claim.reason,
    )
    steps.append(s)

    # 5. Human oversight: the data steward approves the export under its own identity.
    s = Step(
        5,
        "The data steward approves the export (authenticated approver)",
        "approve export_customer_data",
        export_args,
        "",
        "",
    )
    t = time.perf_counter()
    approval_export = steward.decide(
        run_id=run_id,
        request=req_export,
        tool="export_customer_data",
        args=export_args,
        tool_call_id="tc-export-1001",
        approve=True,
    )
    s.timings_ms["approve_core_ms"] = _ms(t)
    record_decision(s, approval_export)
    s.approval_event_id = approval_export.event_id
    s.check(
        "steward_approval_recorded",
        approval_export.decision == Decision.ALLOW,
        approval_export.reason,
    )
    steps.append(s)

    # 6. The approved export runs: Core authorizes, the executor verifies, performs, and records a receipt.
    s = Step(
        6,
        "Execute the approved export through the trusted executor",
        "export_customer_data",
        export_args,
        "",
        "",
    )
    t = time.perf_counter()
    d = agent.submit_write(
        "export_customer_data",
        export_args,
        "tc-export-1001",
        approval_export.event_id or "",
    )
    s.timings_ms["core_ms"] = _ms(t)
    record_decision(s, d)
    s.approval_event_id = approval_export.event_id
    s.check(
        "core_authorizes_export",
        d.decision == Decision.ALLOW and bool(d.authorization),
        d.reason,
    )
    export_authorization = d.authorization
    execute(s, "export_customer_data", export_args, export_authorization)
    s.check(
        "export_executed_once_with_receipt",
        s.executed and s.receipt_recorded,
        s.executor_reason or "",
    )
    s.check(
        "export_file_written",
        any(p.name.startswith("CUST-1001") for p in records.exports_dir.iterdir()),
    )
    steps.append(s)

    # 7. Replay: the same authorization presented again is refused by the executor.
    s = Step(
        7,
        "Replay the same execution authorization",
        "export_customer_data",
        export_args,
        "",
        "",
    )
    t = time.perf_counter()
    replay = executor.execute(
        run_id=run_id,
        tool="export_customer_data",
        arguments=export_args,
        signed=export_authorization or {},
    )
    s.timings_ms["executor_ms"] = _ms(t)
    s.core_decision = "n/a (executor)"
    s.core_reason = replay.reason
    s.executor_reason = replay.reason
    s.check(
        "replay_refused",
        not replay.executed and replay.reason.startswith("authorization_"),
        replay.reason,
    )
    s.check(
        "export_not_repeated", len(list(records.exports_dir.glob("CUST-1001*"))) == 1
    )
    steps.append(s)

    # 8. Update a customer record: the records owner approves, the executor applies the change.
    update_args = {
        "customer_id": "CUST-1002",
        "changes": {"email": "ben.new@customer.example.test"},
    }
    s = Step(
        8,
        "Update a customer record (owner approves; executor applies the change)",
        "update_customer_record",
        update_args,
        "",
        "",
    )
    req_update = agent.request_approval(
        "update_customer_record", update_args, "tc-update-1002"
    )
    t = time.perf_counter()
    approval_update = owner.decide(
        run_id=run_id,
        request=req_update,
        tool="update_customer_record",
        args=update_args,
        tool_call_id="tc-update-1002",
        approve=True,
    )
    s.timings_ms["approve_core_ms"] = _ms(t)
    before = records.digest("CUST-1002")
    t = time.perf_counter()
    d = agent.submit_write(
        "update_customer_record",
        update_args,
        "tc-update-1002",
        approval_update.event_id or "",
    )
    s.timings_ms["core_ms"] = _ms(t)
    record_decision(s, d)
    s.approval_event_id = approval_update.event_id
    s.check(
        "core_authorizes_update",
        d.decision == Decision.ALLOW and bool(d.authorization),
        d.reason,
    )
    execute(s, "update_customer_record", update_args, d.authorization)
    after = records.digest("CUST-1002")
    s.check(
        "update_executed_with_receipt",
        s.executed and s.receipt_recorded,
        s.executor_reason or "",
    )
    s.check(
        "record_changed",
        before != after
        and records.records["CUST-1002"]["email"] == "ben.new@customer.example.test",
    )
    steps.append(s)

    # 9. Core unavailable: fail closed at the agent and at the executor, then recover.
    s = Step(
        9,
        "Core unavailable: nothing runs; the same authorization runs after recovery",
        "update_customer_record",
        {"customer_id": "CUST-1003", "changes": {"tier": "gold"}},
        "",
        "",
    )
    cora_args = s.arguments
    req_cora = agent.request_approval(
        "update_customer_record", cora_args, "tc-update-1003"
    )
    approval_cora = owner.decide(
        run_id=run_id,
        request=req_cora,
        tool="update_customer_record",
        args=cora_args,
        tool_call_id="tc-update-1003",
        approve=True,
    )
    before_cora = records.digest("CUST-1003")
    unreachable = CoreClient("http://127.0.0.1:9", keys["agent"], timeout_sec=2.0)
    down_agent = AgentActor(unreachable, run_id, PILOT_TOOLS)
    t = time.perf_counter()
    d_down = down_agent.submit_write(
        "update_customer_record",
        cora_args,
        "tc-update-1003",
        approval_cora.event_id or "",
    )
    s.timings_ms["core_ms"] = _ms(t)
    record_decision(s, d_down)
    s.check(
        "agent_fails_closed",
        d_down.decision == Decision.INDETERMINATE and not d_down.authorization,
        d_down.reason,
    )
    d_ok = agent.submit_write(
        "update_customer_record",
        cora_args,
        "tc-update-1003",
        approval_cora.event_id or "",
    )
    record_decision(s, d_ok)
    down_executor = Executor(
        core=unreachable,
        public_key_b64=pub,
        audience=audience,
        store=ExecutionStore(out_dir / "executor.sqlite"),
        tools=PILOT_TOOLS,
        performer=records.performer,
    )
    t = time.perf_counter()
    out_down = down_executor.execute(
        run_id=run_id,
        tool="update_customer_record",
        arguments=cora_args,
        signed=d_ok.authorization or {},
    )
    s.timings_ms["executor_while_down_ms"] = _ms(t)
    s.executor_reason = out_down.reason
    s.check(
        "executor_fails_closed",
        not out_down.executed and out_down.reason == "core_unavailable",
        out_down.reason,
    )
    s.check("record_unchanged_while_down", records.digest("CUST-1003") == before_cora)
    execute(s, "update_customer_record", cora_args, d_ok.authorization)
    s.check(
        "runs_after_recovery",
        s.executed and s.receipt_recorded,
        s.executor_reason or "",
    )
    steps.append(s)

    total_ms = _ms(t_all)
    finished = time.time()

    # Evidence: Core's own verification and export, and the offline checks.
    core_ok, core_msg = executor_core.verify_run(run_id)
    export = executor_core.export(run_id)
    evidence_checks = offline_evidence_checks(
        export, authorizations, pub, audience, run_id
    )
    evidence_checks.insert(
        0, {"name": "core_chain_verifies", "ok": core_ok, "detail": core_msg}
    )
    events = export.get("evidence_events", [])
    receipts = [e for e in events if e.get("event_type") == "execution_receipt"]
    summary = {
        "events": len(events),
        "event_types": sorted({e.get("event_type", "") for e in events}),
        "authorizations_issued": len(authorizations),
        "receipts": len(receipts),
    }

    acceptance = _acceptance(steps, evidence_checks)
    run = PilotRun(
        run_id=run_id,
        core_url=core_url,
        steps=steps,
        acceptance=acceptance,
        timings_ms={"workflow_total_ms": total_ms},
        started_utc=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(started)),
        finished_utc=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(finished)),
        policy_revision=policy_revision,
        authorizations=authorizations,
        core_verify={"ok": core_ok, "message": core_msg},
        export_summary=summary,
        evidence_checks=evidence_checks,
    )
    _write_evidence(out_dir, run, export, authorizations)
    return run


def _receipt_summary(
    executor: Executor, authorization_id: str | None
) -> dict[str, Any] | None:
    if not authorization_id:
        return None
    row = executor.store.row(authorization_id)
    if row is None:
        return None
    return {
        "state": row["state"],
        "outcome": row["outcome"],
        "result_digest": row["result_digest"],
        "finished_at_utc": row["finished_at_utc"],
        "receipt_event_id": row["receipt_event_id"],
    }


def _acceptance(
    steps: list[Step], evidence_checks: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    def ok(step_no: int, check: str) -> bool:
        s = next(x for x in steps if x.step == step_no)
        return any(c["name"] == check and c["ok"] for c in s.checks)

    return [
        {
            "criterion": "Unauthorized actions prevented",
            "evidence": "step 3: delete refused by Core (tool_not_permitted); the record is not deleted",
            "ok": ok(3, "unauthorized_action_refused") and ok(3, "record_not_deleted"),
        },
        {
            "criterion": "Human oversight enforced",
            "evidence": "step 2: export held for approval; step 6: export runs only after the steward's approval",
            "ok": ok(2, "export_held_for_approval")
            and ok(2, "no_export_before_approval")
            and ok(6, "core_authorizes_export"),
        },
        {
            "criterion": "Approval impersonation prevented",
            "evidence": "step 4: agent self-approval, outsider approval, and identity claim each refused",
            "ok": ok(4, "agent_self_approval_refused")
            and ok(4, "outsider_approval_refused")
            and ok(4, "claimed_identity_refused"),
        },
        {
            "criterion": "Execution replay prevented",
            "evidence": "step 7: the same authorization presented again is refused by the executor",
            "ok": ok(7, "replay_refused") and ok(7, "export_not_repeated"),
        },
        {
            "criterion": "Evidence independently verifiable",
            "evidence": "section 'Evidence verification' of the report: Core's chain check and offline checks",
            "ok": all(c["ok"] for c in evidence_checks),
        },
        {
            "criterion": "Core unavailability handled safely",
            "evidence": "step 9: the agent and the executor fail closed; the record is unchanged; the call runs after recovery",
            "ok": ok(9, "agent_fails_closed")
            and ok(9, "executor_fails_closed")
            and ok(9, "record_unchanged_while_down")
            and ok(9, "runs_after_recovery"),
        },
        {
            "criterion": "Latency measured and reported",
            "evidence": "every step records Core and executor timings; the report gives them",
            "ok": all(
                ("core_ms" in x.timings_ms or "approve_core_ms" in x.timings_ms)
                for x in steps
                if x.step != 7
            )
            and "executor_ms" in next(x for x in steps if x.step == 7).timings_ms,
        },
    ]


def _write_evidence(
    out_dir: Path,
    run: PilotRun,
    export: dict[str, Any],
    authorizations: list[dict[str, Any]],
) -> None:
    ev = out_dir / "evidence"
    ev.mkdir(parents=True, exist_ok=True)
    (ev / "core-export.json").write_text(
        json.dumps(export, indent=2, sort_keys=True, default=str)
    )
    (ev / "authorizations.json").write_text(
        json.dumps(authorizations, indent=2, sort_keys=True)
    )
    (ev / "receipts.json").write_text(
        json.dumps(
            [
                e
                for e in export.get("evidence_events", [])
                if e.get("event_type") == "execution_receipt"
            ],
            indent=2,
            sort_keys=True,
            default=str,
        )
    )
    run_dict = asdict(run)
    (out_dir / "pilot-run.json").write_text(
        json.dumps(run_dict, indent=2, sort_keys=True, default=str)
    )


def approvers_summary() -> dict[str, str]:
    return dict(APPROVER_IDENTITIES)


__all__ = ["TENANT", "PilotRun", "RecordStore", "Step", "run_pilot"]
