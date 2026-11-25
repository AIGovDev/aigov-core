"""Live validation of executor recovery against a real AIGov Core and PostgreSQL.

Every authorization is issued by the Core under test. The executor runs in child processes that are killed with
os._exit at named boundaries. The side effect is a local log, which is the stand-in for an external system; the count of
lines in that log is the number of times the action ran. Core is stopped and started with Docker for the outage case.

    python scripts/executor_recovery_live.py --mode docker --image aigov-core:integration --out <dir>
    python scripts/executor_recovery_live.py --mode binary --binary <aigov_audit> --database-url <postgres url> --out <dir>

Exit 0 only if every check passes. Results are written to <out>/recovery-live.json and <out>/recovery-live.md.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import signal
import sqlite3
import subprocess
import sys
import time
import urllib.request
import uuid
from datetime import UTC, datetime
from importlib.resources import files
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[1]
TESTS = REPO / "python" / "tests"
sys.path.insert(0, str(TESTS))

import _lifecycle_harness as h
from aigov_py.trusted import (
    ExecutionStore,
    Integration,
    IntegrationConfig,
    ReconcilerRegistry,
    ReconciliationRefused,
    Tool,
    apply_reconciliation,
    deliver_pending,
    migrate,
    report,
    start_core,
    stop_core,
)
from aigov_py.trusted.reconcile import make_payload, sign_evidence
from aigov_py.trusted.store import SchemaVersionMismatch
from nacl.signing import SigningKey

CONFIG = IntegrationConfig(
    tenant="exec-live",
    policy_id="exec-live-policy",
    tools=(Tool("create_file", "repo:write", "write", resource_key="repo_id"),),
    approvers={"lead": "lead@exec-live.example"},
    agent_identity="agent:exec-live",
    executor_identity="executor:exec-live",
    auth_ttl_seconds=600,
)
ALLOWED_REFUSALS = {
    "authorization_receipt_recorded",
    "authorization_replayed",
    "authorization_already_started",
}


class Check:
    def __init__(self) -> None:
        self.rows: list[dict[str, Any]] = []

    def add(self, scenario: str, name: str, ok: bool, detail: str = "") -> None:
        self.rows.append(
            {"scenario": scenario, "check": name, "ok": bool(ok), "detail": detail}
        )
        print(
            f"{'pass' if ok else 'FAIL'}  {scenario}: {name}"
            + (f" ({detail})" if detail else ""),
            flush=True,
        )

    @property
    def failed(self) -> list[dict[str, Any]]:
        return [r for r in self.rows if not r["ok"]]


def _integration_for(
    run_id: str, d: Path, core_url: str, state: dict[str, Any]
) -> Integration:
    """An integration bound to one run. Its authorizations carry this run id, so the executors must use it too."""
    migrate(d / "integration" / "executor.sqlite", backup_dir=None)
    return Integration(
        CONFIG,
        core_url,
        state,
        d / "integration",
        lambda t, a, e: {"success": False},
        run_id=run_id,
    )


def _authorization(integ: Integration, call_id: str) -> dict[str, Any]:
    args = h.ARGS
    request = integ.request_approval("create_file", args, call_id)
    approval = integ.approve("lead", request, "create_file", args, call_id)
    decision = integ.call("create_file", args, call_id, approval.event_id or "")
    if decision.authorization is None:
        raise RuntimeError(f"Core did not authorize: {decision.reason}")
    return decision.authorization


def _job(
    step: str,
    *,
    state: dict[str, Any],
    core_url: str,
    run_id: str,
    db: Path,
    effects: Path,
    signed: Any = None,
    **extra: Any,
) -> dict[str, Any]:
    return {
        "step": step,
        "core_url": core_url,
        "executor_key": state["keys"]["executor"],
        "public_key": state["authorization_public_key"],
        "audience": CONFIG.executor_identity,
        "run_id": run_id,
        "db": str(db),
        "effects": str(effects),
        "arguments": h.ARGS,
        "signed": signed,
        **extra,
    }


def _core_for(state: dict[str, Any], core_url: str):  # type: ignore[no-untyped-def]
    from aigov_py.trusted.core import CoreClient

    return CoreClient(core_url, state["keys"]["executor"])


def _receipts(
    state: dict[str, Any], core_url: str, run_id: str, auth_id: str
) -> list[dict[str, Any]]:
    try:
        export = _core_for(state, core_url).export(run_id)
    except RuntimeError:  # no events for this run yet
        return []
    return [
        e
        for e in export.get("evidence_events", [])
        if e.get("event_type") == "execution_receipt"
        and e.get("payload", {}).get("execution_authorization_id") == auth_id
    ]


def _scenario_dir(root: Path, name: str) -> tuple[Path, Path, Path]:
    d = root / name
    d.mkdir(parents=True, exist_ok=True)
    db = d / "executor.sqlite"
    migrate(
        db, backup_dir=None
    )  # the operator step, before the executor first opens the store
    return db, d / "effects.log", d


def _sleep_past_lease() -> None:
    time.sleep(2.2)


def run(args: argparse.Namespace) -> int:
    check = Check()
    root = Path(args.out).resolve()
    root.mkdir(parents=True, exist_ok=True)
    state_dir = (
        Path.home() / ".cache" / "aigov-executor-live" / f"run-{uuid.uuid4().hex[:8]}"
    )
    started = time.time()
    running, prefix = start_core(
        CONFIG,
        state_dir,
        port=args.port,
        mode=args.mode,
        image=args.image,
        binary=Path(args.binary) if args.binary else None,
        database_url=args.database_url,
    )
    timings: dict[str, float] = {
        "core_ready_seconds": round(running.started_seconds, 2)
    }
    try:
        state = json.loads(running.state_file.read_text())
        core_url = running.core_url
        core_only = _core_for(state, core_url)
        identity, lead_seed = _operator()
        registry = ReconcilerRegistry(keys={identity: _pub(lead_seed)})

        def fresh_run(name: str) -> tuple[str, Path, Path, Path, Any]:
            run_id = f"run-{name}-{uuid.uuid4().hex[:6]}"
            db, effects, d = _scenario_dir(root, name)
            integ = _integration_for(run_id, d, core_url, state)
            return (
                run_id,
                db,
                effects,
                d,
                _authorization(integ, f"call-{name}-{uuid.uuid4().hex[:6]}"),
            )

        # 1. concurrent workers cannot both perform the same authorization
        s = "1-concurrent-workers"
        run_id, db, effects, d, signed = fresh_run("concurrent")
        auth = signed["payload"]["authorization_id"]
        procs = []
        for i in range(8):
            job = _job(
                "execute",
                state=state,
                core_url=core_url,
                run_id=run_id,
                db=db,
                effects=effects,
                signed=signed,
                worker=f"w{i}",
            )
            jp = d / f"job-{i}.json"
            jp.write_text(json.dumps(job))
            code = f"import sys; sys.path.insert(0, {str(TESTS)!r}); import _lifecycle_harness as h; sys.exit(h.child_main({str(jp)!r}))"
            procs.append(
                subprocess.Popen(
                    [sys.executable, "-c", code], stdout=subprocess.PIPE, text=True
                )
            )
        results = [json.loads(p.communicate(timeout=180)[0]) for p in procs]
        executed = [r for r in results if r["executed"]]
        check.add(
            s,
            "exactly one of eight concurrent workers performs the action",
            len(executed) == 1,
            f"{len(executed)} executed",
        )
        check.add(s, "the side effect ran once", h.SideEffects(effects).count() == 1)
        check.add(
            s,
            "every other worker is refused",
            {r["reason"] for r in results} - {"executed"} <= ALLOWED_REFUSALS,
            ", ".join(sorted({r["reason"] for r in results})),
        )
        check.add(
            s,
            "Core holds one receipt for the authorization",
            len(_receipts(state, core_url, run_id, auth)) == 1,
        )

        # 2. process crashes at each boundary
        def crash(name: str, step: str, **kw: Any) -> tuple[str, Path, Path, Any, int]:
            run_id, db, effects, d, signed = fresh_run(name)
            job = _job(
                step,
                state=state,
                core_url=core_url,
                run_id=run_id,
                db=db,
                effects=effects,
                signed=signed,
                **kw,
            )
            code, _out = h.run_child(job, d)
            return run_id, db, effects, signed, code

        def recover(
            run_id: str, db: Path, effects: Path, d_name: str, **kw: Any
        ) -> dict[str, Any]:
            job = _job(
                "recover",
                state=state,
                core_url=core_url,
                run_id=run_id,
                db=db,
                effects=effects,
                **kw,
            )
            code, out = h.run_child(job, root / d_name)
            return {
                "code": code,
                "actions": json.loads(out)["actions"]
                if code == 0 and out.strip()
                else [],
            }

        s = "2-crash-boundaries"
        # before reservation: nothing persisted; a retry runs once
        rid, db, eff, signed, code = crash(
            "before-reserve", "execute", crash_at="before_reserve"
        )
        auth = signed["payload"]["authorization_id"]
        check.add(s, "crash before reservation: process terminated", code == 137)
        check.add(
            s,
            "crash before reservation: no record written",
            ExecutionStore(db).row(auth) is None,
        )
        code2, out = h.run_child(
            _job(
                "execute",
                state=state,
                core_url=core_url,
                run_id=rid,
                db=db,
                effects=eff,
                signed=signed,
            ),
            root / "before-reserve",
        )
        check.add(
            s,
            "crash before reservation: retry runs the action once",
            code2 == 0 and h.SideEffects(eff).count() == 1,
        )

        # after reservation, before execution: resumed exactly once
        rid, db, eff, signed, code = crash(
            "after-reserve", "execute", crash_at="after_reserve"
        )
        auth = signed["payload"]["authorization_id"]
        check.add(s, "crash after reservation: process terminated", code == 137)
        check.add(
            s,
            "crash after reservation: the reservation survived",
            ExecutionStore(db).row(auth)["state"] == "reserved",
        )
        t0 = time.perf_counter()
        r = recover(rid, db, eff, "after-reserve")
        timings["recover_after_reserve_ms"] = round(
            (time.perf_counter() - t0) * 1000, 1
        )
        check.add(
            s,
            "restarted executor resumes the reservation",
            r["actions"][0]["action"] == "resumed_once",
        )
        check.add(s, "resumed action ran once", h.SideEffects(eff).count() == 1)
        check.add(
            s,
            "receipt reached Core once",
            len(_receipts(state, core_url, rid, auth)) == 1,
        )

        # immediately before the side effect: unknown, never retried
        rid, db, eff, signed, code = crash(
            "before-side-effect", "execute", crash_at="before_side_effect", lease=1
        )
        auth = signed["payload"]["authorization_id"]
        check.add(s, "crash before the side effect: process terminated", code == 137)
        _sleep_past_lease()
        r = recover(rid, db, eff, "before-side-effect")
        check.add(
            s,
            "crash before the side effect: outcome recorded as unknown",
            r["actions"][0]["action"] == "outcome_unknown",
        )
        r2 = recover(rid, db, eff, "before-side-effect")
        check.add(
            s,
            "crash before the side effect: a second restart does not retry",
            h.SideEffects(eff).count() == 0
            and r2["actions"][0]["action"] == "awaiting_reconciliation",
        )

        # during the external side effect: unknown, never retried
        rid, db, eff, signed, code = crash(
            "during-side-effect", "execute", lease=1, crash_inside=True
        )
        auth = signed["payload"]["authorization_id"]
        check.add(s, "crash during the side effect: process terminated", code == 137)
        check.add(
            s,
            "crash during the side effect: the action had started",
            h.SideEffects(eff).count() == 1,
        )
        _sleep_past_lease()
        recover(rid, db, eff, "during-side-effect")
        recover(rid, db, eff, "during-side-effect")
        check.add(
            s,
            "crash during the side effect: unknown, and not repeated",
            h.SideEffects(eff).count() == 1
            and ExecutionStore(db).row(auth)["state"] == "reconciliation_required",
        )

        # after the side effect, before the outcome is recorded: unknown
        rid, db, eff, signed, code = crash(
            "after-side-effect",
            "execute",
            crash_at="after_side_effect_before_finish",
            lease=1,
        )
        auth = signed["payload"]["authorization_id"]
        check.add(s, "crash after the side effect: process terminated", code == 137)
        _sleep_past_lease()
        recover(rid, db, eff, "after-side-effect")
        check.add(
            s,
            "crash after the side effect: outcome unknown, action not repeated",
            ExecutionStore(db).row(auth)["state"] == "reconciliation_required"
            and h.SideEffects(eff).count() == 1,
        )

        # after the outcome, before the receipt is sent: the receipt is resent, the action is not
        rid, db, eff, signed, code = crash(
            "before-receipt", "execute", crash_at="after_finish_before_receipt_submit"
        )
        auth = signed["payload"]["authorization_id"]
        check.add(s, "crash before the receipt: process terminated", code == 137)
        check.add(
            s,
            "crash before the receipt: Core holds no receipt yet",
            _receipts(state, core_url, rid, auth) == [],
        )
        r = recover(rid, db, eff, "before-receipt")
        check.add(
            s,
            "crash before the receipt: receipt delivered on restart",
            r["actions"][0]["action"] == "receipt_recorded",
        )
        check.add(
            s,
            "crash before the receipt: action not repeated, one receipt",
            h.SideEffects(eff).count() == 1
            and len(_receipts(state, core_url, rid, auth)) == 1,
        )

        # Core stored the receipt, but the executor never learned so: settled from the export, no duplicate
        rid, db, eff, signed, code = crash(
            "receipt-ack-lost", "execute", crash_at="after_receipt_submitted_before_ack"
        )
        auth = signed["payload"]["authorization_id"]
        check.add(s, "receipt acknowledgement lost: process terminated", code == 137)
        check.add(
            s,
            "receipt acknowledgement lost: Core already holds the receipt",
            len(_receipts(state, core_url, rid, auth)) == 1,
        )
        r = recover(rid, db, eff, "receipt-ack-lost")
        check.add(
            s,
            "receipt acknowledgement lost: settled from Core's export",
            r["actions"][0]["action"] == "receipt_recorded",
        )
        check.add(
            s,
            "receipt acknowledgement lost: no duplicate receipt, action not repeated",
            len(_receipts(state, core_url, rid, auth)) == 1
            and h.SideEffects(eff).count() == 1,
        )

        # recovery itself is killed: the next restart still does the right thing
        rid, db, eff, signed, code = crash(
            "recovery-killed", "execute", crash_at="after_reserve"
        )
        auth = signed["payload"]["authorization_id"]
        code_r, _ = h.run_child(
            _job(
                "recover",
                state=state,
                core_url=core_url,
                run_id=rid,
                db=db,
                effects=eff,
                crash_at="recovery_before_resume",
            ),
            root / "recovery-killed",
        )
        check.add(s, "recovery killed mid-resume: process terminated", code_r == 137)
        r = recover(rid, db, eff, "recovery-killed")
        check.add(
            s,
            "recovery killed mid-resume: the next restart resumes once",
            r["actions"][0]["action"] == "resumed_once"
            and h.SideEffects(eff).count() == 1,
        )

        # 3. ambiguous outcome, reconciliation by signed evidence
        s = "3-reconciliation"
        rid, db, eff, d, signed = fresh_run("reconcile")
        auth = signed["payload"]["authorization_id"]
        job = _job(
            "execute",
            state=state,
            core_url=core_url,
            run_id=rid,
            db=db,
            effects=eff,
            signed=signed,
            raise_inside=True,
        )
        code, out = h.run_child(job, d)
        check.add(
            s,
            "external system fails mid-call: outcome recorded as unknown",
            json.loads(out)["state"] == "reconciliation_required",
        )
        check.add(
            s,
            "unknown outcome: not retried by recovery",
            recover(rid, db, eff, "reconcile")["actions"][0]["action"]
            == "awaiting_reconciliation"
            and h.SideEffects(eff).count() == 1,
        )
        store = ExecutionStore(db)
        row = store.row(auth)
        evidence_path = d / "proof.txt"
        evidence_path.write_text("bank statement: payment for order 7781 cleared")

        def envelope(seed: str, reconciler: str, **over: Any) -> dict[str, Any]:
            payload = make_payload(
                row,
                outcome="succeeded",
                external_reference="order-7781",
                external_evidence=evidence_path.read_bytes(),
                reconciler=reconciler,
                observed_at_utc=datetime.now(UTC).isoformat(),
            )
            payload.update(over)
            return sign_evidence(payload, seed)

        _, attacker = _operator()
        for name, env, reason in [
            (
                "forged signature by an unregistered key",
                envelope(attacker, identity),
                "reconciliation_signature_invalid",
            ),
            (
                "unlisted reconciler identity",
                envelope(lead_seed, "intern@exec-live.example"),
                "reconciler_not_authorized",
            ),
            (
                "evidence bound to another tool",
                envelope(lead_seed, identity, tool_name="delete_everything"),
                "reconciliation_binding_mismatch",
            ),
        ]:
            try:
                apply_reconciliation(
                    store, env, registry, receipt_event_id="execution_receipt-bad"
                )
                check.add(s, f"rejected: {name}", False, "evidence was accepted")
            except ReconciliationRefused as exc:
                check.add(s, f"rejected: {name}", exc.reason == reason, exc.reason)
        check.add(
            s,
            "rejected evidence changes nothing",
            ExecutionStore(db).row(auth)["state"] == "reconciliation_required",
        )
        evidence = apply_reconciliation(
            store,
            envelope(lead_seed, identity),
            registry,
            receipt_event_id="execution_receipt-ok",
        )
        check.add(
            s,
            "authorized reconciler's evidence is applied",
            evidence["outcome"] == "succeeded",
        )
        delivered = deliver_pending(ExecutionStore(db), core_only)
        check.add(
            s,
            "reconciled outcome receipt delivered to Core",
            [x["recorded"] for x in delivered] == [True],
        )
        rec = _receipts(state, core_url, rid, auth)
        check.add(
            s,
            "Core's receipt names the reconciled outcome",
            bool(rec) and rec[0]["payload"]["outcome"] == "reconciled:succeeded",
        )
        history = [e["event"] for e in ExecutionStore(db).events(auth)]
        check.add(
            s,
            "history keeps the unknown outcome and the reconciliation",
            "outcome_unknown" in history and "reconciled" in history,
        )
        check.add(s, "history verifies", ExecutionStore(db).verify_history()[0])
        check.add(
            s,
            "action ran once, reconciliation did not repeat it",
            h.SideEffects(eff).count() == 1,
        )

        # 4. Core unavailable: nothing bypasses authorization
        s = "4-core-unavailable"
        rid, db, eff, d, signed = fresh_run("outage")
        auth = signed["payload"]["authorization_id"]
        rid2, db2, eff2, d2, signed2 = fresh_run("outage-new")
        auth2 = signed2["payload"]["authorization_id"]
        code, _ = h.run_child(
            _job(
                "execute",
                state=state,
                core_url=core_url,
                run_id=rid,
                db=db,
                effects=eff,
                signed=signed,
                crash_at="after_reserve",
            ),
            d,
        )
        check.add(s, "reservation made before the outage", code == 137)
        container = f"{prefix}-core"
        if args.mode == "docker":
            subprocess.run(
                ["docker", "pause", container], check=True, capture_output=True
            )
        else:
            core_pid = int(
                state["pid"]
            )  # the release binary's process; SIGSTOP makes it unresponsive, not absent
            os.kill(core_pid, signal.SIGSTOP)
        try:
            out_exec = h.run_child(
                _job(
                    "execute",
                    state=state,
                    core_url=core_url,
                    run_id=rid2,
                    db=db2,
                    effects=eff2,
                    signed=signed2,
                ),
                d2,
            )
            reason = (
                json.loads(out_exec[1])["reason"] if out_exec[0] == 0 else "crashed"
            )
            check.add(
                s,
                "new call refused while Core is down",
                reason == "core_unavailable",
                reason,
            )
            check.add(
                s,
                "refused call left no reservation",
                ExecutionStore(db2).row(auth2) is None,
            )
            r = recover(rid, db, eff, "outage-recover-down")
            check.add(
                s,
                "restart while Core is down defers, performs nothing",
                r["actions"][0]["action"] == "deferred"
                and h.SideEffects(eff).count() == 0,
            )
        finally:
            if args.mode == "docker":
                subprocess.run(
                    ["docker", "unpause", container], check=True, capture_output=True
                )
                _wait_health(core_url)
            else:
                os.kill(core_pid, signal.SIGCONT)
        r = recover(rid, db, eff, "outage-recover-up")
        check.add(
            s,
            "Core back: the deferred reservation resumes once",
            r["actions"][0]["action"] == "resumed_once"
            and h.SideEffects(eff).count() == 1,
        )

        # 5. schema upgrades preserve records
        s = "5-schema-upgrade"
        legacy_dir = root / "legacy"
        legacy_dir.mkdir(parents=True, exist_ok=True)
        legacy = legacy_dir / "legacy.sqlite"
        _legacy_v1(legacy)
        try:
            ExecutionStore(legacy)
            check.add(s, "v1 store refused before upgrade", False)
        except SchemaVersionMismatch:
            check.add(s, "v1 store refused before upgrade", True)
        before = (
            sqlite3.connect(legacy)
            .execute(
                "SELECT authorization_id, outcome, receipt_event_id FROM executions "
                "ORDER BY authorization_id"
            )
            .fetchall()
        )
        result = migrate(legacy, backup_dir=legacy_dir / "backups")
        after = (
            sqlite3.connect(legacy)
            .execute(
                "SELECT authorization_id, outcome, receipt_event_id FROM executions "
                "ORDER BY authorization_id"
            )
            .fetchall()
        )
        check.add(
            s,
            "upgrade takes a backup",
            bool(result["backup"]) and Path(result["backup"]).exists(),
        )
        check.add(
            s, "upgrade preserves every v1 record", before == after and len(after) == 4
        )
        check.add(
            s, "upgraded history verifies", ExecutionStore(legacy).verify_history()[0]
        )

        # 6. visibility over the live runs
        s = "6-visibility"
        all_db = [p for p in root.rglob("executor.sqlite")]
        totals = {"executions": 0, "unknown": 0, "backlog": 0}
        for p in all_db:
            r = report(ExecutionStore(p))
            totals["executions"] += r["executions"]
            totals["unknown"] += r["unknown_outcomes"]
            totals["backlog"] += r["reconciliation_backlog"]
        # eleven executions have a record; the call refused during the outage left none, by design
        check.add(
            s,
            "report covers every live execution with a record",
            totals["executions"] == 11,
            str(totals),
        )
        check.add(
            s,
            "every store's history verifies",
            all(ExecutionStore(p).verify_history()[0] for p in all_db),
        )
        (root / "visibility.json").write_text(
            json.dumps(
                {
                    "stores": [str(p.relative_to(root)) for p in all_db],
                    "totals": totals,
                },
                indent=2,
            )
        )
    finally:
        removed = stop_core(state_dir, prefix)
        print("cleaned up:", "; ".join(removed) or "nothing", flush=True)

    timings["total_seconds"] = round(time.time() - started, 1)
    outcome = {
        "passed": not check.failed,
        "checks": check.rows,
        "timings": timings,
        "mode": args.mode,
        "core_image": args.image if args.mode == "docker" else "binary",
    }
    (root / "recovery-live.json").write_text(json.dumps(outcome, indent=2))
    _write_md(root / "recovery-live.md", outcome)
    print(
        f"\n{len(check.rows) - len(check.failed)} of {len(check.rows)} checks passed",
        flush=True,
    )
    return 0 if not check.failed else 1


def _operator() -> tuple[str, str]:
    sk = SigningKey.generate()
    return "lead@exec-live-ops.example", base64.b64encode(bytes(sk)).decode("ascii")


def _pub(seed_b64: str) -> str:
    return base64.b64encode(
        bytes(SigningKey(base64.b64decode(seed_b64)).verify_key)
    ).decode("ascii")


def _wait_health(url: str, timeout_s: float = 90.0) -> None:
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        try:
            if urllib.request.urlopen(url + "/health", timeout=3).status == 200:
                return
        except OSError:
            pass
        time.sleep(1)
    raise RuntimeError("Core did not become healthy after restart")


def _legacy_v1(path: Path) -> None:
    sql = (
        files("aigov_py.trusted") / "migrations" / "0001_executor_store.sql"
    ).read_text(encoding="utf-8")
    conn = sqlite3.connect(path)
    conn.executescript(sql)
    rows = [
        (
            "auth_legacy_1",
            "run-legacy",
            "create_file",
            "d1",
            "reserved",
            "2026-11-20T10:00:00+00:00",
            None,
            None,
            None,
            None,
            json.dumps(
                {
                    "payload": {
                        "executor_audience": "executor:exec-live",
                        "policy_revision": "rev-a",
                    }
                }
            ),
        ),
        (
            "auth_legacy_2",
            "run-legacy",
            "create_file",
            "d2",
            "executed",
            "2026-11-20T10:01:00+00:00",
            "2026-11-20T10:01:02+00:00",
            "success",
            "r2",
            "receipt_legacy_2",
            json.dumps(
                {
                    "payload": {
                        "executor_audience": "executor:exec-live",
                        "policy_revision": "rev-a",
                    }
                }
            ),
        ),
        (
            "auth_legacy_3",
            "run-legacy",
            "create_file",
            "d3",
            "executed",
            "2026-11-20T10:02:00+00:00",
            "2026-11-20T10:02:01+00:00",
            "success",
            "r3",
            None,
            json.dumps(
                {
                    "payload": {
                        "executor_audience": "executor:exec-live",
                        "policy_revision": "rev-a",
                    }
                }
            ),
        ),
        (
            "auth_legacy_4",
            "run-legacy",
            "create_file",
            "d4",
            "failed",
            "2026-11-20T10:03:00+00:00",
            "2026-11-20T10:03:00+00:00",
            "blocked:policy",
            None,
            None,
            json.dumps(
                {
                    "payload": {
                        "executor_audience": "executor:exec-live",
                        "policy_revision": "rev-a",
                    }
                }
            ),
        ),
    ]
    conn.executemany(
        "INSERT INTO executions (authorization_id, run_id, tool_name, args_digest, state, reserved_at_utc, "
        "finished_at_utc, outcome, result_digest, receipt_event_id, signed_authorization_json) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        rows,
    )
    conn.commit()
    conn.close()


def _write_md(path: Path, outcome: dict[str, Any]) -> None:
    lines = [
        "# Executor recovery, live validation",
        "",
        (
            f"Result: **{'all checks passed' if outcome['passed'] else 'FAILURES'}** "
            f"({sum(1 for c in outcome['checks'] if c['ok'])} of {len(outcome['checks'])} checks). Mode: {outcome['mode']}."
        ),
        "",
        "| Scenario | Check | Result | Detail |",
        "|---|---|---|---|",
    ]
    for c in outcome["checks"]:
        lines.append(
            f"| {c['scenario']} | {c['check']} | {'pass' if c['ok'] else 'FAIL'} | {c['detail']} |"
        )
    lines += ["", f"Timings: {json.dumps(outcome['timings'])}", ""]
    path.write_text("\n".join(lines), encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    p.add_argument("--mode", choices=["docker", "binary"], default="docker")
    p.add_argument("--image", default="aigov-core:integration")
    p.add_argument("--binary")
    p.add_argument("--database-url")
    p.add_argument("--port", type=int, default=18455)
    p.add_argument("--out", required=True)
    args = p.parse_args(argv)
    if args.mode == "binary" and not (args.binary and args.database_url):
        p.error("binary mode needs --binary and --database-url")
    return run(args)


if __name__ == "__main__":
    raise SystemExit(main())
