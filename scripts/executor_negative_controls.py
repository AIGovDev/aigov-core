"""Negative controls: the same executor failure scenarios, run against whichever SDK is on the import path.

Run it once against the staging implementation and once against this change, with PYTHONPATH pointing at the package
under test:

    PYTHONPATH=<staging>/python python scripts/executor_negative_controls.py --label staging --out <dir>
    PYTHONPATH=<this>/python    python scripts/executor_negative_controls.py --label change  --out <dir>

Each control records what the implementation does and what its store and Core say afterwards. A control is a gap in an
implementation when the observation shows a failure goes unseen, a result is lost, or a capability is absent. The
controls use only the calls both implementations share, and probe the rest.

The Core is the file-backed stand-in from the test harness, so every control is deterministic and needs no Docker.
"""

from __future__ import annotations

import argparse
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import uuid
from importlib.resources import files
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[1]
TESTS = REPO / "python" / "tests"
sys.path.insert(0, str(TESTS))

import _lifecycle_harness as h

from aigov_py import trusted


def _prepare(db: Path) -> None:
    """Create a store the way each implementation expects: its migrate tool if it has one, else its schema file."""
    db.parent.mkdir(parents=True, exist_ok=True)
    if hasattr(trusted, "migrate"):
        trusted.migrate(db, backup_dir=None)
        return
    sql = (
        files("aigov_py.trusted") / "migrations" / "0001_executor_store.sql"
    ).read_text(encoding="utf-8")
    conn = sqlite3.connect(db)
    conn.executescript(sql)
    conn.close()


_CHILD = """
import json, os, sys
sys.path.insert(0, {tests!r})
import _lifecycle_harness as h
from aigov_py.trusted import Executor, ExecutionStore
job = json.load(open({job!r}))
core = h.FileCore(job["core"])
if job.get("crash") == "after_submit":
    real_submit = core.submit
    def submit(event):
        decision = real_submit(event)
        os._exit(137)  # Core has stored the receipt; the executor dies before it learns so
    core.submit = submit
effects = h.SideEffects(job["effects"])
performer = effects.performer(crash_inside=job.get("crash") == "in_performer", raise_inside=job.get("raise", False))
ex = Executor(core=core, public_key_b64=job["pub"], audience=h.AUDIENCE, store=ExecutionStore(job["db"]),
              tools=h.TOOLS, performer=performer)
if job["step"] == "execute":
    out = ex.execute(run_id=h.RUN, tool=h.TOOL.name, arguments=h.ARGS, signed=job["signed"])
    print(json.dumps({{"reason": out.reason, "executed": out.executed}}))
else:
    print(json.dumps({{"actions": [a.as_dict() for a in ex.recover()]}}) if hasattr(ex, "recover") else json.dumps({{"actions": None}}))
"""


def _child(workdir: Path, **job: Any) -> tuple[int, str, str]:
    job_path = workdir / f"job-{uuid.uuid4().hex[:8]}.json"
    job_path.write_text(json.dumps(job), encoding="utf-8")
    code = _CHILD.format(tests=str(TESTS), job=str(job_path))
    # Start in the scratch directory: the repository root has its own aigov_py shim, which would win over PYTHONPATH.
    proc = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
        env={**os.environ},
        cwd=str(workdir),
    )
    return (
        proc.returncode,
        proc.stdout.strip(),
        proc.stderr.strip().splitlines()[-1] if proc.stderr.strip() else "",
    )


def _row(db: Path, auth: str) -> dict[str, Any] | None:
    from aigov_py.trusted.store import ExecutionStore

    return ExecutionStore(db).row(auth)


def _fixture(tmp: Path) -> tuple[Path, Path, Path, dict, str]:
    db = tmp / "exec.sqlite"
    _prepare(db)
    core_path = tmp / "core.json"
    effects = tmp / "effects.log"
    seed, pub = h.new_authorization_key()
    signed = h.signed_authorization(seed)
    return db, core_path, effects, signed, pub


def control_crash_mid_side_effect(tmp: Path) -> dict[str, Any]:
    """The process dies after the action began and before any outcome is written."""
    db, core_path, effects, signed, pub = _fixture(tmp)
    h.FileCore(core_path)
    auth = signed["payload"]["authorization_id"]
    code, _, _ = _child(
        tmp,
        step="execute",
        db=str(db),
        core=str(core_path),
        effects=str(effects),
        pub=pub,
        signed=signed,
        crash="in_performer",
    )
    row = _row(db, auth)
    code2, out2, _ = _child(
        tmp,
        step="execute",
        db=str(db),
        core=str(core_path),
        effects=str(effects),
        pub=pub,
        signed=signed,
    )
    code3, out3, _ = _child(
        tmp,
        step="recover",
        db=str(db),
        core=str(core_path),
        effects=str(effects),
        pub=pub,
        signed=signed,
    )
    return {
        "process_died": code == 137,
        "store_state_after_crash": row["state"] if row else None,
        "restart_retry": json.loads(out2)["reason"] if code2 == 0 else f"exit {code2}",
        "restart_recover": json.loads(out3)["actions"]
        if code3 == 0
        else f"exit {code3}",
        "side_effect_count": h.SideEffects(effects).count(),
        "can_tell_the_action_ran": bool(row and row["state"] not in ("reserved",)),
    }


def control_receipt_lost_after_core_stored_it(tmp: Path) -> dict[str, Any]:
    """Core stored the receipt, and the executor died before it recorded the acknowledgement."""
    db, core_path, effects, signed, pub = _fixture(tmp)
    core = h.FileCore(core_path)
    auth = signed["payload"]["authorization_id"]
    code, _, _ = _child(
        tmp,
        step="execute",
        db=str(db),
        core=str(core_path),
        effects=str(effects),
        pub=pub,
        signed=signed,
        crash="after_submit",
    )
    row = _row(db, auth)
    code2, out2, _ = _child(
        tmp,
        step="recover",
        db=str(db),
        core=str(core_path),
        effects=str(effects),
        pub=pub,
        signed=signed,
    )
    row2 = _row(db, auth)
    receipt_field = row2.get("receipt_event_id") if row2 else None
    return {
        "process_died": code == 137,
        "core_receipts": len(core.receipts_for(auth)),
        "store_receipt_after_crash": (row or {}).get("receipt_event_id"),
        "restart_recover": json.loads(out2)["actions"]
        if code2 == 0
        else f"exit {code2}",
        "store_receipt_after_restart": receipt_field,
        "store_agrees_with_core": bool(receipt_field)
        and len(core.receipts_for(auth)) == 1,
        "side_effect_count": h.SideEffects(effects).count(),
    }


def control_two_workers_race(tmp: Path) -> dict[str, Any]:
    db, core_path, effects, signed, pub = _fixture(tmp)
    h.FileCore(core_path)
    procs = []
    for i in range(4):
        job_path = tmp / f"race-{i}.json"
        job_path.write_text(
            json.dumps(
                {
                    "step": "execute",
                    "db": str(db),
                    "core": str(core_path),
                    "effects": str(effects),
                    "pub": pub,
                    "signed": signed,
                }
            )
        )
        code = _CHILD.format(tests=str(TESTS), job=str(job_path))
        procs.append(
            subprocess.Popen(
                [sys.executable, "-c", code],
                stdout=subprocess.PIPE,
                text=True,
                cwd=str(tmp),
            )
        )
    results = [json.loads(p.communicate(timeout=120)[0]) for p in procs]
    return {
        "executed_by": sum(1 for r in results if r["executed"]),
        "side_effect_count": h.SideEffects(effects).count(),
        "refusals": sorted({r["reason"] for r in results if not r["executed"]}),
    }


def control_performer_raises(tmp: Path) -> dict[str, Any]:
    """The external system fails in the middle of the call. The outcome is genuinely unknown."""
    db, core_path, effects, signed, pub = _fixture(tmp)
    h.FileCore(core_path)
    auth = signed["payload"]["authorization_id"]
    code, out, err = _child(
        tmp,
        step="execute",
        db=str(db),
        core=str(core_path),
        effects=str(effects),
        pub=pub,
        signed=signed,
        **{"raise": True},
    )
    row = _row(db, auth)
    code2, out2, _ = _child(
        tmp,
        step="execute",
        db=str(db),
        core=str(core_path),
        effects=str(effects),
        pub=pub,
        signed=signed,
    )
    return {
        "first_call_exit": code,
        "first_call_result": json.loads(out)["reason"]
        if out.startswith("{")
        else f"unhandled: {err[:80]}",
        "store_state": row["state"] if row else None,
        "retry_after_failure": json.loads(out2)["reason"]
        if code2 == 0
        else f"exit {code2}",
        "side_effect_count": h.SideEffects(effects).count(),
        "outcome_recorded_as_unknown": bool(
            row and row["state"] in ("outcome_unknown", "reconciliation_required")
        ),
    }


def control_recorded_outcome_altered(tmp: Path) -> dict[str, Any]:
    """Someone with database access edits a recorded outcome after the fact."""
    db, core_path, effects, signed, pub = _fixture(tmp)
    h.FileCore(core_path)
    auth = signed["payload"]["authorization_id"]
    _child(
        tmp,
        step="execute",
        db=str(db),
        core=str(core_path),
        effects=str(effects),
        pub=pub,
        signed=signed,
    )
    conn = sqlite3.connect(db)
    conn.execute(
        "UPDATE executions SET outcome = 'blocked:forged', state = 'failed' WHERE authorization_id = ?",
        (auth,),
    )
    conn.commit()
    conn.close()
    detected: Any = "no check exists"
    if hasattr(trusted.ExecutionStore, "verify_projection"):
        detected = bool(not trusted.ExecutionStore(db).verify_projection()[0])
    return {"edit_accepted": True, "detected_by_store_check": detected}


def control_capabilities(tmp: Path) -> dict[str, Any]:
    """What the implementation provides at all: its schema management, reconciliation, recovery, and visibility."""
    db = tmp / "caps.sqlite"
    _prepare(db)
    conn = sqlite3.connect(db)
    version = conn.execute("PRAGMA user_version").fetchone()[0]
    conn.close()
    return {
        "schema_version_recorded": version,
        "versioned_migrations_tool": hasattr(trusted, "migrate"),
        "reconciliation_by_signed_evidence": hasattr(trusted, "apply_reconciliation"),
        "recovery_after_restart": hasattr(trusted.Executor, "recover"),
        "operational_report": hasattr(trusted, "report"),
        "append_only_history": hasattr(trusted, "ExecutionStore")
        and hasattr(trusted.ExecutionStore, "events"),
    }


CONTROLS = [
    ("C1 crash in the middle of the side effect", control_crash_mid_side_effect),
    ("C2 receipt lost after Core stored it", control_receipt_lost_after_core_stored_it),
    ("C3 two workers race for one authorization", control_two_workers_race),
    ("C4 external system fails mid-call", control_performer_raises),
    ("C5 recorded outcome edited after the fact", control_recorded_outcome_altered),
    ("C6 capabilities", control_capabilities),
]


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--label", required=True)
    p.add_argument("--out", required=True)
    args = p.parse_args(argv)
    results: dict[str, Any] = {
        "label": args.label,
        "package": str(Path(trusted.__file__).resolve()),
        "controls": {},
    }
    for name, fn in CONTROLS:
        with tempfile.TemporaryDirectory(prefix="negctl-") as tmp:
            try:
                results["controls"][name] = fn(Path(tmp))
            except Exception as exc:  # noqa: BLE001 - an error is an observation too
                results["controls"][name] = {"error": f"{type(exc).__name__}: {exc}"}
        print(f"{args.label}: {name}: done", flush=True)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / f"negative-controls-{args.label}.json").write_text(
        json.dumps(results, indent=2, default=str)
    )
    print(json.dumps(results, indent=2, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
