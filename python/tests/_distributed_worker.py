"""One executor process for the distributed tests. Runs in its own OS process with its own PostgreSQL connections.

Job (JSON file): ``step`` is ``execute``, ``recover``, or ``deliver``. Options:

- ``crash_at``: exit with status 137 when the executor reaches this fault point (simulates a killed process).
- ``pause_inside``: seconds to sleep inside the performer, after the side effect (simulates a stalled worker).
- ``terminate_db_inside``: database URL whose sessions are terminated from inside the performer (simulates a database
  interruption after the side effect).
- ``wait_file_inside``: after the side effect, wait until this file exists (the test cuts the network to the database).
- ``lease``: lease length in seconds, on database time.
"""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

import _lifecycle_harness as h  # noqa: E402

from aigov_py.trusted import receipts  # noqa: E402
from aigov_py.trusted.core import CoreClient  # noqa: E402
from aigov_py.trusted.executor import Executor  # noqa: E402


def _terminate_sessions(url: str) -> None:
    import psycopg

    db = url.rsplit("/", 1)[-1].split("?")[0]
    admin = url.rsplit("/", 1)[0] + "/postgres"
    with psycopg.connect(admin, autocommit=True) as conn:
        conn.execute(
            "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = %s AND pid <> pg_backend_pid()",
            (db,),
        )


def main(job_path: str) -> int:
    job: dict[str, Any] = json.loads(Path(job_path).read_text(encoding="utf-8"))
    crash_at = job.get("crash_at")

    def fault(point: str) -> None:
        if crash_at == point:
            os._exit(137)

    core = h.FileCore(Path(job["core"]))
    effects = h.SideEffects(Path(job["effects"]))
    pause = float(job.get("pause_inside", 0) or 0)
    terminate_url = job.get("terminate_db_inside")
    wait_file = job.get("wait_file_inside")

    def performer(tool: str, arguments: dict, execution_id: str) -> dict:
        result = effects.performer()(tool, arguments, execution_id)  # the side effect: one line in the effects file
        if terminate_url:
            _terminate_sessions(terminate_url)
        if wait_file:
            # Hold here until the test has cut the database connection: the outcome cannot be recorded afterwards.
            deadline = time.time() + 30
            while not os.path.exists(wait_file) and time.time() < deadline:
                time.sleep(0.05)
        if pause:
            time.sleep(pause)
        return result

    if job.get("store") == "sqlite":
        # The SQLite store (one host): used by the benchmark's negative control on the current staging implementation.
        from aigov_py.trusted.store import ExecutionStore

        store = ExecutionStore(Path(job["db"]), fault=fault)
    else:
        from aigov_py.trusted.store_pg import PostgresExecutionStore  # imported here: staging trees have no store_pg

        store = PostgresExecutionStore(job["url"], tenant=job.get("tenant", "tenant-a"), fault=fault)
    executor = Executor(
        core=core,
        public_key_b64=job["public_key"],
        audience=h.AUDIENCE,
        store=store,
        tools=h.TOOLS,
        performer=performer,
        lease_seconds=int(job.get("lease", 300)),
        worker_id=job.get("worker"),
        fault=fault,
    )
    if job["step"] == "execute":
        results = []
        for item in job["items"]:
            out = executor.execute(run_id=item["run_id"], tool=h.TOOL.name, arguments=item["arguments"], signed=item["signed"])
            results.append({"authorization_id": item["signed"]["payload"]["authorization_id"], "reason": out.reason,
                            "executed": out.executed, "end_to_end_ms": round(out.end_to_end_ms, 3)})
        print(json.dumps({"worker": executor.worker_id, "results": results}))
    elif job["step"] == "recover":
        actions = executor.recover()
        print(json.dumps({"actions": [a.as_dict() for a in actions]}))
    elif job["step"] == "record":
        store.record_receipt_recorded(
            authorization_id=job["authorization_id"], receipt_event_id=job["receipt_event_id"], now=job["now"]
        )
        print(json.dumps({"recorded": True}))
    elif job["step"] == "deliver":
        ok = receipts.deliver(store, core, run_id=job["run_id"], authorization_id=job["authorization_id"])
        print(json.dumps({"delivered": ok}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1]))
