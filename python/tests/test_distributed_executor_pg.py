"""Distributed execution, process level: several executor processes share one PostgreSQL executor store.

Each process is a separate OS process with its own connections (``_distributed_worker.py``). The side effect is one line
per real action in a shared file; the count of lines is the number of times the action ran. Each scenario injects one
failure and asserts what must hold afterwards.

    AIGOV_TEST_EXECUTOR_ADMIN_URL=postgresql://user:pass@host:5432/postgres python -m pytest tests/test_distributed_executor_pg.py

The session creates one uniquely named database and drops it at the end.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import _lifecycle_harness as h
import pytest

from aigov_py.trusted import store_admin
from aigov_py.trusted.store_pg import PostgresExecutionStore

ADMIN = os.environ.get("AIGOV_TEST_EXECUTOR_ADMIN_URL", "").strip()
pytestmark = pytest.mark.skipif(not ADMIN, reason="set AIGOV_TEST_EXECUTOR_ADMIN_URL (admin URL of a disposable server)")
WORKER = Path(__file__).resolve().parent / "_distributed_worker.py"


@pytest.fixture(scope="module")
def pg_url():
    import psycopg

    db = f"govai_dist_{uuid.uuid4().hex[:10]}"
    with psycopg.connect(ADMIN, autocommit=True) as conn:
        conn.execute(f'CREATE DATABASE "{db}"')
    base = ADMIN.rsplit("/", 1)[0]
    url = f"{base}/{db}"
    store_admin.main(["migrate-pg", "--url", url])
    try:
        yield url
    finally:
        with psycopg.connect(ADMIN, autocommit=True) as conn:
            conn.execute(f'DROP DATABASE IF EXISTS "{db}" WITH (FORCE)')


def _action(out: dict, auth: str) -> str | None:
    """The recovery action for one authorization. The database is shared by the module, so recovery also reports others."""
    return next((a["action"] for a in out["actions"] if a["authorization_id"] == auth), None)


class World:
    """Per-test files: the Core stand-in, the side-effect file, and a set of signed authorizations."""

    def __init__(self, url: str, root: Path) -> None:
        self.url = url
        self.root = root
        self.core = root / "core.json"
        self.effects = root / "effects.log"
        self.seed, self.pub = h.new_authorization_key()
        h.FileCore(self.core)
        h.SideEffects(self.effects)

    def items(self, n: int) -> list[dict]:
        out = []
        for _ in range(n):
            signed = h.signed_authorization(self.seed)
            out.append({"run_id": h.RUN, "arguments": h.ARGS, "signed": signed})
        return out

    def job(self, step: str, worker: str, **extra) -> dict:
        return {"step": step, "url": self.url, "tenant": "tenant-a", "core": str(self.core), "effects": str(self.effects),
                "public_key": self.pub, "worker": worker, **extra}

    def write_job(self, job: dict) -> Path:
        p = self.root / f"job-{uuid.uuid4().hex[:8]}.json"
        p.write_text(json.dumps(job), encoding="utf-8")
        return p

    def run(self, job: dict) -> tuple[int, dict | None]:
        p = self.write_job(job)
        proc = subprocess.run([sys.executable, str(WORKER), str(p)], capture_output=True, text=True, timeout=180)
        out = None
        if proc.returncode == 0 and proc.stdout.strip():
            out = json.loads(proc.stdout.strip().splitlines()[-1])
        return proc.returncode, out

    def popen(self, job: dict):
        p = self.write_job(job)
        return subprocess.Popen([sys.executable, str(WORKER), str(p)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    def effect_count(self) -> int:
        return h.SideEffects(self.effects).count()

    def effect_ids(self) -> list[str]:
        return [json.loads(line)["execution_id"] for line in self.effects.read_text().splitlines() if line.strip()]

    def store(self) -> PostgresExecutionStore:
        return PostgresExecutionStore(self.url, tenant="tenant-a")


@pytest.fixture
def world(pg_url):
    with tempfile.TemporaryDirectory(prefix="dist-exec-") as d:
        yield World(pg_url, Path(d))


def test_contention_four_processes_perform_each_authorization_exactly_once(world):
    items = world.items(12)
    jobs = [world.popen(world.job("execute", f"worker-{i}", items=items)) for i in range(4)]
    outputs = []
    for p in jobs:
        out, err = p.communicate(timeout=240)
        assert p.returncode == 0, err
        outputs.append(json.loads(out.strip().splitlines()[-1]))
    executed = [r for o in outputs for r in o["results"] if r["executed"]]
    refused = [r["reason"] for o in outputs for r in o["results"] if not r["executed"]]
    assert world.effect_count() == len(items), "each authorization must run exactly once"
    assert len({r["authorization_id"] for r in executed}) == len(items)
    # After a receipt is recorded in Core, the status check refuses the authorization before any reservation.
    assert set(refused) <= {"authorization_replayed", "authorization_already_started", "store_unavailable",
                            "authorization_receipt_recorded"}, refused
    assert world.store().verify_history()[0] and world.store().verify_projection()[0]


def test_an_unauthorized_authorization_never_reaches_the_side_effect(world):
    forged = h.signed_authorization(h.new_authorization_key()[0])  # signed by a key the executor does not trust
    rc, out = world.run(world.job("execute", "w-forged", items=[{"run_id": h.RUN, "arguments": h.ARGS, "signed": forged}]))
    assert rc == 0
    assert out["results"][0]["executed"] is False
    assert world.effect_count() == 0


def test_a_killed_process_after_the_side_effect_is_never_rerun(world):
    items = world.items(1)
    rc, _ = world.run(world.job("execute", "w-dies", items=items, crash_at="after_side_effect_before_finish", lease=1))
    assert rc == 137
    assert world.effect_count() == 1
    time.sleep(2.2)  # the lease passes on database time
    rc, out = world.run(world.job("recover", "w-recover", lease=1))
    assert rc == 0
    assert _action(out, items[0]["signed"]["payload"]["authorization_id"]) == "outcome_unknown"
    row = world.store().row(items[0]["signed"]["payload"]["authorization_id"])
    assert row["state"] == "reconciliation_required"
    rc, out = world.run(world.job("execute", "w-again", items=items, lease=1))  # a retry is refused, not re-run
    assert out["results"][0]["reason"] == "authorization_replayed"
    assert world.effect_count() == 1


def test_a_killed_process_after_reserving_is_resumed_once_by_recovery(world):
    items = world.items(1)
    rc, _ = world.run(world.job("execute", "w-dies-early", items=items, crash_at="after_reserve", lease=1))
    assert rc == 137
    assert world.effect_count() == 0  # nothing was started, so nothing ran
    rc, out = world.run(world.job("recover", "w-recover", lease=1))
    assert _action(out, items[0]["signed"]["payload"]["authorization_id"]) == "resumed_once"
    assert world.effect_count() == 1
    rc, out = world.run(world.job("recover", "w-recover-2", lease=1))  # a second recovery does nothing more
    assert world.effect_count() == 1
    assert world.store().row(items[0]["signed"]["payload"]["authorization_id"])["state"] == "succeeded"


def test_a_stalled_worker_that_loses_its_claim_cannot_record_success(world):
    items = world.items(1)
    auth = items[0]["signed"]["payload"]["authorization_id"]
    stalled = world.popen(world.job("execute", "w-stalled", items=items, pause_inside=4, lease=1))
    time.sleep(1.0)
    # The lease (1 s, database time) passes while the first worker is still inside the side effect.
    time.sleep(1.2)
    rc, out = world.run(world.job("recover", "w-recover", lease=1))
    assert _action(out, auth) == "outcome_unknown", out
    stdout, stderr = stalled.communicate(timeout=60)
    assert stalled.returncode == 0, stderr
    result = json.loads(stdout.strip().splitlines()[-1])["results"][0]
    assert result["reason"] == "stale_worker" and result["executed"] is False
    row = world.store().row(auth)
    assert row["state"] == "reconciliation_required"
    assert row["receipt_state"] == "none"  # the stalled worker sent no receipt for an outcome it could not record
    assert world.effect_count() == 1


def test_a_network_interruption_to_the_database_after_the_side_effect_leaves_the_outcome_unknown_not_rerun(world):
    from _pg_proxy import TcpProxy

    host_port = world.url.split("@", 1)[1].split("/", 1)[0]
    host, port = host_port.split(":")
    proxy = TcpProxy(host, int(port))
    proxy_port = proxy.start()
    proxy_url = world.url.replace(host_port, f"127.0.0.1:{proxy_port}")
    items = world.items(1)
    auth = items[0]["signed"]["payload"]["authorization_id"]
    cut_flag = world.root / "cut.flag"
    job = world.job("execute", "w-cut", items=items, lease=1, wait_file_inside=str(cut_flag))
    job["url"] = proxy_url
    worker = world.popen(job)

    # Cut the network once the side effect has happened and the worker is waiting on the flag.
    deadline = time.time() + 60
    while world.effect_count() == 0 and time.time() < deadline:
        time.sleep(0.05)
    proxy.cut()
    cut_flag.write_text("cut")
    out, err = worker.communicate(timeout=120)
    assert worker.returncode == 0, err
    result = json.loads(out.strip().splitlines()[-1])["results"][0]
    assert result["reason"] == "outcome_not_recorded", result
    assert world.effect_count() == 1

    proxy.restore()  # the database is reachable again
    time.sleep(2.2)  # the lease passes on database time
    rc, out = world.run(world.job("recover", "w-recover", lease=1))
    assert rc == 0
    assert world.store().row(auth)["state"] == "reconciliation_required"
    assert world.effect_count() == 1
    proxy.cut()


def test_concurrent_receipt_recording_takes_effect_once(world):
    items = world.items(1)
    auth = items[0]["signed"]["payload"]["authorization_id"]
    store = world.store()
    # A finished execution whose receipt is pending: reserved, claimed, and finished by a first worker.
    store.reserve(authorization_id=auth, run_id=h.RUN, tool=h.TOOL.name, digest="d" * 64, signed_json="{}",
                  now="2026-11-26T10:00:00+00:00", executor_identity="executor", policy_revision="rev-1",
                  arguments_json='{"path":"x"}')
    fence = store.start(authorization_id=auth, worker_id="w-first", now="2026-11-26T10:00:01+00:00", lease_seconds=300)
    store.finish(authorization_id=auth, outcome="success", result_digest_hex="e" * 64, now="2026-11-26T10:00:02+00:00",
                 receipt_event_id="execution_receipt-race", worker_id="w-first", fence=fence)
    job = dict(authorization_id=auth, receipt_event_id="execution_receipt-race", now="2026-11-26T10:00:03+00:00")
    procs = [world.popen(world.job("record", f"rec-{i}", **job)) for i in range(2)]
    for p in procs:
        out, err = p.communicate(timeout=120)
        assert p.returncode == 0, err
        assert json.loads(out.strip().splitlines()[-1])["recorded"] is True
    assert store.row(auth)["receipt_state"] == "recorded"
    assert len([e for e in store.events(auth) if e["event"] == "receipt_recorded"]) == 1


def test_an_executor_that_cannot_reach_the_store_refuses_before_any_side_effect(world):
    bad = world.job("execute", "w-no-db", items=world.items(1))
    bad["url"] = "postgresql://postgres@127.0.0.1:1/govai_unreachable?connect_timeout=1"
    rc, _ = world.run(bad)
    assert rc != 0  # the store cannot open: the executor does not start
    assert world.effect_count() == 0


def test_a_recovery_host_whose_clock_is_two_hours_ahead_does_not_expire_a_live_lease(world):
    """Regression for the clock-based lease on the SQLite store: a skewed recovery host declared a live execution unknown."""
    from datetime import UTC
    from datetime import datetime as _dt

    from aigov_py.trusted.executor import Executor

    items = world.items(1)
    auth = items[0]["signed"]["payload"]["authorization_id"]
    live = world.popen(world.job("execute", "w-live", items=items, pause_inside=4, lease=300))
    time.sleep(1.5)  # the live worker has claimed the execution and is inside its side effect
    skewed = time.time() + 7200
    recovery = Executor(core=h.FileCore(world.core), public_key_b64=world.pub, audience=h.AUDIENCE, store=world.store(),
                        tools=h.TOOLS, performer=h.SideEffects(world.effects).performer(), worker_id="skewed",
                        lease_seconds=300, clock=lambda: skewed)
    actions = {a.authorization_id: a.action for a in recovery.recover()}
    assert actions.get(auth) != "outcome_unknown", actions
    out, err = live.communicate(timeout=120)
    assert live.returncode == 0, err
    assert json.loads(out.strip().splitlines()[-1])["results"][0]["executed"] is True
    assert world.store().row(auth)["state"] == "succeeded"
    assert world.effect_count() == 1
    assert _dt.now(UTC).year >= 2026  # the clock used above is the real one; the skew applied to recovery only


def test_connection_exhaustion_refuses_before_any_side_effect_and_never_duplicates(pg_url):
    """A role that may hold one connection at a time, shared by four executor processes: most operations are refused by
    PostgreSQL ('too many connections'). The executor must refuse those calls before any side effect, never run an
    authorization twice, and record nothing it cannot write."""
    import psycopg

    role = f"dist_limited_{uuid.uuid4().hex[:8]}"
    db = pg_url.rsplit("/", 1)[1]
    admin = ADMIN
    with psycopg.connect(admin, autocommit=True) as conn:
        conn.execute(f'CREATE ROLE "{role}" LOGIN CONNECTION LIMIT 1')
        conn.execute(f'GRANT ALL ON DATABASE "{db}" TO "{role}"')
    # Table grants belong to the test database, not to the admin database: connect to it.
    with psycopg.connect(pg_url, autocommit=True) as conn:
        conn.execute(f'GRANT USAGE ON SCHEMA public TO "{role}"')
        conn.execute(f'GRANT ALL ON ALL TABLES IN SCHEMA public TO "{role}"')
        conn.execute(f'GRANT ALL ON ALL SEQUENCES IN SCHEMA public TO "{role}"')
    try:
        base = admin.rsplit("/", 1)[0]
        host_part = base.split("@", 1)[1]
        limited_url = f"postgresql://{role}@{host_part}/{db}"
        with tempfile.TemporaryDirectory(prefix="dist-exhaust-") as d:
            w = World(limited_url, Path(d))
            items = w.items(6)
            jobs = [w.popen(w.job("execute", f"exh-{i}", items=items)) for i in range(4)]
            outs, refused_at_start = [], []
            for p in jobs:
                out, err = p.communicate(timeout=240)
                if p.returncode == 0:
                    outs.append(json.loads(out.strip().splitlines()[-1]))
                else:
                    refused_at_start.append(err.strip().splitlines()[-1] if err.strip() else "")
            reasons = [r["reason"] for o in outs for r in o["results"]]
            executed = [r["authorization_id"] for o in outs for r in o["results"] if r["executed"]]
            assert len(set(executed)) == len(executed), "an authorization ran twice"
            assert w.effect_count() == len(set(executed)), "a side effect happened without a recorded execution"
            # Exhaustion was actually reached: a process could not open its store (refused at start), or a call was refused.
            assert refused_at_start or "store_unavailable" in reasons, (reasons, refused_at_start)
            assert all("StoreUnavailable" in e for e in refused_at_start), refused_at_start
            assert len(executed) <= 6
    finally:
        with psycopg.connect(pg_url, autocommit=True) as conn:  # privileges granted inside the test database
            conn.execute(f'DROP OWNED BY "{role}"')
        with psycopg.connect(admin, autocommit=True) as conn:
            conn.execute(f'DROP ROLE IF EXISTS "{role}"')
