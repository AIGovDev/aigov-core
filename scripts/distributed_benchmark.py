"""Reproducible local benchmark of the executor store under concurrent executor processes.

    python scripts/distributed_benchmark.py --store pg --admin-url postgresql://user:pass@127.0.0.1:5432/postgres \
        --levels 1,2,4,8 --authorizations 60 --forged 10 --out bench-pg.json
    python scripts/distributed_benchmark.py --store sqlite --levels 1,2,4,8 --out bench-sqlite.json

Every level runs ``c`` executor processes. Each process attempts every authorization, in its own random order, so the
claims race. Some authorizations are forged (signed by a key the executor does not trust); they must never run.

Measured from the outside, not from what the workers report about themselves:

- unauthorized executions: forged authorizations that reached the side effect (must be 0);
- duplicate executions: side effects minus distinct authorizations executed (must be 0);
- false denials: valid authorizations that no process executed (must be 0);
- evidence: the store's history verifies, and every executed authorization has its receipt recorded;
- throughput: executed authorizations per second of wall time;
- per-attempt latency p50, p95, p99 (the executor's own end-to-end timing for each call);
- database contention (PostgreSQL only): samples of sessions waiting on locks, and the peak number of sessions;
- recovery latency (PostgreSQL only): time from the lease's expiry to the recovery that marks a killed execution unknown.

The side effect and the Core are the test stand-ins from ``python/tests/_lifecycle_harness.py`` (a file-backed Core and
a side-effect log). The benchmark measures the store and the executor, not a real external system or a real Core.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import random
import statistics
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
TESTS = REPO / "python" / "tests"
sys.path.insert(0, str(TESTS))

import _lifecycle_harness as h  # noqa: E402  (after sys.path setup)

WORKER = TESTS / "_distributed_worker.py"
BENIGN_REFUSALS = {"authorization_replayed", "authorization_already_started", "authorization_receipt_recorded"}


def _percentile(values: list[float], p: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    k = max(0, min(len(ordered) - 1, int(round(p / 100.0 * len(ordered) + 0.5)) - 1))
    return round(ordered[k], 3)


class Sampler(threading.Thread):
    """Samples PostgreSQL sessions while a level runs: how many wait on a lock, and the peak session count."""

    def __init__(self, admin_url: str, db: str, interval: float = 0.02) -> None:
        super().__init__(daemon=True)
        self._admin_url = admin_url
        self._db = db
        self._interval = interval
        self._halt = threading.Event()
        self.lock_wait_samples = 0
        self.peak_sessions = 0
        self.samples = 0

    def run(self) -> None:
        import psycopg

        with psycopg.connect(self._admin_url, autocommit=True) as conn:
            while not self._halt.is_set():
                row = conn.execute(
                    "SELECT count(*), count(*) FILTER (WHERE wait_event_type = 'Lock') FROM pg_stat_activity "
                    "WHERE datname = %s AND backend_type = 'client backend'",
                    (self._db,),
                ).fetchone()
                self.samples += 1
                self.peak_sessions = max(self.peak_sessions, int(row[0]))
                self.lock_wait_samples += int(row[1])
                time.sleep(self._interval)

    def stop(self) -> None:
        self._halt.set()
        self.join(timeout=5)


class Store:
    """The store under test: a fresh PostgreSQL database, or a fresh SQLite file."""

    def __init__(self, kind: str, admin_url: str | None, root: Path) -> None:
        self.kind = kind
        self.root = root
        self.admin_url = admin_url
        self.db = None
        if kind == "pg":
            import psycopg

            from aigov_py.trusted import store_admin

            self.db = f"govai_bench_{uuid.uuid4().hex[:10]}"
            with psycopg.connect(admin_url, autocommit=True) as conn:
                conn.execute(f'CREATE DATABASE "{self.db}"')
            self.url = admin_url.rsplit("/", 1)[0] + f"/{self.db}"
            store_admin.main(["migrate-pg", "--url", self.url])
            self.job_fields = {"url": self.url, "tenant": "tenant-bench"}
        elif kind == "sqlite":
            from aigov_py.trusted import store_admin

            self.path = root / "executor.sqlite"
            store_admin.migrate(self.path, backup_dir=None)
            self.job_fields = {"store": "sqlite", "db": str(self.path)}
        else:
            raise SystemExit(f"unknown store {kind}")

    def verify(self) -> dict:
        if self.kind == "pg":
            from aigov_py.trusted.store_pg import PostgresExecutionStore

            s = PostgresExecutionStore(self.url, tenant="tenant-bench")
        else:
            from aigov_py.trusted.store import ExecutionStore

            s = ExecutionStore(self.path)
        ok_h, detail_h = s.verify_history()
        ok_p, detail_p = s.verify_projection()
        return {"history_ok": ok_h, "history": detail_h, "projection_ok": ok_p, "projection": detail_p}

    def receipts_recorded(self) -> int:
        if self.kind == "pg":
            import psycopg

            with psycopg.connect(self.url) as conn:
                return int(conn.execute("SELECT count(*) FROM executions WHERE receipt_state = 'recorded'").fetchone()[0])
        import sqlite3

        c = sqlite3.connect(self.path)
        try:
            return int(c.execute("SELECT count(*) FROM executions WHERE receipt_state = 'recorded'").fetchone()[0])
        finally:
            c.close()

    def drop(self) -> None:
        if self.kind == "pg" and self.db:
            import psycopg

            with psycopg.connect(self.admin_url, autocommit=True) as conn:
                conn.execute(f'DROP DATABASE IF EXISTS "{self.db}" WITH (FORCE)')


def _items(seed: str, n: int) -> list[dict]:
    return [{"run_id": h.RUN, "arguments": h.ARGS, "signed": h.signed_authorization(seed)} for _ in range(n)]


def run_level(store: Store, root: Path, concurrency: int, valid: int, forged: int, admin_url: str | None) -> dict:
    receipts_before = store.receipts_recorded()  # the store is shared by all levels of one run
    seed, pub = h.new_authorization_key()
    forged_seed, _ = h.new_authorization_key()
    level = root / f"c{concurrency}"
    level.mkdir()
    core = level / "core.json"
    effects = level / "effects.log"
    h.FileCore(core)
    h.SideEffects(effects)
    valid_items = _items(seed, valid)
    forged_items = _items(forged_seed, forged)
    forged_ids = {it["signed"]["payload"]["authorization_id"] for it in forged_items}
    valid_ids = {it["signed"]["payload"]["authorization_id"] for it in valid_items}
    everything = valid_items + forged_items

    procs = []
    for i in range(concurrency):
        order = everything[:]
        random.Random(i * 7919 + concurrency).shuffle(order)
        job = {"step": "execute", "core": str(core), "effects": str(effects), "public_key": pub,
               "worker": f"c{concurrency}-w{i}", "items": order, "lease": 300, **store.job_fields}
        jp = level / f"job-{i}.json"
        jp.write_text(json.dumps(job))
        procs.append(subprocess.Popen([sys.executable, str(WORKER), str(jp)], stdout=subprocess.PIPE,
                                      stderr=subprocess.PIPE, text=True))

    sampler = None
    if store.kind == "pg" and admin_url:
        sampler = Sampler(admin_url, store.db)
        sampler.start()
    t0 = time.perf_counter()
    attempts, errors = [], []
    for p in procs:
        out, err = p.communicate(timeout=900)
        if p.returncode != 0:
            errors.append(err.strip()[-500:])
            continue
        data = json.loads(out.strip().splitlines()[-1])
        attempts.extend(data["results"])
    wall = time.perf_counter() - t0
    if sampler:
        sampler.stop()

    executed_ids = [a["authorization_id"] for a in attempts if a["executed"]]
    executed_valid = [a for a in executed_ids if a in valid_ids]
    effects_ids = h.SideEffects(effects).count()
    effect_lines = [json.loads(line) for line in effects.read_text().splitlines() if line.strip()]
    side_effect_auths = {line["execution_id"] for line in effect_lines}
    unauthorized = sum(1 for a in executed_ids if a in forged_ids)
    from aigov_py.trusted.executor import execution_key

    forged_exec_ids = {execution_key(x) for x in forged_ids}
    forged_effects = sum(1 for line in effect_lines if line["execution_id"] in forged_exec_ids)
    distinct_valid = len(set(executed_valid))
    ms = [a["end_to_end_ms"] for a in attempts if "end_to_end_ms" in a]
    ms_exec = [a["end_to_end_ms"] for a in attempts if a["executed"] and "end_to_end_ms" in a]
    reasons: dict[str, int] = {}
    for a in attempts:
        reasons[a["reason"]] = reasons.get(a["reason"], 0) + 1
    false_denials = valid - distinct_valid
    result = {
        "concurrency": concurrency,
        "authorizations_valid": valid,
        "authorizations_forged": forged,
        "attempts": len(attempts),
        "worker_errors": errors,
        "executed_valid_distinct": distinct_valid,
        "unauthorized_executions": unauthorized,
        "unauthorized_side_effects": forged_effects,
        "side_effects_total": effects_ids,
        "duplicate_executions": effects_ids - len(side_effect_auths),
        "false_denials": false_denials,
        "refusal_reasons": reasons,
        "wall_seconds": round(wall, 3),
        "throughput_executed_per_second": round(distinct_valid / wall, 2) if wall else None,
        "latency_ms": {"p50": _percentile(ms, 50), "p95": _percentile(ms, 95), "p99": _percentile(ms, 99),
                       "mean": round(statistics.fmean(ms), 3) if ms else None, "samples": len(ms)},
        "latency_executed_ms": {"p50": _percentile(ms_exec, 50), "p95": _percentile(ms_exec, 95),
                                "p99": _percentile(ms_exec, 99), "samples": len(ms_exec)},
        # The receipts recorded during this level. The store is shared across levels, so the total is kept separately.
        "receipts_recorded": store.receipts_recorded() - receipts_before,
        "receipts_recorded_store_total": store.receipts_recorded(),
        "evidence": store.verify(),
    }
    if sampler:
        result["db_contention"] = {"lock_wait_samples": sampler.lock_wait_samples, "samples": sampler.samples,
                                   "peak_sessions": sampler.peak_sessions}
    return result


def recovery_latency(store: Store, root: Path, lease: int = 1, runs: int = 3) -> dict:
    """A worker killed inside the side effect; time from its lease's expiry to the recovery that records unknown."""
    if store.kind != "pg":
        return {"skipped": "recovery latency is measured on the shared store"}
    samples = []
    for run in range(runs):
        seed, pub = h.new_authorization_key()
        d = root / f"rec{run}"
        d.mkdir()
        core, effects = d / "core.json", d / "effects.log"
        h.FileCore(core)
        h.SideEffects(effects)
        items = _items(seed, 1)
        job = {"step": "execute", "core": str(core), "effects": str(effects), "public_key": pub, "worker": f"rec-{run}",
               "items": items, "lease": lease, "crash_at": "after_side_effect_before_finish", **store.job_fields}
        jp = d / "job.json"
        jp.write_text(json.dumps(job))
        p = subprocess.run([sys.executable, str(WORKER), str(jp)], capture_output=True, text=True, timeout=120)
        assert p.returncode == 137, p.stderr
        crashed_at = time.time()
        # The expiry is the lease the store recorded (database clock). Read it before recovery clears it.
        from aigov_py.trusted.store_pg import PostgresExecutionStore

        auth_id = items[0]["signed"]["payload"]["authorization_id"]
        expiry = PostgresExecutionStore(store.url, tenant="tenant-bench").row(auth_id)["lease_until"].timestamp()
        recover_job = {"step": "recover", "core": str(core), "effects": str(effects), "public_key": pub,
                       "worker": f"recover-{run}", "lease": lease, **store.job_fields}
        rj = d / "recover.json"
        found_at = None
        while time.time() - crashed_at < 60:
            rj.write_text(json.dumps(recover_job))
            q = subprocess.run([sys.executable, str(WORKER), str(rj)], capture_output=True, text=True, timeout=120)
            out = json.loads(q.stdout.strip().splitlines()[-1])
            if any(a["action"] == "outcome_unknown" for a in out["actions"]):
                found_at = time.time()
                break
            time.sleep(0.05)
        if found_at is None:
            samples.append(None)
            continue
        samples.append(round((found_at - expiry) * 1000.0, 1))
    good = [s for s in samples if s is not None]
    return {"lease_seconds": lease, "runs": runs, "ms_after_lease_expiry": samples,
            "p50_ms": _percentile(good, 50), "max_ms": max(good) if good else None}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--store", choices=["pg", "sqlite"], required=True)
    ap.add_argument("--admin-url", default=os.environ.get("AIGOV_TEST_EXECUTOR_ADMIN_URL", ""))
    ap.add_argument("--levels", default="1,2,4,8")
    ap.add_argument("--authorizations", type=int, default=60)
    ap.add_argument("--forged", type=int, default=10)
    ap.add_argument("--recovery-runs", type=int, default=3)
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args(argv)
    if args.store == "pg" and not args.admin_url:
        ap.error("--admin-url (or AIGOV_TEST_EXECUTOR_ADMIN_URL) is required for --store pg")

    started = time.time()
    with tempfile.TemporaryDirectory(prefix="dist-bench-") as d:
        root = Path(d)
        store = Store(args.store, args.admin_url or None, root)
        try:
            levels = [int(x) for x in args.levels.split(",")]
            results = [run_level(store, root, c, args.authorizations, args.forged, args.admin_url or None) for c in levels]
            recovery = recovery_latency(store, root, runs=args.recovery_runs)
        finally:
            store.drop()
    report = {
        "store": args.store,
        "git_head": _git_head(),
        "python": platform.python_version(),
        "load_average_1_5_15_at_end": [round(x, 2) for x in os.getloadavg()],
        "cpu_count": os.cpu_count(),
        "platform": platform.platform(),
        "authorizations_valid": args.authorizations,
        "authorizations_forged": args.forged,
        "levels": results,
        "recovery": recovery,
        "core_stand_in": "file-backed Core stand-in (_lifecycle_harness.FileCore), not the Rust Core",
        "started_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(started)),
        "wall_seconds": round(time.time() - started, 1),
    }
    args.out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps({k: report[k] for k in ("store", "git_head", "wall_seconds")}))
    for r in results:
        print(f"c={r['concurrency']:>2} valid_executed={r['executed_valid_distinct']:>3}/{r['authorizations_valid']} "
              f"unauth={r['unauthorized_executions']} dup={r['duplicate_executions']} false_denials={r['false_denials']} "
              f"thr={r['throughput_executed_per_second']}/s p50={r['latency_ms']['p50']} p95={r['latency_ms']['p95']} "
              f"p99={r['latency_ms']['p99']} evidence={r['evidence']['history_ok'] and r['evidence']['projection_ok']}")
    return 0


def _git_head() -> str:
    try:
        return subprocess.run(["git", "-C", str(REPO), "rev-parse", "--short", "HEAD"], capture_output=True,
                              text=True, check=True).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return "unknown"


if __name__ == "__main__":
    raise SystemExit(main())
