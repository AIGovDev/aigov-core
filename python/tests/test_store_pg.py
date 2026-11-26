"""The executor store on PostgreSQL: the migration, the atomic claim, fencing, database-clock leases, append-only history,
tenant isolation, and idempotent receipt recording.

    AIGOV_TEST_EXECUTOR_ADMIN_URL=postgresql://user:pass@host:5432/postgres python -m pytest tests/test_store_pg.py

The session creates one uniquely named database and drops it at the end. It never touches any other database.
"""

from __future__ import annotations

import json
import os
import time
import uuid
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

import pytest

from aigov_py.trusted import store_admin
from aigov_py.trusted.lifecycle import State
from aigov_py.trusted.store import ExecutionStoreError
from aigov_py.trusted.store_pg import PostgresExecutionStore, StaleWorker

ADMIN = os.environ.get("AIGOV_TEST_EXECUTOR_ADMIN_URL", "").strip()
pytestmark = pytest.mark.skipif(not ADMIN, reason="set AIGOV_TEST_EXECUTOR_ADMIN_URL (admin URL of a disposable server)")


def _with_db(url: str, db: str) -> str:
    base, _, _ = url.rpartition("/")
    return f"{base}/{db}"


@pytest.fixture(scope="session")
def pg_url():
    import psycopg

    db = f"govai_exec_{uuid.uuid4().hex[:10]}"
    with psycopg.connect(ADMIN, autocommit=True) as conn:
        conn.execute(f'CREATE DATABASE "{db}"')
    url = _with_db(ADMIN, db)
    try:
        store_admin.main(["migrate-pg", "--url", url])
        yield url
    finally:
        with psycopg.connect(ADMIN, autocommit=True) as conn:
            conn.execute(f'DROP DATABASE IF EXISTS "{db}" WITH (FORCE)')


@pytest.fixture
def fresh_url():
    """A database of its own, for tests that alter history on purpose. Dropped afterwards."""
    import psycopg

    db = f"govai_exec_{uuid.uuid4().hex[:10]}"
    with psycopg.connect(ADMIN, autocommit=True) as conn:
        conn.execute(f'CREATE DATABASE "{db}"')
    url = _with_db(ADMIN, db)
    store_admin.main(["migrate-pg", "--url", url])
    try:
        yield url
    finally:
        with psycopg.connect(ADMIN, autocommit=True) as conn:
            conn.execute(f'DROP DATABASE IF EXISTS "{db}" WITH (FORCE)')


def _store(url: str, tenant: str = "tenant-a", fault=None) -> PostgresExecutionStore:
    return PostgresExecutionStore(url, tenant=tenant, fault=fault)


def _reserve(s: PostgresExecutionStore, auth: str) -> bool:
    return s.reserve(authorization_id=auth, run_id="run-1", tool="create_file", digest="d" * 64,
                     signed_json="{}", now="2026-11-26T10:00:00+00:00", executor_identity="executor",
                     policy_revision="rev-1", arguments_json='{"path":"x"}')


def _auth() -> str:
    return "auth_" + uuid.uuid4().hex


def test_migration_is_versioned_and_idempotent(pg_url):
    assert store_admin.main(["status-pg", "--url", pg_url]) == 0
    assert store_admin.main(["migrate-pg", "--url", pg_url]) == 0  # re-run: nothing to apply
    _store(pg_url)  # opens: the schema version is the one this SDK requires


def test_the_store_refuses_an_unmigrated_database(pg_url):
    import psycopg

    db = f"govai_unmigrated_{uuid.uuid4().hex[:8]}"
    with psycopg.connect(ADMIN, autocommit=True) as conn:
        conn.execute(f'CREATE DATABASE "{db}"')
    try:
        from aigov_py.trusted.store import SchemaMissing

        with pytest.raises(SchemaMissing):
            _store(_with_db(ADMIN, db))
    finally:
        with psycopg.connect(ADMIN, autocommit=True) as conn:
            conn.execute(f'DROP DATABASE IF EXISTS "{db}" WITH (FORCE)')


def test_one_reservation_per_authorization_across_tenants(pg_url):
    a, b = _store(pg_url, "tenant-a"), _store(pg_url, "tenant-b")
    auth = _auth()
    assert _reserve(a, auth) is True
    assert _reserve(a, auth) is False
    assert _reserve(b, auth) is False  # another tenant cannot reserve the same authorization
    assert b.row(auth) is None  # and cannot see that it exists


def test_a_claim_returns_a_fence_and_a_second_claim_gets_nothing(pg_url):
    s = _store(pg_url)
    auth = _auth()
    _reserve(s, auth)
    fence = s.start(authorization_id=auth, worker_id="w1", now="2026-11-26T10:00:01+00:00", lease_seconds=300)
    assert isinstance(fence, int) and fence >= 1
    assert s.start(authorization_id=auth, worker_id="w2", now="2026-11-26T10:00:01+00:00", lease_seconds=300) is None


def test_a_stale_fence_cannot_finish_and_writes_nothing(pg_url):
    s = _store(pg_url)
    auth = _auth()
    _reserve(s, auth)
    fence = s.start(authorization_id=auth, worker_id="w1", now="2026-11-26T10:00:01+00:00", lease_seconds=300)
    events_before = len(s.events(auth))
    with pytest.raises(StaleWorker):
        s.finish(authorization_id=auth, outcome="success", result_digest_hex="a" * 64,
                 now="2026-11-26T10:00:02+00:00", receipt_event_id="r-x", fence=fence + 1)
    with pytest.raises(StaleWorker):
        s.finish(authorization_id=auth, outcome="success", result_digest_hex="a" * 64,
                 now="2026-11-26T10:00:02+00:00", receipt_event_id="r-x", fence=None)
    assert s.row(auth)["state"] == State.STARTED.value
    assert len(s.events(auth)) == events_before


def test_the_owner_finishes_once_and_a_receipt_is_recorded_idempotently(pg_url):
    s = _store(pg_url)
    auth = _auth()
    _reserve(s, auth)
    fence = s.start(authorization_id=auth, worker_id="w1", now="2026-11-26T10:00:01+00:00", lease_seconds=300)
    s.finish(authorization_id=auth, outcome="success", result_digest_hex="b" * 64,
             now="2026-11-26T10:00:02+00:00", receipt_event_id="r-1", worker_id="w1", fence=fence)
    row = s.row(auth)
    assert row["state"] == State.SUCCEEDED.value and row["receipt_state"] == "pending"
    s.record_receipt_recorded(authorization_id=auth, receipt_event_id="r-1", now="2026-11-26T10:00:03+00:00")
    before = len(s.events(auth))
    s.record_receipt_recorded(authorization_id=auth, receipt_event_id="r-1", now="2026-11-26T10:00:04+00:00")
    assert len(s.events(auth)) == before  # a duplicate delivery writes nothing
    with pytest.raises(ExecutionStoreError):
        s.record_receipt_recorded(authorization_id=auth, receipt_event_id="r-other", now="2026-11-26T10:00:05+00:00")


def test_history_is_append_only_at_the_database_level(pg_url):
    import psycopg

    s = _store(pg_url)
    auth = _auth()
    _reserve(s, auth)
    with psycopg.connect(pg_url) as conn:
        for stmt in ("UPDATE execution_events SET actor = 'x'", "DELETE FROM execution_events",
                     "TRUNCATE execution_events"):
            with pytest.raises(psycopg.Error):
                conn.execute(stmt)
            conn.rollback()


def test_a_history_row_altered_by_an_administrator_is_detected(fresh_url):
    import psycopg

    pg_url = fresh_url
    s = _store(pg_url)
    assert s.verify_history()[0] is True
    auth = _auth()
    _reserve(s, auth)
    with psycopg.connect(pg_url, autocommit=True) as conn:
        conn.execute("ALTER TABLE execution_events DISABLE TRIGGER execution_events_no_update")
        try:
            conn.execute("UPDATE execution_events SET actor = 'forged' WHERE authorization_id = %s", (auth,))
        finally:
            conn.execute("ALTER TABLE execution_events ENABLE TRIGGER execution_events_no_update")
    ok, detail = s.verify_history()
    assert ok is False and "content does not match" in detail


def test_another_tenant_cannot_finish_or_read_an_execution(pg_url):
    a, b = _store(pg_url, "tenant-a"), _store(pg_url, "tenant-b")
    auth = _auth()
    _reserve(a, auth)
    assert b.start(authorization_id=auth, worker_id="intruder", now="2026-11-26T10:00:01+00:00", lease_seconds=300) is None
    assert b.row(auth) is None and b.events(auth) == []
    assert all(r["authorization_id"] != auth for r in b.all_rows())


def test_the_lease_is_decided_on_database_time(pg_url):
    s = _store(pg_url)
    auth = _auth()
    _reserve(s, auth)
    s.start(authorization_id=auth, worker_id="w1", now="2026-11-26T10:00:01+00:00", lease_seconds=2)
    assert s.expire_lease(authorization_id=auth, now="2026-11-26T10:00:02+00:00", actor="recovery") is False
    time.sleep(2.5)
    assert s.expire_lease(authorization_id=auth, now="2026-11-26T10:00:05+00:00", actor="recovery") is True
    row = s.row(auth)
    assert row["state"] == State.RECONCILIATION_REQUIRED.value
    # Once recovery has moved it on, the first worker can no longer finish it.
    with pytest.raises(StaleWorker):
        s.finish(authorization_id=auth, outcome="success", result_digest_hex="c" * 64,
                 now="2026-11-26T10:00:06+00:00", receipt_event_id="r-late", fence=1)


def _claim_once(args):
    url, auth = args
    s = PostgresExecutionStore(url, tenant="tenant-a")
    return s.start(authorization_id=auth, worker_id=f"p-{os.getpid()}", now="2026-11-26T10:00:01+00:00", lease_seconds=300)


def test_concurrent_claims_from_eight_processes_give_exactly_one_fence(pg_url):
    s = _store(pg_url)
    auth = _auth()
    _reserve(s, auth)
    with ProcessPoolExecutor(max_workers=8) as pool:
        claims = list(pool.map(_claim_once, [(pg_url, auth)] * 8))
    winners = [c for c in claims if c is not None]
    assert len(winners) == 1, claims
    assert s.row(auth)["fence"] == winners[0]


def test_the_history_chain_verifies_across_tenants(fresh_url):
    a, b = _store(fresh_url, "tenant-a"), _store(fresh_url, "tenant-b")
    _reserve(a, _auth())
    _reserve(b, _auth())
    assert a.verify_history()[0] is True
    assert a.verify_projection()[0] is True and b.verify_projection()[0] is True
