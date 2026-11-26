"""The registry anchor in PostgreSQL (the production anchor). Runs only against a disposable database:

    AIGOV_TEST_REGISTRY_PG_URL=postgresql://user:pass@host:5432/disposable python -m pytest tests/test_registry_postgres.py

Each test uses its own registry id and removes its anchor row afterwards. Nothing else in the database is touched.
"""

from __future__ import annotations

import os
import tempfile
import uuid
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

import pytest
from _registry_world import World, _commit_worker, settle_anchor

from aigov_py.trusted import keys as K
from aigov_py.trusted.registry_anchor import AnchorError, PostgresAnchor

PG_URL = os.environ.get("AIGOV_TEST_REGISTRY_PG_URL", "").strip()
pytestmark = pytest.mark.skipif(not PG_URL, reason="set AIGOV_TEST_REGISTRY_PG_URL to a disposable PostgreSQL database")


def _refuse_code(fn) -> str:
    with pytest.raises(K.KeyRegistryError) as exc:
        fn()
    return exc.value.code


MIGRATION_0004 = """
CREATE TABLE IF NOT EXISTS key_registry_anchor (
    registry_id TEXT PRIMARY KEY,
    seq BIGINT NOT NULL CHECK (seq >= 0),
    head_hash TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
)
"""


def _apply_migration_0004() -> None:
    """The production table comes from rust/migrations/0004_key_registry_anchor.sql. The test database gets the same DDL."""
    import psycopg

    with psycopg.connect(PG_URL, autocommit=True) as conn:
        conn.execute(MIGRATION_0004)


@pytest.fixture
def pg_world():
    _apply_migration_0004()
    rid = f"pgtest-{uuid.uuid4().hex[:12]}"
    with tempfile.TemporaryDirectory(prefix="registry-pg-") as d:
        w = World(Path(d), registry_id=rid, anchor=PostgresAnchor(PG_URL, rid))
        w.install_operator("ops-admin")
        w.register_active("exe-a")
        yield w
        _delete_anchor(rid)


def _delete_anchor(rid: str) -> None:
    import psycopg

    with psycopg.connect(PG_URL, autocommit=True) as conn:
        conn.execute("DELETE FROM key_registry_anchor WHERE registry_id = %s", (rid,))


def _anchor_row(rid: str):
    import psycopg

    with psycopg.connect(PG_URL) as conn:
        return conn.execute("SELECT seq, head_hash FROM key_registry_anchor WHERE registry_id = %s", (rid,)).fetchone()


def test_the_postgres_anchor_follows_the_log(pg_world):
    events = pg_world.events()
    seq, head = _anchor_row(pg_world.registry_id)
    assert seq == len(events)
    assert head == events[-1]["hash"]
    assert pg_world.reader().version == len(events)


def test_a_rolled_back_log_is_refused_by_the_postgres_anchor(pg_world):
    before = pg_world.events()
    pg_world.revoke("exe-a")
    pg_world.write_events(before)
    assert _refuse_code(pg_world.reader) == "anchor_log_behind"


def test_concurrent_revocations_apply_exactly_once_under_the_row_lock(pg_world):
    seed = pg_world.operators["ops-admin"]
    args = [(str(pg_world.root), "ops-admin", seed, "exe-a", PG_URL, pg_world.registry_id)] * 6
    with ProcessPoolExecutor(max_workers=6) as pool:
        outcomes = list(pool.map(_commit_worker, args))
    assert outcomes.count("applied") == 1, outcomes
    assert pg_world.reader().get("exe-a").status == "revoked"
    seq, head = _anchor_row(pg_world.registry_id)
    assert seq == len(pg_world.events()) and head == pg_world.events()[-1]["hash"]


def test_a_crash_before_the_anchor_commit_leaves_the_anchor_unchanged_and_reconcile_recovers(pg_world):
    class Crash(RuntimeError):
        pass

    def boom():
        raise Crash("power loss")

    pg_world.reg.refresh()
    before = _anchor_row(pg_world.registry_id)
    req = K.KeyRegistry.sign_request(K.KeyRegistry.new_request(
        op="revoke", actor="ops-admin", expected_version=pg_world.reg.version, kid="exe-a", reason="crash",
        compromised_from_utc="2026-11-26T00:00:00+00:00"), pg_world.operators["ops-admin"])
    with pytest.raises(Crash):
        pg_world.reg._submit(req, hook=boom)
    # The transaction was rolled back: the anchor did not move, and the log holds one unanchored event.
    assert _anchor_row(pg_world.registry_id) == before
    assert len(pg_world.events()) == before[0] + 1
    assert _refuse_code(pg_world.reader) == "anchor_log_ahead"
    pg_world.reg.reconcile()
    assert pg_world.reader().get("exe-a").status == "revoked"
    assert _anchor_row(pg_world.registry_id)[0] == len(pg_world.events())


def test_a_moved_anchor_refuses_a_write_before_anything_is_appended(pg_world):
    import psycopg

    events_before = len(pg_world.events())
    with psycopg.connect(PG_URL, autocommit=True) as conn:
        conn.execute("UPDATE key_registry_anchor SET head_hash = %s WHERE registry_id = %s",
                     ("0" * 64, pg_world.registry_id))
    pg_world.reg.refresh = lambda: None  # a writer that did not re-read is still refused by the write path
    req = K.KeyRegistry.sign_request(K.KeyRegistry.new_request(
        op="revoke", actor="ops-admin", expected_version=events_before, kid="exe-a", reason="x",
        compromised_from_utc="2026-11-26T00:00:00+00:00"), pg_world.operators["ops-admin"])
    assert _refuse_code(lambda: pg_world.reg.apply(req)) == "anchor_head_mismatch"
    assert len(pg_world.events()) == events_before


def test_a_missing_anchor_row_refuses_every_read(pg_world):
    rid = f"pgmissing-{uuid.uuid4().hex[:12]}"
    missing = PostgresAnchor(PG_URL, rid)
    assert missing.current() is None
    assert _refuse_code(lambda: K.KeyRegistry(pg_world.registry_path, trust=pg_world.trust, anchor=missing)) == "anchor_missing"


def test_an_unreachable_anchor_fails_closed(pg_world):
    unreachable = PostgresAnchor("postgresql://127.0.0.1:1/none?connect_timeout=1", pg_world.registry_id)
    with pytest.raises(AnchorError) as exc:
        unreachable.current()
    assert exc.value.code == "anchor_unavailable"
    assert _refuse_code(lambda: K.KeyRegistry(pg_world.registry_path, trust=pg_world.trust, anchor=unreachable)) == "anchor_unavailable"
