"""PostgreSQL-backed: console.runs ownership enforcement with the additive migration.

Opt-in: AIGOV_TEST_PG_RUNS=1. When enabled, a missing or non-test database FAILS (never skips).
The test drops and recreates the test-only schema ``console`` in the named test database.
"""

import os
import pathlib
import uuid

import psycopg
import pytest
from aigov_py.govai_postgres_runs import upsert_run_row_postgres
from aigov_py.tenant_ledger import RunOwnershipError

REPO = pathlib.Path(__file__).resolve().parents[2]
MIGRATION = REPO / "docs" / "operations" / "runs-tenant-migration.sql"

pytestmark = pytest.mark.skipif(
    os.environ.get("AIGOV_TEST_PG_RUNS", "").strip() != "1",
    reason="NOT RUN: set AIGOV_TEST_PG_RUNS=1 and GOVAI_DATABASE_URL to a disposable test database",
)


def _dsn():
    dsn = (os.environ.get("GOVAI_DATABASE_URL") or os.environ.get("DATABASE_URL") or "").strip()
    assert dsn, "AIGOV_TEST_PG_RUNS=1 but no GOVAI_DATABASE_URL/DATABASE_URL (fail closed)"
    name = dsn.split("?")[0].rsplit("/", 1)[-1]
    assert "test" in name, f"refusing to run against database {name!r}: name must contain 'test'"
    assert "@localhost" in dsn or "@127.0.0.1" in dsn, "refusing non-local database"
    return dsn


def _row(run_id, tenant):
    return {
        "id": run_id, "tenant_id": tenant, "created_at": "2026-01-01T00:00:00Z", "mode": "ci",
        "status": "valid", "policy_version": "v0.5_dev", "bundle_sha256": "a", "evidence_sha256": "b",
        "report_sha256": "c", "evidence_source": "test", "closed_at": "2026-01-01T00:00:01Z",
        "environment": "dev",
    }


@pytest.fixture
def db(monkeypatch):
    dsn = _dsn()
    monkeypatch.setenv("GOVAI_DATABASE_URL", dsn)
    with psycopg.connect(dsn, autocommit=True) as conn:
        conn.execute("drop schema if exists console cascade")
        conn.execute("create schema console")
        # Legacy shape: no tenant column, id is the key.
        conn.execute(
            """create table console.runs (
                 id text primary key, created_at timestamptz, mode text, status text,
                 policy_version text, bundle_sha256 text, evidence_sha256 text, report_sha256 text,
                 evidence_source text, closed_at timestamptz, environment text)"""
        )
        conn.execute(
            "insert into console.runs (id, created_at, closed_at, mode, status) "
            "values ('legacy-1', now(), now(), 'ci', 'valid')"
        )
        conn.execute(MIGRATION.read_text(encoding="utf-8"))
    yield dsn


def test_owner_can_update_own_run_and_others_are_refused(db):
    run = f"run-{uuid.uuid4().hex[:8]}"
    upsert_run_row_postgres(_row(run, "acme"))
    upsert_run_row_postgres(_row(run, "acme"))  # same owner: allowed
    with pytest.raises(RunOwnershipError):
        upsert_run_row_postgres(_row(run, "globex"))  # cross-tenant overwrite: refused
    with psycopg.connect(db) as conn:
        owner = conn.execute("select tenant_id from console.runs where id = %s", (run,)).fetchone()[0]
    assert owner == "acme", "the stored row must still belong to the original tenant"


def test_legacy_unowned_row_is_never_overwritten(db):
    with pytest.raises(RunOwnershipError):
        upsert_run_row_postgres(_row("legacy-1", "acme"))
    with psycopg.connect(db) as conn:
        assert conn.execute("select tenant_id from console.runs where id = 'legacy-1'").fetchone()[0] is None


def test_rejects_malformed_tenant_before_touching_database(db):
    from aigov_py.tenant_ledger import TenantLedgerError

    with pytest.raises(TenantLedgerError):
        upsert_run_row_postgres(_row("run-x", "team.a"))
