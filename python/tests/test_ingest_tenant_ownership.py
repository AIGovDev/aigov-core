"""Operator ingest refuses to write runs the claimed tenant does not own (no database)."""

import json

import aigov_py.ingest_run as ingest
import pytest


@pytest.fixture
def calls(monkeypatch, tmp_path):
    monkeypatch.setenv("GOVAI_LEDGER_DIR", str(tmp_path))
    monkeypatch.delenv("AIGOV_TENANT_ID", raising=False)
    record = {"upserts": [], "uploads": []}
    monkeypatch.setattr(ingest, "build_run_row", lambda run_id, tenant_id: {"id": run_id, "tenant_id": tenant_id})
    monkeypatch.setattr(ingest, "upsert_run_row", lambda row: record["upserts"].append(row))
    monkeypatch.setattr(ingest, "upload_run_artifacts", lambda run_id, tenant_id, mode: record["uploads"].append((run_id, tenant_id)))
    return record


def _ledger(tmp_path, tenant, run_id):
    from aigov_py.tenant_ledger import ledger_path_for_tenant

    path = ledger_path_for_tenant(tenant, ledger_dir=str(tmp_path))
    event = {"event_id": "e1", "run_id": run_id}
    path.write_text(json.dumps({"prev_hash": "0", "record_hash": "1", "event_json": json.dumps(event)}) + "\n", encoding="utf-8")


def test_missing_tenant_is_refused(calls):
    assert ingest.main(["ingest_run", "run-1"]) == 2
    assert calls["upserts"] == [] and calls["uploads"] == []


def test_malformed_tenant_is_refused(calls):
    assert ingest.main(["ingest_run", "run-1", "--tenant-id", "team.a"]) == 2
    assert calls["upserts"] == []


def test_run_not_in_claimed_tenant_ledger_is_refused_before_any_write(calls, tmp_path):
    _ledger(tmp_path, "acme", "run-1")
    # Spoof: globex claims acme's run.
    assert ingest.main(["ingest_run", "run-1", "--tenant-id", "globex"]) == 2
    assert calls["upserts"] == [] and calls["uploads"] == []


def test_owner_tenant_ingests_and_row_carries_tenant(calls, tmp_path):
    _ledger(tmp_path, "acme", "run-1")
    assert ingest.main(["ingest_run", "run-1", "--tenant-id", "acme"]) == 0
    assert calls["upserts"] == [{"id": "run-1", "tenant_id": "acme"}]
    assert calls["uploads"] == [("run-1", "acme")]


def test_tenant_from_environment_is_accepted(calls, tmp_path, monkeypatch):
    _ledger(tmp_path, "acme", "run-2")
    monkeypatch.setenv("AIGOV_TENANT_ID", "acme")
    assert ingest.main(["ingest_run", "run-2"]) == 0
    assert calls["upserts"][0]["tenant_id"] == "acme"
