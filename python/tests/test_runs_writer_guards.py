from types import SimpleNamespace

"""Run-row writers: production refusal, tenant requirement, owner check, tenant-scoped artifacts."""


import pytest

from aigov_py import supabase_db
from aigov_py.storage_upload import upload_artifacts_for_run
from aigov_py.tenant_ledger import RunOwnershipError, TenantLedgerError


def test_supabase_writer_refused_in_production(monkeypatch):
    monkeypatch.setenv("AIGOV_ENVIRONMENT", "prod")

    def no_client(**_):
        raise AssertionError("client must not be created in production")

    monkeypatch.setattr(supabase_db, "create_supabase_client", no_client)
    with pytest.raises(RuntimeError, match="disabled in production"):
        supabase_db.upsert_run_row_via_supabase({"id": "r", "tenant_id": "acme"})


def test_supabase_writer_requires_valid_tenant(monkeypatch):
    monkeypatch.setenv("AIGOV_ENVIRONMENT", "staging")
    monkeypatch.setattr(supabase_db, "create_supabase_client", lambda **_: pytest.fail("no client without tenant"))
    with pytest.raises(TenantLedgerError):
        supabase_db.upsert_run_row_via_supabase({"id": "r"})


class _Executable:
    error = None

    def execute(self):
        return self


class _FakeTable:
    def __init__(self, store, name):
        self.store, self.name, self.filters = store, name, {}
        self.payload = None

    def select(self, _cols):
        return self

    def eq(self, col, val):
        self.filters[col] = val
        return self

    def execute(self):
        rows = [r for r in self.store.get(self.name, []) if all(r.get(c) == v for c, v in self.filters.items())]
        return SimpleNamespace(data=rows, error=None)

    def upsert(self, row, on_conflict=None):
        self.store.setdefault(self.name, []).append(row)
        return _Executable()


class _FakeClient:
    def __init__(self, store):
        self.store = store

    def table(self, name):
        return _FakeTable(self.store, name)


def test_supabase_writer_refuses_run_owned_by_another_tenant(monkeypatch):
    monkeypatch.setenv("AIGOV_ENVIRONMENT", "staging")
    store = {"runs": [{"id": "run-1", "tenant_id": "acme"}]}
    monkeypatch.setattr(supabase_db, "create_supabase_client", lambda **_: _FakeClient(store))
    with pytest.raises(RunOwnershipError):
        supabase_db.upsert_run_row_via_supabase({"id": "run-1", "tenant_id": "globex"})
    assert len(store["runs"]) == 1, "nothing may be written"


def test_supabase_writer_refuses_legacy_unowned_run(monkeypatch):
    monkeypatch.setenv("AIGOV_ENVIRONMENT", "staging")
    store = {"runs": [{"id": "legacy-1", "tenant_id": None}]}
    monkeypatch.setattr(supabase_db, "create_supabase_client", lambda **_: _FakeClient(store))
    with pytest.raises(RunOwnershipError):
        supabase_db.upsert_run_row_via_supabase({"id": "legacy-1", "tenant_id": "acme"})


def test_supabase_writer_allows_same_owner_update(monkeypatch):
    monkeypatch.setenv("AIGOV_ENVIRONMENT", "staging")
    store = {"runs": [{"id": "run-1", "tenant_id": "acme"}]}
    monkeypatch.setattr(supabase_db, "create_supabase_client", lambda **_: _FakeClient(store))
    supabase_db.upsert_run_row_via_supabase({"id": "run-1", "tenant_id": "acme"})
    assert len(store["runs"]) == 2


def test_artifact_objects_are_tenant_scoped(monkeypatch, tmp_path):
    seen = []

    def fake_upload(client, *, bucket, object_name, path, content_type=None):
        seen.append((bucket, object_name))
        from aigov_py.storage_upload import UploadResult
        return UploadResult(ok=True, bucket=bucket, object_name=object_name, message="ok")

    monkeypatch.setattr("aigov_py.storage_upload.upload_file_path", fake_upload)
    f = tmp_path / "x"
    f.write_text("{}")
    upload_artifacts_for_run(None, run_id="run-1", tenant_id="acme", pack_zip=f, audit_json=f, evidence_json=f)
    assert seen and all(name.startswith("acme/run-1") for _, name in seen), seen
