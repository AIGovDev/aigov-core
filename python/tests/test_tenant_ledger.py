"""Tenant ledger mapping and run ownership (no database). Vectors match rust/src/project.rs."""

import json

import pytest
from aigov_py.tenant_ledger import (
    LEGACY_TENANTS_ENV,
    TenantLedgerError,
    ledger_path_for_tenant,
    run_recorded_for_tenant,
    tenant_ledger_segment,
    tenant_ledger_segment_legacy,
    validate_tenant_id,
)

VECTORS = {
    "team.a": "~h7465616d2e61",
    "team_a": "team_a",
    "a/b": "~h612f62",
    "a_b": "a_b",
    "café": "~h636166c3a9",
    "café": "~h63616665cc81",
    "Team": "Team",
    "../x": "~h2e2e2f78",
    "": "~h",
}


@pytest.mark.parametrize("tenant,segment", VECTORS.items())
def test_segment_vectors_match_rust(tenant, segment):
    assert tenant_ledger_segment(tenant) == segment


def test_distinct_tenants_never_share_a_segment():
    segments = {}
    for t in list(VECTORS) + ["x" * 129, "x" * 130, "é" * 80]:
        seg = tenant_ledger_segment(t)
        assert "." not in seg and "/" not in seg and "\\" not in seg
        assert segments.setdefault(seg, t) == t, f"{t!r} and {segments.get(seg)!r} share {seg!r}"


def test_legacy_segment_is_lossy_by_design():
    assert tenant_ledger_segment_legacy("team.a") == tenant_ledger_segment_legacy("team_a") == "team_a"


def test_validate_rejects_malformed_ids():
    for bad in ["", " ", "team a", "a/b", "../x", "x" * 129, "é", None]:
        with pytest.raises(TenantLedgerError):
            validate_tenant_id(bad)
    assert validate_tenant_id("team-alpha_01") == "team-alpha_01"


def _write_ledger(tmp_path, tenant, run_ids):
    path = ledger_path_for_tenant(tenant, ledger_dir=str(tmp_path))
    lines = []
    for run in run_ids:
        event = {"event_id": f"{run}-e", "run_id": run}
        lines.append(json.dumps({"prev_hash": "0", "record_hash": "1", "event_json": json.dumps(event)}))
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def test_owner_proven_from_own_ledger(tmp_path):
    _write_ledger(tmp_path, "acme", ["run-1"])
    assert run_recorded_for_tenant("run-1", "acme", ledger_dir=str(tmp_path)) is True


def test_spoofed_tenant_claim_is_not_proven(tmp_path):
    _write_ledger(tmp_path, "acme", ["run-1"])
    # Another tenant claims the same run: its own ledger does not contain it.
    assert run_recorded_for_tenant("run-1", "globex", ledger_dir=str(tmp_path)) is False


def test_dotted_tenant_cannot_prove_ownership_of_underscored_tenant(tmp_path):
    _write_ledger(tmp_path, "team_a", ["run-1"])
    # Dotted ids are not valid tenant ids for ownership proofs, so the claim is refused outright.
    with pytest.raises(TenantLedgerError):
        run_recorded_for_tenant("run-1", "team.a", ledger_dir=str(tmp_path))


def test_missing_ledger_fails_closed(tmp_path):
    assert run_recorded_for_tenant("run-1", "acme", ledger_dir=str(tmp_path)) is False


def test_malformed_ledger_line_raises_instead_of_denying_silently(tmp_path):
    path = ledger_path_for_tenant("acme", ledger_dir=str(tmp_path))
    path.write_text("not json\n", encoding="utf-8")
    with pytest.raises(TenantLedgerError):
        run_recorded_for_tenant("run-1", "acme", ledger_dir=str(tmp_path))


def test_legacy_listed_tenant_reads_legacy_file(tmp_path, monkeypatch):
    monkeypatch.setenv(LEGACY_TENANTS_ENV, "team.a")
    path = ledger_path_for_tenant("team.a", ledger_dir=str(tmp_path))
    assert path.name == "audit_log__team_a.jsonl"
    monkeypatch.delenv(LEGACY_TENANTS_ENV)
    assert ledger_path_for_tenant("team.a", ledger_dir=str(tmp_path)).name == "audit_log__~h7465616d2e61.jsonl"
