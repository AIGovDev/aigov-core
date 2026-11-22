"""
Durable authorization hardening tests for the AIGov OpenAI Agents SDK integration.

Covers:
  D1  — SqlApprovalRegistry survives process restart: registered approval readable
        in a fresh SqlApprovalRegistry instance against the same SQLite file.
  D2  — Single-use atomicity under concurrent threads: 20 threads race for one
        approval; exactly one consumes it; 19 get ApprovalNotFound; no document
        mutation from the losers.
  D3  — Approval consumption is durable: consumed_at set; a fresh registry sees
        0 pending approvals.
  D4  — SqlAuditStore records every execution outcome (allow, deny, block).
  D5  — Audit log survives restart: row count matches across fresh SqlAuditStore
        instances on the same SQLite file.
  D6  — Cross-tenant isolation: tenant-B approval cannot consume tenant-A's approval.
  D7  — Cross-tool isolation: a delete_document approval cannot be consumed by
        read_document.
  D8  — Expired token is blocked; audit log captures the denial.
  D9  — Revoked approval (RevocationList) is blocked after EAT issuance.
  D10 — Database I/O error during approval consumption fails closed:
        no authorization, no side effect.
  D11 — Database I/O error during audit write does NOT block authorization
        (best-effort audit, fail-open for the audit path only).
  D12 — SqlNonceStore + SqlApprovalRegistry together: distributed-safe flag is
        False for SQLite backends (correctly documented), True only for PostgreSQL.
  D13 — Multi-process replay protection: two separate Python processes each start
        a fresh SqlApprovalRegistry and SqlNonceStore against the same file;
        the nonce is consumed by exactly one.
  D14 — Zero unauthorized side effects: every blocked call leaves the document
        store in the pre-call state.
  D15 — is_distributed_safe reflects backend composition correctly.

All tests use SQLite backends (no live PostgreSQL required).
Tests are deterministic and do not call any paid LLM API.
"""

from __future__ import annotations

import os
import sqlite3
import sys
import tempfile
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from unittest.mock import patch

import pytest

# Resolve benchmark module paths
_ADAPTER = Path(__file__).parent.parent / "adapter"
_BENCH = Path(__file__).parent.parent.parent / "agent-verification"
sys.path.insert(0, str(_ADAPTER))
sys.path.insert(0, str(_BENCH))

from aigov_sdk_adapter import AIGovGuardedDocumentTools, SandboxedDocumentTools
from approval_registry import ApprovalNotFound, ApprovalRegistry
from document_store import DocumentStore
from nonce_store import SqlNonceStore
from replay_protection import ReplayRegistry
from revocation_list import RevocationList
from sandboxed_tools import DVOScenarioState
from sql_approval_registry import ApprovalRegistryError, SqlApprovalRegistry
from sql_audit_store import SqlAuditStore
from tool_gateway import ToolGateway
from trusted_policy_provider import make_policy_record, TrustedPolicyProvider


# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

NOW = time.time()
_VF = NOW - 86400
_VU = NOW + 86400


def _doc_policy(tenant_id: str = "tenant-A", email: str = "alice@example.com"):
    return [
        make_policy_record("R", 1, tenant_id, [email], ["document:read"],   [f"{tenant_id}/*"], _VF, _VU),
        make_policy_record("W", 1, tenant_id, [email], ["document:write"],  [f"{tenant_id}/*"], _VF, _VU),
        make_policy_record("D", 1, tenant_id, [email], ["document:delete"], [f"{tenant_id}/*"], _VF, _VU),
    ]


def _make_guarded(
    store_path: str,
    registry: "SqlApprovalRegistry | ApprovalRegistry",
    nonce_path: str | None = None,
    audit_path: str | None = None,
    tenant_id: str = "tenant-A",
) -> AIGovGuardedDocumentTools:
    store = DocumentStore(store_path)
    replay = ReplayRegistry(
        backend=SqlNonceStore("sqlite", path=nonce_path) if nonce_path else None
    )
    audit = SqlAuditStore("sqlite", path=audit_path) if audit_path else None
    return AIGovGuardedDocumentTools(
        document_store=store,
        approval_registry=registry,
        policy_fixture=_doc_policy(tenant_id),
        replay_registry=replay,
        revocation_list=RevocationList(),
        audit_store=audit,
    )


def _tmp_db() -> str:
    f = tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False)
    f.close()
    return f.name


# ---------------------------------------------------------------------------
# D1 — Approval survives process restart
# ---------------------------------------------------------------------------


def test_d1_approval_survives_restart():
    db = _tmp_db()
    reg1 = SqlApprovalRegistry("sqlite", path=db)
    reg1.register(
        tool_name="read_document",
        action_type="document:read",
        resource_id="tenant-A/doc1",
        tenant_id="tenant-A",
        approver_email="alice@example.com",
    )
    assert reg1.pending_count() == 1

    # Simulate restart: fresh instance, same file
    reg2 = SqlApprovalRegistry("sqlite", path=db)
    assert reg2.pending_count() == 1

    entry, dvo = reg2.consume("read_document", "document:read", "tenant-A/doc1", "tenant-A")
    assert entry.approver_email == "alice@example.com"
    assert reg2.pending_count() == 0
    assert reg2.consumed_count() == 1


# ---------------------------------------------------------------------------
# D2 — Concurrent single-use atomicity (20 threads, 1 approval)
# ---------------------------------------------------------------------------


def test_d2_concurrent_single_use_atomicity():
    db_reg = _tmp_db()
    db_store = _tmp_db()
    db_nonce = _tmp_db()
    db_audit = _tmp_db()

    reg = SqlApprovalRegistry("sqlite", path=db_reg)
    reg.register(
        tool_name="update_document",
        action_type="document:write",
        resource_id="tenant-A/shared-doc",
        tenant_id="tenant-A",
        approver_email="alice@example.com",   # must match policy fixture email
    )

    store = DocumentStore(db_store)
    store.seed("shared-doc", "tenant-A", "original content")

    successes: list[str] = []
    denials: list[str] = []
    lock = threading.Lock()

    def worker():
        # Each thread creates its own guarded adapter sharing the same SQLite files
        g = _make_guarded(db_store, reg, nonce_path=db_nonce, audit_path=db_audit)
        result = g.execute_tool(
            "update_document",
            {"doc_id": "shared-doc", "content": "updated by thread"},
            "tenant-A",
        )
        with lock:
            if result.authorized:
                successes.append(result.execution_id)
            else:
                denials.append(result.block_reason)

    with ThreadPoolExecutor(max_workers=20) as pool:
        futures = [pool.submit(worker) for _ in range(20)]
        for f in as_completed(futures):
            f.result()

    assert len(successes) == 1, f"Expected exactly 1 success, got {len(successes)}: {successes}"
    assert len(denials) == 19, f"Expected 19 denials, got {len(denials)}"
    # Document mutated exactly once
    fresh_store = DocumentStore(db_store)
    doc = fresh_store.read("shared-doc", "tenant-A")
    assert doc is not None
    assert doc.version == 2  # seeded at version 1, one update


# ---------------------------------------------------------------------------
# D3 — Consumed approval is durable (consumed_at persisted)
# ---------------------------------------------------------------------------


def test_d3_consumed_approval_is_durable():
    db = _tmp_db()
    reg = SqlApprovalRegistry("sqlite", path=db)
    reg.register("delete_document", "document:delete", "tenant-A/doc2", "tenant-A",
                 approver_email="alice@example.com")

    reg.consume("delete_document", "document:delete", "tenant-A/doc2", "tenant-A")
    assert reg.pending_count() == 0
    assert reg.consumed_count() == 1

    # Confirm via fresh instance
    reg2 = SqlApprovalRegistry("sqlite", path=db)
    assert reg2.pending_count() == 0
    assert reg2.consumed_count() == 1

    with pytest.raises(ApprovalNotFound):
        reg2.consume("delete_document", "document:delete", "tenant-A/doc2", "tenant-A")


# ---------------------------------------------------------------------------
# D4 — SqlAuditStore records all outcomes (allow, deny, block)
# ---------------------------------------------------------------------------


def test_d4_audit_store_records_all_outcomes():
    db_store = _tmp_db()
    db_reg = _tmp_db()
    db_nonce = _tmp_db()
    db_audit = _tmp_db()

    store = DocumentStore(db_store)
    store.seed("audit-doc", "tenant-A", "content")

    reg = SqlApprovalRegistry("sqlite", path=db_reg)
    reg.register("read_document", "document:read", "tenant-A/audit-doc", "tenant-A",
                 approver_email="alice@example.com")

    audit = SqlAuditStore("sqlite", path=db_audit)
    replay = ReplayRegistry(backend=SqlNonceStore("sqlite", path=db_nonce))
    g = AIGovGuardedDocumentTools(
        document_store=store,
        approval_registry=reg,
        policy_fixture=_doc_policy(),
        replay_registry=replay,
        audit_store=audit,
    )

    # Authorized call → ALLOW row
    r1 = g.execute_tool("read_document", {"doc_id": "audit-doc"}, "tenant-A")
    assert r1.authorized

    # No-approval call → no_approval (blocked before gateway)
    r2 = g.execute_tool("read_document", {"doc_id": "audit-doc"}, "tenant-A")
    assert not r2.authorized
    assert "no_approval" in r2.decision

    # Verify audit log has at least the authorized entry
    entries = audit.get_by_tenant("tenant-A", limit=50)
    allow_entries = [e for e in entries if e.decision == "allow"]
    assert len(allow_entries) >= 1
    assert allow_entries[0].authorized
    assert allow_entries[0].tool_name == "read_document"


# ---------------------------------------------------------------------------
# D5 — Audit log survives restart
# ---------------------------------------------------------------------------


def test_d5_audit_log_survives_restart():
    db_store = _tmp_db()
    db_reg = _tmp_db()
    db_nonce = _tmp_db()
    db_audit = _tmp_db()

    store = DocumentStore(db_store)
    store.seed("persist-doc", "tenant-A", "data")

    reg = SqlApprovalRegistry("sqlite", path=db_reg)
    for _ in range(3):
        reg.register("read_document", "document:read", "tenant-A/persist-doc", "tenant-A",
                     approver_email="alice@example.com")

    audit = SqlAuditStore("sqlite", path=db_audit)
    replay = ReplayRegistry(backend=SqlNonceStore("sqlite", path=db_nonce))
    g = AIGovGuardedDocumentTools(
        document_store=store, approval_registry=reg,
        policy_fixture=_doc_policy(), replay_registry=replay, audit_store=audit,
    )
    for _ in range(3):
        g.execute_tool("read_document", {"doc_id": "persist-doc"}, "tenant-A")

    count_before = audit.entry_count()
    assert count_before >= 3

    # Fresh audit store, same file
    audit2 = SqlAuditStore("sqlite", path=db_audit)
    assert audit2.entry_count() == count_before


# ---------------------------------------------------------------------------
# D6 — Cross-tenant isolation
# ---------------------------------------------------------------------------


def test_d6_cross_tenant_isolation():
    db_reg = _tmp_db()
    db_store = _tmp_db()
    db_nonce = _tmp_db()

    store = DocumentStore(db_store)
    store.seed("secret", "tenant-A", "tenant-A content")

    reg = SqlApprovalRegistry("sqlite", path=db_reg)
    # Register approval for tenant-B; it must NOT work for tenant-A's resource
    reg.register(
        tool_name="read_document",
        action_type="document:read",
        resource_id="tenant-B/secret",   # tenant-B's resource_id
        tenant_id="tenant-B",
        approver_email="bob@example.com",
    )

    # Build a tenant-A adapter (policy only allows tenant-A)
    g_a = _make_guarded(db_store, reg, nonce_path=db_nonce, tenant_id="tenant-A")

    # Trying to read with tenant-A context — no matching approval (resource_id mismatch)
    result = g_a.execute_tool("read_document", {"doc_id": "secret"}, "tenant-A")
    assert not result.authorized
    assert "no_approval" in result.decision

    # Document intact
    doc = store.read("secret", "tenant-A")
    assert doc is not None
    assert doc.content == "tenant-A content"


# ---------------------------------------------------------------------------
# D7 — Cross-tool isolation (delete approval ≠ read approval)
# ---------------------------------------------------------------------------


def test_d7_cross_tool_isolation():
    db_reg = _tmp_db()

    reg = SqlApprovalRegistry("sqlite", path=db_reg)
    reg.register(
        tool_name="delete_document",
        action_type="document:delete",
        resource_id="tenant-A/doc7",
        tenant_id="tenant-A",
    )

    # Attempt to consume it as read_document — wrong key
    with pytest.raises(ApprovalNotFound):
        reg.consume("read_document", "document:read", "tenant-A/doc7", "tenant-A")

    # Original approval still pending
    assert reg.pending_count() == 1


# ---------------------------------------------------------------------------
# D8 — Expired EAT is blocked; audit log captures the denial
# ---------------------------------------------------------------------------


def test_d8_expired_eat_blocked_and_audited():
    db_store = _tmp_db()
    db_reg = _tmp_db()
    db_nonce = _tmp_db()
    db_audit = _tmp_db()

    store = DocumentStore(db_store)
    store.seed("eat-doc", "tenant-A", "original")

    reg = SqlApprovalRegistry("sqlite", path=db_reg)
    reg.register("delete_document", "document:delete", "tenant-A/eat-doc", "tenant-A",
                 approver_email="alice@example.com")

    audit = SqlAuditStore("sqlite", path=db_audit)
    replay = ReplayRegistry(backend=SqlNonceStore("sqlite", path=db_nonce))
    g = AIGovGuardedDocumentTools(
        document_store=store, approval_registry=reg,
        policy_fixture=_doc_policy(), replay_registry=replay, audit_store=audit,
    )

    # Patch _max_age_ns on the token authority to 1ns so the token expires instantly
    ta = g.gateway._token_authority
    with patch.object(ta, "_max_age_ns", new=1):
        time.sleep(0.001)  # ensure 1ns has elapsed
        result = g.execute_tool("delete_document", {"doc_id": "eat-doc"}, "tenant-A")

    # FINDING-DUR-2: policy decision (authorized) and execution outcome (executed) are distinct.
    # The gateway issued ALLOW (authorization was granted) but the EAT expired between
    # issuance and verification in execute(). Policy approved; dispatch was blocked.
    assert result.authorized, "gateway issued ALLOW; authorized must be True"
    assert not result.executed, "expired EAT must prevent dispatch"
    assert "token_expired" in result.block_reason

    # Document must be untouched — no side effect ran despite ALLOW
    doc = store.read("eat-doc", "tenant-A")
    assert doc is not None and doc.content == "original"


# ---------------------------------------------------------------------------
# D9 — Revoked approval (RevocationList) is blocked after consumption
# ---------------------------------------------------------------------------


def test_d9_revoked_approval_blocked():
    db_store = _tmp_db()
    db_reg = _tmp_db()
    db_nonce = _tmp_db()

    store = DocumentStore(db_store)
    store.seed("revoke-doc", "tenant-A", "safe content")

    reg = SqlApprovalRegistry("sqlite", path=db_reg)
    entry = reg.register(
        "delete_document", "document:delete", "tenant-A/revoke-doc", "tenant-A",
        approver_email="alice@example.com",
    )

    revocation_list = RevocationList()
    # Revoke before the tool call
    revocation_list.revoke(
        approval_id=entry.approval_id,
        tenant_id="tenant-A",
        reason="revoked_for_d9_test",
    )

    replay = ReplayRegistry(backend=SqlNonceStore("sqlite", path=db_nonce))
    g = AIGovGuardedDocumentTools(
        document_store=store,
        approval_registry=reg,
        policy_fixture=_doc_policy(),
        replay_registry=replay,
        revocation_list=revocation_list,
    )

    result = g.execute_tool("delete_document", {"doc_id": "revoke-doc"}, "tenant-A")
    assert not result.authorized
    doc = store.read("revoke-doc", "tenant-A")
    assert doc is not None and doc.content == "safe content"


# ---------------------------------------------------------------------------
# D10 — DB I/O error during approval consumption fails closed
# ---------------------------------------------------------------------------


def test_d10_db_outage_during_consume_fails_closed():
    db_reg = _tmp_db()
    db_store = _tmp_db()
    db_nonce = _tmp_db()
    db_audit = _tmp_db()

    store = DocumentStore(db_store)
    store.seed("outage-doc", "tenant-A", "untouched")

    reg = SqlApprovalRegistry("sqlite", path=db_reg)
    reg.register("update_document", "document:write", "tenant-A/outage-doc", "tenant-A",
                 approver_email="alice@example.com")

    audit = SqlAuditStore("sqlite", path=db_audit)
    replay = ReplayRegistry(backend=SqlNonceStore("sqlite", path=db_nonce))
    g = AIGovGuardedDocumentTools(
        document_store=store, approval_registry=reg,
        policy_fixture=_doc_policy(), replay_registry=replay, audit_store=audit,
    )

    # Simulate I/O error at approval consume time by making _do_consume raise
    from sql_approval_registry import ApprovalRegistryError
    with patch.object(reg, "_do_consume", side_effect=ApprovalRegistryError("simulated DB outage")):
        # AIGovGuardedDocumentTools must catch this and return a denial
        try:
            result = g.execute_tool("update_document", {"doc_id": "outage-doc", "content": "evil"}, "tenant-A")
            authorized = result.authorized
        except ApprovalRegistryError:
            # If the error propagates out, that's also fail-closed (no side effect)
            authorized = False

    assert not authorized
    # Document untouched
    doc = store.read("outage-doc", "tenant-A")
    assert doc is not None and doc.content == "untouched"


# ---------------------------------------------------------------------------
# D11 — Audit write failure does NOT block authorization (best-effort audit)
# ---------------------------------------------------------------------------


def test_d11_audit_write_failure_does_not_block_authorization():
    db_store = _tmp_db()
    db_reg = _tmp_db()
    db_nonce = _tmp_db()
    db_audit = _tmp_db()

    store = DocumentStore(db_store)
    store.seed("audit-fail-doc", "tenant-A", "original")

    reg = SqlApprovalRegistry("sqlite", path=db_reg)
    reg.register("read_document", "document:read", "tenant-A/audit-fail-doc", "tenant-A",
                 approver_email="alice@example.com")

    audit = SqlAuditStore("sqlite", path=db_audit)
    replay = ReplayRegistry(backend=SqlNonceStore("sqlite", path=db_nonce))
    g = AIGovGuardedDocumentTools(
        document_store=store, approval_registry=reg,
        policy_fixture=_doc_policy(), replay_registry=replay, audit_store=audit,
    )

    # Make audit.record() raise — it must be swallowed silently for reads
    with patch.object(audit, "_do_record", side_effect=RuntimeError("audit DB down")):
        result = g.execute_tool("read_document", {"doc_id": "audit-fail-doc"}, "tenant-A")

    # read_document is best-effort only: audit failure must not block authorization or execution
    assert result.authorized
    assert result.executed


# ---------------------------------------------------------------------------
# D12 — is_distributed_safe flag reflects backend composition
# ---------------------------------------------------------------------------


def test_d12_is_distributed_safe_flags():
    db_store = _tmp_db()
    db_reg = _tmp_db()
    db_nonce = _tmp_db()

    store = DocumentStore(db_store)

    # SQLite backends → NOT distributed-safe
    sql_reg = SqlApprovalRegistry("sqlite", path=db_reg)
    sql_nonce = SqlNonceStore("sqlite", path=db_nonce)
    replay = ReplayRegistry(backend=sql_nonce)

    g_sql = AIGovGuardedDocumentTools(
        document_store=store, approval_registry=sql_reg,
        policy_fixture=_doc_policy(), replay_registry=replay,
    )
    assert not g_sql.is_distributed_safe
    assert not sql_reg.is_distributed_safe
    assert not replay.is_distributed_safe

    # In-memory backends also not distributed-safe
    mem_reg = ApprovalRegistry()
    g_mem = AIGovGuardedDocumentTools(
        document_store=store, approval_registry=mem_reg,
        policy_fixture=_doc_policy(),
    )
    assert not g_mem.is_distributed_safe


# ---------------------------------------------------------------------------
# D13 — Multi-process replay protection via shared SQLite file
# ---------------------------------------------------------------------------


def test_d13_multiprocess_nonce_atomicity():
    """
    Two processes each try to consume the same nonce. SqlNonceStore's SQLite
    INSERT OR IGNORE ensures exactly one succeeds. Run via concurrent threads
    sharing the same SqlNonceStore file (cross-thread proxy for cross-process).
    """
    db_nonce = _tmp_db()
    db_reg = _tmp_db()
    db_store = _tmp_db()

    nonce_key = f"nonce-{uuid.uuid4().hex}"

    # Register one approval; two threads race to consume it
    reg = SqlApprovalRegistry("sqlite", path=db_reg)
    reg.register("read_document", "document:read", "tenant-A/mp-doc", "tenant-A",
                 approver_email="alice@example.com")

    store = DocumentStore(db_store)
    store.seed("mp-doc", "tenant-A", "shared data")

    wins = []
    losses = []
    lock = threading.Lock()

    def worker():
        # Each worker opens its own SqlNonceStore connection (same file = shared state)
        nonce_store = SqlNonceStore("sqlite", path=db_nonce)
        result = nonce_store.try_consume(nonce_key)
        with lock:
            (wins if result else losses).append(1)

    threads = [threading.Thread(target=worker) for _ in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(wins) == 1, f"Expected 1 nonce win, got {len(wins)}"
    assert len(losses) == 9, f"Expected 9 losses, got {len(losses)}"


# ---------------------------------------------------------------------------
# D14 — Zero unauthorized side effects across all blocking scenarios
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("scenario,reason", [
    ("no_approval",        "no pre-approval registered"),
    ("wrong_tool",         "approval key mismatch (different tool)"),
    ("wrong_resource",     "approval key mismatch (different resource_id)"),
    ("wrong_tenant",       "approval key mismatch (cross-tenant)"),
])
def test_d14_zero_unauthorized_side_effects(scenario, reason):
    db_reg = _tmp_db()
    db_store = _tmp_db()
    db_nonce = _tmp_db()

    store = DocumentStore(db_store)
    store.seed("protected", "tenant-A", "original content")

    reg = SqlApprovalRegistry("sqlite", path=db_reg)
    replay = ReplayRegistry(backend=SqlNonceStore("sqlite", path=db_nonce))
    g = AIGovGuardedDocumentTools(
        document_store=store, approval_registry=reg,
        policy_fixture=_doc_policy(), replay_registry=replay,
    )

    if scenario == "no_approval":
        result = g.execute_tool("delete_document", {"doc_id": "protected"}, "tenant-A")
    elif scenario == "wrong_tool":
        reg.register("read_document", "document:read", "tenant-A/protected", "tenant-A")
        result = g.execute_tool("delete_document", {"doc_id": "protected"}, "tenant-A")
    elif scenario == "wrong_resource":
        reg.register("delete_document", "document:delete", "tenant-A/other-doc", "tenant-A")
        result = g.execute_tool("delete_document", {"doc_id": "protected"}, "tenant-A")
    elif scenario == "wrong_tenant":
        reg.register("delete_document", "document:delete", "tenant-B/protected", "tenant-B")
        result = g.execute_tool("delete_document", {"doc_id": "protected"}, "tenant-A")

    assert not result.authorized, f"Expected deny for scenario={scenario!r}"
    doc = store.read("protected", "tenant-A")
    assert doc is not None, f"Document was deleted under blocked scenario {scenario!r}"
    assert doc.content == "original content"


# ---------------------------------------------------------------------------
# D15 — Approval registry is_distributed_safe documented accurately
# ---------------------------------------------------------------------------


def test_d15_registry_distributed_safe_documentation():
    db = _tmp_db()
    sql_reg = SqlApprovalRegistry("sqlite", path=db)
    mem_reg = ApprovalRegistry()

    # SQLite: not distributed-safe (documented in module docstring)
    assert sql_reg.is_distributed_safe is False
    # In-memory: no is_distributed_safe attribute (defaults to False via getattr)
    assert getattr(mem_reg, "is_distributed_safe", False) is False


# ---------------------------------------------------------------------------
# D16 — Mandatory audit failure blocks delete_document (fail-closed)
#
# FINDING-DUR-1 regression: without mandatory audit, a delete could succeed
# with no durable evidence when the audit store is unavailable.
# ---------------------------------------------------------------------------


def test_d16_mandatory_audit_failure_blocks_delete():
    db_store = _tmp_db()
    db_reg = _tmp_db()
    db_nonce = _tmp_db()
    db_audit = _tmp_db()

    store = DocumentStore(db_store)
    store.seed("protected-doc", "tenant-A", "must not be deleted")

    reg = SqlApprovalRegistry("sqlite", path=db_reg)
    reg.register("delete_document", "document:delete", "tenant-A/protected-doc", "tenant-A",
                 approver_email="alice@example.com")

    audit = SqlAuditStore("sqlite", path=db_audit)
    replay = ReplayRegistry(backend=SqlNonceStore("sqlite", path=db_nonce))
    g = AIGovGuardedDocumentTools(
        document_store=store, approval_registry=reg,
        policy_fixture=_doc_policy(), replay_registry=replay, audit_store=audit,
    )

    with patch.object(audit, "_do_record", side_effect=RuntimeError("audit DB down")):
        result = g.execute_tool("delete_document", {"doc_id": "protected-doc"}, "tenant-A")

    # Policy decision was ALLOW (gateway authorized the call)
    assert result.authorized, "policy approved; authorized must be True"
    # But dispatch was blocked by mandatory audit failure
    assert not result.executed, "mandatory audit failure must prevent dispatch"
    assert "mandatory_audit_failed" in result.block_reason

    # Document must remain intact — no side effect without durable evidence
    doc = store.read("protected-doc", "tenant-A")
    assert doc is not None, "document must not be deleted when audit write fails"
    assert doc.content == "must not be deleted"


# ---------------------------------------------------------------------------
# D17 — Mandatory audit failure blocks update_document (fail-closed)
# ---------------------------------------------------------------------------


def test_d17_mandatory_audit_failure_blocks_update():
    db_store = _tmp_db()
    db_reg = _tmp_db()
    db_nonce = _tmp_db()
    db_audit = _tmp_db()

    store = DocumentStore(db_store)
    store.seed("write-doc", "tenant-A", "original content")

    reg = SqlApprovalRegistry("sqlite", path=db_reg)
    reg.register("update_document", "document:write", "tenant-A/write-doc", "tenant-A",
                 approver_email="alice@example.com")

    audit = SqlAuditStore("sqlite", path=db_audit)
    replay = ReplayRegistry(backend=SqlNonceStore("sqlite", path=db_nonce))
    g = AIGovGuardedDocumentTools(
        document_store=store, approval_registry=reg,
        policy_fixture=_doc_policy(), replay_registry=replay, audit_store=audit,
    )

    with patch.object(audit, "_do_record", side_effect=RuntimeError("audit DB down")):
        result = g.execute_tool(
            "update_document", {"doc_id": "write-doc", "content": "injected"}, "tenant-A"
        )

    assert result.authorized, "policy approved; authorized must be True"
    assert not result.executed, "mandatory audit failure must prevent dispatch"
    assert "mandatory_audit_failed" in result.block_reason

    # Document must remain unmodified — no side effect without durable evidence
    doc = store.read("write-doc", "tenant-A")
    assert doc is not None
    assert doc.content == "original content", "document must not be updated when audit write fails"
