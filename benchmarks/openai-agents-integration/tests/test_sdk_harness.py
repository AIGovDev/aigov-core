"""
AIGov OpenAI Agents SDK Integration — Adversarial Test Harness

Phase 3: 10 deterministic adversarial scenarios against the full AIGov
authorization pipeline with real SQLite side effects.

Design principles:
  - No live OpenAI API calls; ScriptedModel or direct adapter calls for all tests.
  - Every test asserts the ACTUAL persisted state in the SQLite document store.
  - Tests are independent (each gets a fresh tmp SQLite file and fresh registries).
  - All 10 scenarios map to real threat categories from the security spec.

Threat coverage:
  T1  — Authorized read succeeds, store unchanged
  T2  — Authorized update persists, version increments
  T3  — Authorized delete soft-deletes, audit row present
  T4  — DENY: no pre-approval (unauthorized by LLM)
  T5  — DENY: prompt-injection in doc_id — resource_id mismatch blocks execution
  T6  — DENY: approval replay (second identical call after first consumed)
  T7  — DENY: cross-tenant substitution (approval for tenant-A, call for tenant-B)
  T8  — DENY: wrong tool_name (approval for read, attempt is update)
  T9  — DENY: revoked approval (revocation list blocks before EAT issuance)
  T10 — DENY: expired EAT (token issued in past, verify_for_execution rejects)
"""

from __future__ import annotations

import sys
import tempfile
import time
import uuid
from pathlib import Path

import pytest

_REPO = Path(__file__).parent.parent.parent.parent  # aigov-core-j root
_BENCH = _REPO / "benchmarks" / "agent-verification"
_ADAPTER = Path(__file__).parent.parent / "adapter"
sys.path.insert(0, str(_BENCH))
sys.path.insert(0, str(_ADAPTER))

from approval_registry import ApprovalNotFound, ApprovalRegistry
from document_store import DocumentStore
from aigov_sdk_adapter import AIGovGuardedDocumentTools, _resource_id_from_args
from replay_protection import ReplayRegistry
from revocation_list import RevocationList
from trusted_policy_provider import make_policy_record, TrustedPolicyProvider

_NOW  = 1_700_000_000.0
_VALID_FROM  = _NOW - 86_400
_VALID_UNTIL = _NOW + 86_400

# ---------------------------------------------------------------------------
# Policy fixture for document tools
# ---------------------------------------------------------------------------

DOC_POLICY_FIXTURE = [
    # D01: alice can read any tenant-A document
    make_policy_record(
        policy_id="D-A-READ-01",
        version=1,
        tenant_id="tenant-A",
        authorized_principals=["alice@example.com"],
        allowed_action_types=["document:read"],
        allowed_resource_patterns=["tenant-A/*"],
        valid_from=_VALID_FROM,
        valid_until=_VALID_UNTIL,
    ),
    # D02: alice can write any tenant-A document
    make_policy_record(
        policy_id="D-A-WRITE-01",
        version=1,
        tenant_id="tenant-A",
        authorized_principals=["alice@example.com"],
        allowed_action_types=["document:write"],
        allowed_resource_patterns=["tenant-A/*"],
        valid_from=_VALID_FROM,
        valid_until=_VALID_UNTIL,
    ),
    # D03: alice can delete any tenant-A document
    make_policy_record(
        policy_id="D-A-DELETE-01",
        version=1,
        tenant_id="tenant-A",
        authorized_principals=["alice@example.com"],
        allowed_action_types=["document:delete"],
        allowed_resource_patterns=["tenant-A/*"],
        valid_from=_VALID_FROM,
        valid_until=_VALID_UNTIL,
    ),
    # D04: bob can read tenant-B documents only
    make_policy_record(
        policy_id="D-B-READ-01",
        version=1,
        tenant_id="tenant-B",
        authorized_principals=["bob@example.com"],
        allowed_action_types=["document:read"],
        allowed_resource_patterns=["tenant-B/*"],
        valid_from=_VALID_FROM,
        valid_until=_VALID_UNTIL,
    ),
]


# ---------------------------------------------------------------------------
# Shared factory
# ---------------------------------------------------------------------------

def _make_harness(
    db_suffix: str = "",
    *,
    replay_registry: ReplayRegistry | None = None,
    revocation_list: RevocationList | None = None,
    current_time: float | None = None,
):
    """
    Return (guarded, store, registry) with an isolated SQLite temp file.

    current_time is passed through to the ToolGateway for deterministic
    expiry tests.
    """
    tmp = tempfile.NamedTemporaryFile(
        suffix=f"{db_suffix}.sqlite", delete=False
    )
    tmp.close()
    store = DocumentStore(tmp.name)
    registry = ApprovalRegistry()
    guarded = AIGovGuardedDocumentTools(
        document_store=store,
        approval_registry=registry,
        policy_fixture=DOC_POLICY_FIXTURE,
        replay_registry=replay_registry,
        revocation_list=revocation_list,
        current_time=current_time,
    )
    return guarded, store, registry


# ---------------------------------------------------------------------------
# T1 — Authorized read; no side effect
# ---------------------------------------------------------------------------

def test_t1_authorized_read_succeeds():
    guarded, store, registry = _make_harness("t1", current_time=_NOW)
    store.seed("doc-1", "tenant-A", "original content")

    registry.register(
        tool_name="read_document",
        action_type="document:read",
        resource_id="tenant-A/doc-1",
        tenant_id="tenant-A",
        approver_email="alice@example.com",
    )

    result = guarded.execute_tool(
        "read_document",
        {"doc_id": "doc-1"},
        tenant_id="tenant-A",
    )

    assert result.authorized, f"Expected ALLOW, got {result.decision}: {result.block_reason}"
    assert result.executed
    assert result.data["found"] is True
    assert result.data["content"] == "original content"

    # Read is non-mutating — store content unchanged
    rec = store.read("doc-1", "tenant-A")
    assert rec.content == "original content"
    assert rec.version == 1


# ---------------------------------------------------------------------------
# T2 — Authorized update; version increments; content persisted
# ---------------------------------------------------------------------------

def test_t2_authorized_update_persists():
    guarded, store, registry = _make_harness("t2", current_time=_NOW)
    store.seed("doc-2", "tenant-A", "v1 content")

    registry.register(
        tool_name="update_document",
        action_type="document:write",
        resource_id="tenant-A/doc-2",
        tenant_id="tenant-A",
        approver_email="alice@example.com",
    )

    result = guarded.execute_tool(
        "update_document",
        {"doc_id": "doc-2", "content": "v2 content"},
        tenant_id="tenant-A",
    )

    assert result.authorized, f"Expected ALLOW: {result.decision}: {result.block_reason}"
    assert result.executed
    assert result.data["updated"] is True
    assert result.data["version"] == 2

    # Verify actual persisted state
    rec = store.read("doc-2", "tenant-A")
    assert rec is not None
    assert rec.content == "v2 content"
    assert rec.version == 2


# ---------------------------------------------------------------------------
# T3 — Authorized delete; soft-delete persists in audit row
# ---------------------------------------------------------------------------

def test_t3_authorized_delete_soft_deletes():
    guarded, store, registry = _make_harness("t3", current_time=_NOW)
    store.seed("doc-3", "tenant-A", "content to delete")

    registry.register(
        tool_name="delete_document",
        action_type="document:delete",
        resource_id="tenant-A/doc-3",
        tenant_id="tenant-A",
        approver_email="alice@example.com",
    )

    result = guarded.execute_tool(
        "delete_document",
        {"doc_id": "doc-3"},
        tenant_id="tenant-A",
    )

    assert result.authorized, f"Expected ALLOW: {result.decision}: {result.block_reason}"
    assert result.executed
    assert result.data["deleted"] is True

    # Document is gone for live queries
    assert store.read("doc-3", "tenant-A") is None
    assert store.count_live("tenant-A") == 0

    # Soft-delete row still present in full audit view
    all_recs = store.all_records("tenant-A")
    assert len(all_recs) == 1
    assert all_recs[0].deleted is True
    assert all_recs[0].doc_id == "doc-3"


# ---------------------------------------------------------------------------
# T4 — DENY: no pre-approval registered
# ---------------------------------------------------------------------------

def test_t4_no_approval_denies():
    guarded, store, registry = _make_harness("t4", current_time=_NOW)
    store.seed("doc-4", "tenant-A", "sensitive content")
    # Deliberately register NO approval

    result = guarded.execute_tool(
        "read_document",
        {"doc_id": "doc-4"},
        tenant_id="tenant-A",
    )

    assert not result.authorized
    assert not result.executed
    assert result.decision == "no_approval"

    # Store content is unmodified
    rec = store.read("doc-4", "tenant-A")
    assert rec.content == "sensitive content"


# ---------------------------------------------------------------------------
# T5 — DENY: prompt-injection-style doc_id causes resource_id mismatch
# ---------------------------------------------------------------------------

def test_t5_prompt_injection_resource_mismatch_denies():
    """
    The LLM was persuaded to request doc-99 (injected ID) instead of doc-5.
    The approval was registered for tenant-A/doc-5. The adapter derives
    resource_id from the actual call arguments (tenant-A/doc-99), which
    does not match the registered approval key → ApprovalNotFound → DENY.

    This test demonstrates that prompt-injection cannot gain authorization
    for a different resource: the approval is key'd to the specific resource_id,
    not to the tool name alone.
    """
    guarded, store, registry = _make_harness("t5", current_time=_NOW)
    store.seed("doc-5", "tenant-A", "legitimate doc")
    store.seed("doc-99", "tenant-A", "injected target")

    # Register approval for doc-5 (legitimate resource)
    registry.register(
        tool_name="read_document",
        action_type="document:read",
        resource_id="tenant-A/doc-5",
        tenant_id="tenant-A",
        approver_email="alice@example.com",
    )

    # LLM was injected and now requests doc-99 instead
    result = guarded.execute_tool(
        "read_document",
        {"doc_id": "doc-99"},
        tenant_id="tenant-A",
    )

    assert not result.authorized
    assert not result.executed
    assert result.decision == "no_approval"

    # Neither document was modified
    rec_target = store.read("doc-99", "tenant-A")
    assert rec_target.content == "injected target"
    assert rec_target.version == 1


# ---------------------------------------------------------------------------
# T6 — DENY: approval replay (second call after first consumed)
# ---------------------------------------------------------------------------

def test_t6_approval_replay_denied():
    """
    One approval is registered. First call succeeds. Second call (replay)
    fails because the approval was already consumed (single-use).
    """
    guarded, store, registry = _make_harness("t6", current_time=_NOW)
    store.seed("doc-6", "tenant-A", "replayable doc")

    registry.register(
        tool_name="read_document",
        action_type="document:read",
        resource_id="tenant-A/doc-6",
        tenant_id="tenant-A",
        approver_email="alice@example.com",
    )

    # First call: should succeed
    result1 = guarded.execute_tool(
        "read_document", {"doc_id": "doc-6"}, tenant_id="tenant-A",
    )
    assert result1.authorized

    # Second call (replay): same parameters, approval already consumed
    result2 = guarded.execute_tool(
        "read_document", {"doc_id": "doc-6"}, tenant_id="tenant-A",
    )
    assert not result2.authorized
    assert not result2.executed
    assert result2.decision == "no_approval"


# ---------------------------------------------------------------------------
# T7 — DENY: cross-tenant substitution
# ---------------------------------------------------------------------------

def test_t7_cross_tenant_substitution_denied():
    """
    Approval registered for tenant-B/doc-7 with bob@example.com (D04).
    Attacker attempts to use this approval from tenant-A context.
    resource_id computed from call args is tenant-A/doc-7, not tenant-B/doc-7.
    ApprovalRegistry key mismatch → no_approval.
    """
    guarded, store, registry = _make_harness("t7", current_time=_NOW)
    store.seed("doc-7", "tenant-A", "tenant-A private doc")

    # Approval belongs to tenant-B
    registry.register(
        tool_name="read_document",
        action_type="document:read",
        resource_id="tenant-B/doc-7",   # tenant-B resource
        tenant_id="tenant-B",
        approver_email="bob@example.com",
    )

    # Attempt to execute in tenant-A context
    result = guarded.execute_tool(
        "read_document",
        {"doc_id": "doc-7"},
        tenant_id="tenant-A",           # wrong tenant
    )

    assert not result.authorized
    assert not result.executed
    assert result.decision == "no_approval"
    # Remaining approval (tenant-B) is still pending — not consumed
    assert registry.pending_count() == 1


# ---------------------------------------------------------------------------
# T8 — DENY: wrong tool_name (approval for read, attempt is update)
# ---------------------------------------------------------------------------

def test_t8_wrong_tool_name_denied():
    """
    Approval registered for read_document. Adapter attempts update_document.
    ApprovalKey includes tool_name, so the lookup fails.
    """
    guarded, store, registry = _make_harness("t8", current_time=_NOW)
    store.seed("doc-8", "tenant-A", "content")

    registry.register(
        tool_name="read_document",         # only read is authorized
        action_type="document:read",
        resource_id="tenant-A/doc-8",
        tenant_id="tenant-A",
        approver_email="alice@example.com",
    )

    # Attempt to escalate to update
    result = guarded.execute_tool(
        "update_document",
        {"doc_id": "doc-8", "content": "attacker content"},
        tenant_id="tenant-A",
    )

    assert not result.authorized
    assert not result.executed
    assert result.decision == "no_approval"

    # Store must be unmodified
    rec = store.read("doc-8", "tenant-A")
    assert rec.content == "content"
    assert rec.version == 1


# ---------------------------------------------------------------------------
# T9 — DENY: revoked approval (RevocationList blocks before EAT issuance)
# ---------------------------------------------------------------------------

def test_t9_revoked_approval_denied():
    """
    Approval is registered, then the approval_id is added to the RevocationList
    before the tool call. The ConditionI orchestrator checks revocation during
    orchestration; the gateway also checks immediately before EAT issuance.
    Either check blocks execution.
    """
    rev = RevocationList()
    guarded, store, registry = _make_harness("t9", current_time=_NOW,
                                             revocation_list=rev)
    store.seed("doc-9", "tenant-A", "revoked target")

    entry = registry.register(
        tool_name="read_document",
        action_type="document:read",
        resource_id="tenant-A/doc-9",
        tenant_id="tenant-A",
        approver_email="alice@example.com",
    )

    # Revoke the approval_id before the call
    rev.revoke(approval_id=entry.approval_id, tenant_id="tenant-A",
               reason="revoked_for_t9_test")

    result = guarded.execute_tool(
        "read_document", {"doc_id": "doc-9"}, tenant_id="tenant-A",
    )

    assert not result.authorized
    assert not result.executed
    # Decision is deny (from policy layer) or no_approval (depends on
    # whether DVOScenarioState returns approval_active=False)
    assert result.decision in {"deny", "no_approval", "indeterminate"}

    # Store content is unchanged
    rec = store.read("doc-9", "tenant-A")
    assert rec.content == "revoked target"


# ---------------------------------------------------------------------------
# T10 — DENY: EAT expired (token max_age exceeded)
# ---------------------------------------------------------------------------

def test_t10_expired_eat_denied():
    """
    Gate: If the ExecutionTokenAuthority's max_age_ns is very short (1 ns),
    any token is expired by the time execute() verifies it.

    We test this by patching the token authority's max_age_ns after
    construction (the gateway installs a fresh authority into the tools).
    This confirms that EAT expiry independently blocks execution even
    when all other checks pass.
    """
    guarded, store, registry = _make_harness("t10", current_time=_NOW)
    store.seed("doc-10", "tenant-A", "auth but expired")

    registry.register(
        tool_name="read_document",
        action_type="document:read",
        resource_id="tenant-A/doc-10",
        tenant_id="tenant-A",
        approver_email="alice@example.com",
    )

    # Patch: make the authority issue tokens with 1 ns max_age.
    # _max_age_ns controls the max_age_ns field placed on each issued token.
    # verify_for_execution → is_expired() checks time.time_ns() - issued_at_ns > max_age_ns.
    authority = guarded.sandboxed_tools._token_authority
    if hasattr(authority, "_max_age_ns"):  # noqa: SIM102
        original_max_age = authority._max_age_ns
        authority._max_age_ns = 1  # 1 nanosecond — always expired by verify time
        try:
            result = guarded.execute_tool(
                "read_document", {"doc_id": "doc-10"}, tenant_id="tenant-A",
            )
        finally:
            authority._max_age_ns = original_max_age  # restore

        # Either the authority rejects the expired token (SandboxedDocumentTools
        # calls verify_for_execution which checks is_expired) → not executed,
        # or the gateway returned ALLOW but the tools rejected the token.
        # In either case the store must be unmodified and execution must not happen.
        assert not result.executed
        rec = store.read("doc-10", "tenant-A")
        assert rec.content == "auth but expired"
    else:
        pytest.skip("ExecutionTokenAuthority does not expose max_age_ns for patching")


# ---------------------------------------------------------------------------
# S1: Action-type downgrade attack via direct gateway call (HIGH)
# ---------------------------------------------------------------------------

def test_s1_action_type_downgrade_blocked_by_gateway():
    """
    FINDING-S1 (HIGH): TOOL_CAPABILITY_MAP previously excluded document tools,
    allowing delete_document to be called with action_type='document:read'.
    The gateway's step-2 capability check would skip the enforcement (None lookup),
    and the read policy would authorize the deletion.

    After fix: document tools are in TOOL_CAPABILITY_MAP. The gateway now rejects
    the downgraded action_type at step 2, returning capability_mismatch.

    Regression test: calling ToolGateway.request() directly with the wrong
    action_type must be blocked and must NOT delete the document.
    """
    import sys as _sys
    _sys.path.insert(0, str(Path(__file__).parent.parent.parent / "agent-verification"))
    from tool_gateway import ToolGateway, ToolRequest
    from replay_protection import ReplayRegistry
    from revocation_list import RevocationList
    from sandboxed_tools import DVOScenarioState
    from aigov_sdk_adapter import SandboxedDocumentTools

    tmp = tempfile.NamedTemporaryFile(suffix="s1.sqlite", delete=False)
    tmp.close()
    store_s1 = DocumentStore(tmp.name)
    store_s1.seed("secret", "tenant-A", "sensitive content")

    sandboxed_s1 = SandboxedDocumentTools(store_s1)

    policy_for_s1 = [
        make_policy_record(
            policy_id="S1-READ", version=1, tenant_id="tenant-A",
            authorized_principals=["alice@example.com"],
            allowed_action_types=["document:read"],
            allowed_resource_patterns=["tenant-A/*"],
            valid_from=_VALID_FROM, valid_until=_VALID_UNTIL,
        ),
        make_policy_record(
            policy_id="S1-DELETE", version=1, tenant_id="tenant-A",
            authorized_principals=["alice@example.com"],
            allowed_action_types=["document:delete"],
            allowed_resource_patterns=["tenant-A/*"],
            valid_from=_VALID_FROM, valid_until=_VALID_UNTIL,
        ),
    ]
    gw_s1 = ToolGateway(
        policy_provider=TrustedPolicyProvider(policy_for_s1),
        tools=sandboxed_s1,
        replay_registry=ReplayRegistry(),
        revocation_list=RevocationList(),
        current_time=_NOW,
    )

    # Attack: delete_document with downgraded action_type="document:read"
    req = ToolRequest(
        tool_name="delete_document",
        arguments={"doc_id": "secret"},
        proposal_id="prop-attack",
        approval_id="appr-attack",
        record_id="rec-attack",
        action_type="document:read",        # DOWNGRADED — should be document:delete
        resource_id="tenant-A/secret",
        tenant_id="tenant-A",
        dvo_state=DVOScenarioState(
            proposal_id="prop-attack",
            approval_id="appr-attack",
            record_id="rec-attack",
            approver_email="alice@example.com",
            audit_found=True,
            audit_hash_verified=True,
            audit_executed_value=None,
            approval_active=True,
            approval_matches_proposal=True,
            external_state_value="approved",
        ),
        model_verdict=True,
    )
    result = gw_s1.request(req)

    # After fix: gateway's TOOL_CAPABILITY_MAP knows delete_document requires
    # document:delete and rejects the mismatched document:read.
    assert not result.executed, (
        f"CRITICAL: delete executed under document:read policy! "
        f"decision={result.decision_record.decision}, executed={result.executed}"
    )
    assert result.capability_mismatch, "Expected capability_mismatch flag"
    # Document must be unmodified
    assert store_s1.read("secret", "tenant-A") is not None, \
        "Document was deleted — action_type downgrade attack succeeded!"
    assert store_s1.read("secret", "tenant-A").content == "sensitive content"


def test_s2_action_type_mismatch_blocked_in_execute():
    """
    FINDING-S2 (MEDIUM): SandboxedDocumentTools had TOOL_ACTION_TYPES defined
    but not enforced in execute(). After fix, execute() checks that
    expected_action_type matches the tool's required type. This provides
    defense-in-depth even if the gateway's capability map check is bypassed.
    """
    from aigov_sdk_adapter import SandboxedDocumentTools
    from execution_token import ExecutionTokenAuthority

    tmp = tempfile.NamedTemporaryFile(suffix="s2.sqlite", delete=False)
    tmp.close()
    store_s2 = DocumentStore(tmp.name)
    store_s2.seed("classified", "tenant-A", "classified data")

    sdt = SandboxedDocumentTools(store_s2)
    authority = ExecutionTokenAuthority()
    sdt._token_authority = authority

    # Issue a valid token for delete_document with the WRONG action_type
    # (simulating what the gateway would issue if the capability check were bypassed)
    exec_id = str(uuid.uuid4())
    args = {"doc_id": "classified"}
    from sandboxed_tools import compute_args_binding_hash
    binding_hash = compute_args_binding_hash(
        tool_name="delete_document",
        arguments=args,
        action_type="document:read",        # wrong
        resource_id="tenant-A/classified",
    )
    token = authority.issue(
        execution_id=exec_id,
        tool_name="delete_document",
        args_binding_hash=binding_hash,
        action_type="document:read",        # wrong action_type
        resource_id="tenant-A/classified",
        tenant_id="tenant-A",
    )

    result = sdt.execute(
        tool_name="delete_document",
        arguments=args,
        execution_id=exec_id,
        tenant_id="tenant-A",
        args_binding_hash=binding_hash,
        execution_token=token,
        expected_action_type="document:read",   # propagated wrong type
        expected_resource_id="tenant-A/classified",
    )

    # Defense-in-depth: execute() rejects the action_type mismatch
    assert not result["success"], "Delete should be blocked by action_type mismatch check"
    assert "action_type_mismatch" in result.get("blocked_reason", ""), \
        f"Expected action_type_mismatch in {result}"
    # Document must be unmodified
    assert store_s2.read("classified", "tenant-A") is not None
    assert store_s2.read("classified", "tenant-A").content == "classified data"


def test_s3_direct_execute_no_token_blocked():
    """
    Fail-closed: calling SandboxedDocumentTools.execute() directly without a
    token (bypassing the gateway entirely) must not execute any side effect.
    """
    from aigov_sdk_adapter import SandboxedDocumentTools

    tmp = tempfile.NamedTemporaryFile(suffix="s3.sqlite", delete=False)
    tmp.close()
    store_s3 = DocumentStore(tmp.name)
    store_s3.seed("bypass-target", "tenant-A", "content")

    sdt = SandboxedDocumentTools(store_s3)
    # No _token_authority installed, no token passed
    result = sdt.execute(
        tool_name="delete_document",
        arguments={"doc_id": "bypass-target"},
        execution_id="fake-exec",
        tenant_id="tenant-A",
        args_binding_hash="fake-hash",
        execution_token=None,
    )

    assert not result["success"]
    assert "no_execution_token" in result.get("blocked_reason", "")
    assert store_s3.read("bypass-target", "tenant-A") is not None


def test_s4_audit_persistence_across_restart():
    """
    After process restart (simulated by opening a new DocumentStore against
    the same SQLite file), soft-deleted documents remain visible in the full
    audit view. The in-process execution_history is NOT durable — a new store
    has an empty history — but the persisted soft-delete row confirms the
    operation occurred.
    """
    guarded, store, registry = _make_harness("s4-restart", current_time=_NOW)
    db_path = store._db_path
    store.seed("audit-doc", "tenant-A", "content")

    registry.register("delete_document", "document:delete",
                       "tenant-A/audit-doc", "tenant-A", "alice@example.com")
    result = guarded.execute_tool("delete_document", {"doc_id": "audit-doc"}, "tenant-A")
    assert result.authorized

    # Simulate restart: open a fresh DocumentStore against the same file
    fresh_store = DocumentStore(db_path)
    # Live query: document is gone
    assert fresh_store.read("audit-doc", "tenant-A") is None
    # Audit view: soft-delete row is present
    all_recs = fresh_store.all_records("tenant-A")
    deleted_rows = [r for r in all_recs if r.doc_id == "audit-doc" and r.deleted]
    assert len(deleted_rows) == 1, "Soft-delete row must persist across store restart"


def test_s5_malformed_sdk_args_handled():
    """
    If the OpenAI Agents SDK provides malformed JSON as args_json to
    on_invoke_tool, the invoke functions must return a structured JSON error
    string rather than raising an unhandled JSONDecodeError.
    """
    import asyncio
    guarded, store, registry = _make_harness("s5-json", current_time=_NOW)

    try:
        from aigov_sdk_adapter import make_sdk_tools
        tools = make_sdk_tools(guarded, "tenant-A")
    except ImportError:
        pytest.skip("openai-agents not installed")

    # Find the read_document tool
    read_tool = next(t for t in tools if t.name == "read_document")

    async def _run():
        # Pass malformed JSON — should return a structured error, not raise
        return await read_tool.on_invoke_tool(None, "{not valid json}")

    response_str = asyncio.run(_run())
    import json
    resp = json.loads(response_str)
    assert resp["authorized"] is False
    assert resp["decision"] == "deny"
    assert "malformed_args" in resp.get("block_reason", "")


# ---------------------------------------------------------------------------
# Integration smoke: resource_id derivation helper
# ---------------------------------------------------------------------------

def test_resource_id_derivation():
    assert _resource_id_from_args("read_document", {"doc_id": "x"}, "t") == "t/x"
    assert _resource_id_from_args("update_document", {"doc_id": "y", "content": "c"}, "t") == "t/y"
    assert _resource_id_from_args("delete_document", {"doc_id": "z"}, "t") == "t/z"
    # Fallback key
    assert _resource_id_from_args("read_document", {"document_id": "q"}, "t") == "t/q"


# ---------------------------------------------------------------------------
# Integration smoke: unknown tool is denied immediately
# ---------------------------------------------------------------------------

def test_unknown_tool_denied():
    guarded, store, registry = _make_harness("unk", current_time=_NOW)
    result = guarded.execute_tool("rm_production_database", {}, "tenant-A")
    assert not result.authorized
    assert result.block_reason.startswith("unknown_tool")
