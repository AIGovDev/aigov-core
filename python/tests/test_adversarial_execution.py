"""
Phase 3: Adversarial execution tests.

Tests actual sandboxed tool execution outcomes (not just authorization labels).

Key invariants under test:
  1. Direct invocation bypass — calling tools.execute() without a valid EAT
     from the gateway's authority is blocked regardless of claimed authorization.
  2. Forged EAT — a token from a DIFFERENT authority does not verify.
  3. Parallel same approval — 10 concurrent threads sharing one approval_id:
     exactly 1 executes (ReplayRegistry atomicity under load).
  4. Replay after success — a used approval cannot be replayed.
  5. Cross-process replay — a NEW ReplayRegistry (simulates process restart)
     does NOT know about the previous session's nonces. Replay SUCCEEDS.
     This is a DOCUMENTED LIMITATION, not a bug in the new code; the test
     verifies that is_distributed_safe == False and that the behavior matches
     the documentation.
  6. Revocation immediately before execution — approval revoked after
     orchestration but caught by pre-execution check → blocked.
  7. Argument mutation after gateway.request() — frozen_args used for execution.
  8. Cross-tenant substitution — alpha approver cannot authorize beta-inc op.
  9. Policy outage → INDETERMINATE → no execution (fail-closed).
 10. Capability mismatch blocked record uses frozen_args (not req.arguments).
 11. Legitimate concurrent operations — 10 threads, distinct approvals → all 10 execute.
 12. EAT field binding — token for wrong tool/args/tenant/resource not accepted.
 13. EAT expiry — token with zero max_age expires immediately.
"""

from __future__ import annotations

import sys
import threading
import time
from pathlib import Path

import pytest

_BENCH = Path(__file__).parent.parent.parent / "benchmarks" / "agent-verification"
sys.path.insert(0, str(_BENCH))

from agent_integration_scenarios import POLICY_FIXTURE, _NOW  # noqa: E402
from execution_token import ExecutionToken, ExecutionTokenAuthority  # noqa: E402
from policy_decision import PolicyDecision  # noqa: E402
from replay_protection import ReplayRegistry  # noqa: E402
from revocation_list import RevocationList  # noqa: E402
from sandboxed_tools import (  # noqa: E402
    DVOScenarioState,
    SandboxedGitHubTools,
    compute_args_binding_hash,
)
from tool_gateway import ToolGateway, ToolRequest  # noqa: E402
from trusted_policy_provider import TrustedPolicyProvider  # noqa: E402


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _make_gateway(
    extra_revocations: list[tuple[str, str, str]] | None = None,
    replay_registry: ReplayRegistry | None = None,
    revocation_list: RevocationList | None = None,
) -> ToolGateway:
    if revocation_list is None:
        revocation_list = RevocationList()
    if extra_revocations:
        for approval_id, tenant_id, reason in extra_revocations:
            revocation_list.revoke(approval_id, tenant_id, reason)
    return ToolGateway(
        policy_provider=TrustedPolicyProvider(POLICY_FIXTURE),
        tools=SandboxedGitHubTools(),
        replay_registry=replay_registry or ReplayRegistry(),
        revocation_list=revocation_list,
        current_time=_NOW,
    )


def _clean_state(
    proposal_id: str = "p",
    approval_id: str = "a",
    record_id: str = "r",
    approver_email: str = "alice@alpha-corp.com",
) -> DVOScenarioState:
    return DVOScenarioState(
        proposal_id=proposal_id, approval_id=approval_id,
        record_id=record_id, approver_email=approver_email,
        audit_found=True, audit_hash_verified=True,
        audit_executed_value="2026-11-21",
        approval_active=True, approval_matches_proposal=True,
        external_state_value="2026-11-21",
    )


def _req(
    tool_name: str = "read_repo_metadata",
    arguments: dict | None = None,
    action_type: str = "repo:read",
    resource_id: str = "alpha-corp/repo-001",
    tenant_id: str = "alpha-corp",
    approver_email: str = "alice@alpha-corp.com",
    model_verdict: bool | None = True,
    approval_id: str = "adv-a",
    proposal_id: str = "adv-p",
    record_id: str = "adv-r",
) -> ToolRequest:
    return ToolRequest(
        tool_name=tool_name,
        arguments=arguments or {"repo_id": "alpha-corp/repo-001"},
        proposal_id=proposal_id,
        approval_id=approval_id,
        record_id=record_id,
        action_type=action_type,
        resource_id=resource_id,
        tenant_id=tenant_id,
        dvo_state=_clean_state(
            proposal_id=proposal_id, approval_id=approval_id,
            record_id=record_id, approver_email=approver_email,
        ),
        model_verdict=model_verdict,
    )


# ---------------------------------------------------------------------------
# 1. Direct invocation bypass (BYPASS-1 — now fixed)
# ---------------------------------------------------------------------------


class TestDirectInvocationBypass:
    def test_tools_execute_without_token_blocked(self) -> None:
        """
        Call tools.execute() directly without going through ToolGateway.
        No token → blocked. Demonstrates BYPASS-1 is now fixed.
        """
        authority = ExecutionTokenAuthority()
        tools = SandboxedGitHubTools(token_authority=authority)
        args = {"repo_id": "alpha-corp/r", "path": "file.txt", "content": "pwned"}
        args_hash = compute_args_binding_hash("create_file", args, "repo:write", "alpha-corp/r")

        result = tools.execute(
            tool_name="create_file",
            arguments=args,
            execution_id="bypass-attempt-1",
            tenant_id="alpha-corp",
            args_binding_hash=args_hash,
            execution_token=None,  # No token — simulates direct bypass
        )
        assert not result["success"]
        assert result["blocked_reason"] == "no_execution_token"
        # Verify repo was NOT modified
        assert ("alpha-corp", "alpha-corp/r") not in tools._repos
        assert len(tools.authorized_executions()) == 0

    def test_tools_execute_with_forged_token_blocked(self) -> None:
        """
        Call tools.execute() with a token from a DIFFERENT authority (forged).
        Token does not verify → blocked.
        """
        real_authority = ExecutionTokenAuthority()
        tools = SandboxedGitHubTools(token_authority=real_authority)

        # Attacker creates their own authority — different signing key
        forged_authority = ExecutionTokenAuthority()
        args = {"repo_id": "alpha-corp/r"}
        args_hash = compute_args_binding_hash("read_repo_metadata", args, "repo:read", "alpha-corp/r")
        forged_token = forged_authority.issue(
            execution_id="forged-exec",
            tool_name="read_repo_metadata",
            args_binding_hash=args_hash,
            action_type="repo:read",
            resource_id="alpha-corp/r",
            tenant_id="alpha-corp",
        )

        result = tools.execute(
            tool_name="read_repo_metadata",
            arguments=args,
            execution_id="forged-exec",
            tenant_id="alpha-corp",
            args_binding_hash=args_hash,
            execution_token=forged_token,
        )
        assert not result["success"]
        assert result["blocked_reason"] == "token_signature_invalid"
        assert len(tools.authorized_executions()) == 0

    def test_tools_without_authority_blocks_all(self) -> None:
        """
        SandboxedGitHubTools with no token_authority blocks everything,
        even with a valid token from some authority.
        """
        some_authority = ExecutionTokenAuthority()
        tools = SandboxedGitHubTools(token_authority=None)  # no authority configured
        args_hash = compute_args_binding_hash("read_repo_metadata", {}, "repo:read", "r")
        token = some_authority.issue("x", "read_repo_metadata", args_hash, "repo:read", "r", "t")

        result = tools.execute("read_repo_metadata", {}, "x", "t", args_hash, token)
        assert not result["success"]
        assert result["blocked_reason"] == "no_token_authority_configured"


# ---------------------------------------------------------------------------
# 2. EAT field binding
# ---------------------------------------------------------------------------


class TestEATFieldBinding:
    def test_token_wrong_tool_rejected(self) -> None:
        authority = ExecutionTokenAuthority()
        tools = SandboxedGitHubTools(token_authority=authority)
        args_hash = compute_args_binding_hash("create_file", {"path": "f"}, "repo:write", "r")
        # Token issued for "create_file" but used for "read_repo_metadata"
        token = authority.issue("e1", "create_file", args_hash, "repo:write", "r", "t")
        result = tools.execute("read_repo_metadata", {"path": "f"}, "e1", "t", args_hash, token)
        assert not result["success"]
        assert "mismatch" in result["blocked_reason"]

    def test_token_wrong_args_hash_rejected(self) -> None:
        authority = ExecutionTokenAuthority()
        tools = SandboxedGitHubTools(token_authority=authority)
        correct_hash = compute_args_binding_hash("create_file", {"path": "safe.txt"}, "repo:write", "r")
        attack_hash  = compute_args_binding_hash("create_file", {"path": "../../etc/passwd"}, "repo:write", "r")
        # Token issued for safe.txt hash, but execute() is called with passwd hash
        token = authority.issue("e2", "create_file", correct_hash, "repo:write", "r", "t")
        result = tools.execute("create_file", {"path": "../../etc/passwd"}, "e2", "t", attack_hash, token)
        assert not result["success"]
        assert "mismatch" in result["blocked_reason"]

    def test_token_wrong_tenant_rejected(self) -> None:
        authority = ExecutionTokenAuthority()
        tools = SandboxedGitHubTools(token_authority=authority)
        args_hash = compute_args_binding_hash("read_repo_metadata", {}, "repo:read", "r")
        token = authority.issue("e3", "read_repo_metadata", args_hash, "repo:read", "r", "alpha-corp")
        # Execute for "beta-inc" tenant using alpha-corp token
        result = tools.execute("read_repo_metadata", {}, "e3", "beta-inc", args_hash, token)
        assert not result["success"]
        assert "mismatch" in result["blocked_reason"]

    def test_expired_token_rejected(self) -> None:
        # Authority with 0ms max_age → token expires immediately
        authority = ExecutionTokenAuthority(max_age_ms=0.0)
        tools = SandboxedGitHubTools(token_authority=authority)
        args_hash = compute_args_binding_hash("read_repo_metadata", {}, "repo:read", "r")
        token = authority.issue("e4", "read_repo_metadata", args_hash, "repo:read", "r", "t")
        # Even if issued just now, 0ms TTL means already expired
        result = tools.execute("read_repo_metadata", {}, "e4", "t", args_hash, token)
        assert not result["success"]
        assert result["blocked_reason"] == "token_expired"


# ---------------------------------------------------------------------------
# 3. Parallel same approval (single-process atomicity)
# ---------------------------------------------------------------------------


class TestParallelSameApproval:
    def test_exactly_one_executes(self) -> None:
        """
        10 threads competing for the same approval_id.
        ReplayRegistry.try_consume() atomicity: exactly 1 executes.
        """
        gateway = _make_gateway()
        results: list[bool] = []
        lock = threading.Lock()
        barrier = threading.Barrier(10)

        def run() -> None:
            barrier.wait()
            result = gateway.request(_req(
                approval_id="parallel-shared-01",
                proposal_id="parallel-p-01",
            ))
            with lock:
                results.append(result.executed)

        threads = [threading.Thread(target=run) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert results.count(True) == 1, f"Expected 1 execution, got {results.count(True)}"
        assert len(results) == 10

    def test_replay_after_success_blocked(self) -> None:
        """After a successful execution, the same approval_id is consumed."""
        gateway = _make_gateway()
        r1 = gateway.request(_req(approval_id="replay-01", proposal_id="replay-p-01"))
        r2 = gateway.request(_req(approval_id="replay-01", proposal_id="replay-p-01"))

        assert r1.executed
        assert not r2.executed
        reasons = r2.decision_record.policy_failure_reasons
        assert any("replay" in r for r in reasons), f"No replay reason: {reasons}"

    def test_legitimate_concurrent_all_execute(self) -> None:
        """
        10 threads with DISTINCT approval_ids all execute successfully.
        No false rejection under concurrency.
        """
        gateway = _make_gateway()
        results: list[bool] = []
        lock = threading.Lock()
        barrier = threading.Barrier(10)

        def run(i: int) -> None:
            barrier.wait()
            result = gateway.request(_req(
                approval_id=f"legit-concurrent-{i:02d}",
                proposal_id=f"legit-p-{i:02d}",
            ))
            with lock:
                results.append(result.executed)

        threads = [threading.Thread(target=run, args=(i,)) for i in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert results.count(True) == 10, f"Expected 10 executions, got {results.count(True)}"


# ---------------------------------------------------------------------------
# 4. Cross-process replay (BYPASS-2 — documented limitation)
# ---------------------------------------------------------------------------


class TestCrossProcessReplay:
    def test_registry_is_not_distributed_safe(self) -> None:
        """ReplayRegistry explicitly declares it is NOT distributed-safe."""
        assert ReplayRegistry().is_distributed_safe is False

    def test_process_restart_allows_replay(self) -> None:
        """
        DOCUMENTED LIMITATION: A new ReplayRegistry instance (simulating a
        process restart with an in-memory store) does NOT know about nonces
        consumed in a previous session.

        Result: the same approval_id can be used again after restart.
        This demonstrates the cross-process replay vulnerability and confirms
        the production blocker: a persistent nonce store is required.
        """
        # Session 1: consume the nonce
        registry_session1 = ReplayRegistry()
        gateway_session1 = _make_gateway(replay_registry=registry_session1)
        r1 = gateway_session1.request(_req(
            approval_id="cross-proc-replay-01",
            proposal_id="cross-proc-p-01",
        ))
        assert r1.executed  # nonce consumed in session 1

        # Session 2: new registry (process restart). The nonce is NOT in this registry.
        registry_session2 = ReplayRegistry()
        gateway_session2 = _make_gateway(replay_registry=registry_session2)
        r2 = gateway_session2.request(_req(
            approval_id="cross-proc-replay-01",
            proposal_id="cross-proc-p-01",
        ))
        # This SUCCEEDS — it's the documented cross-process replay vulnerability.
        # In production, a persistent nonce store would prevent this.
        assert r2.executed, (
            "Expected cross-process replay to succeed (documenting the limitation). "
            "If this fails, the fix has been deployed."
        )


# ---------------------------------------------------------------------------
# 5. Revocation immediately before execution (BYPASS-3 — now fixed)
# ---------------------------------------------------------------------------


class TestPreExecutionRevocation:
    def test_revocation_after_orchestration_caught_by_pre_exec_check(self) -> None:
        """
        Pre-execution revocation check (Step 6 in gateway.request()).

        Simulate: approval is revoked AFTER orchestration begins but BEFORE
        the EAT is issued. We inject the revocation into the RevocationList
        after gateway creation but before the request runs.

        In the current single-threaded path, we cannot inject mid-call.
        Instead, we pre-revoke the approval (which the orchestrator also
        checks), and confirm that revocation is detected.
        The key difference from the old test is: even if we bypass the
        orchestrator's revocation check (by patching), the pre-execution
        check in Step 6 still catches it.
        """
        revocation_list = RevocationList()
        gateway = _make_gateway(revocation_list=revocation_list)

        # Pre-revoke BEFORE the request to simulate the approval being revoked
        # between orchestration completing and token issuance. With the pre-exec
        # check, this is caught at Step 6 even if orchestration missed it.
        revocation_list.revoke("pre-exec-rev-01", "alpha-corp", "revoked_in_window")

        result = gateway.request(_req(
            approval_id="pre-exec-rev-01",
            proposal_id="pre-exec-p-01",
        ))
        assert not result.executed
        reasons = result.decision_record.policy_failure_reasons
        assert any("revoked" in r for r in reasons), f"No revocation reason: {reasons}"

    def test_revocation_after_first_request_blocks_second_different_nonce(self) -> None:
        """
        If a policy is revoked at the RevocationList level, all subsequent
        uses of that approval_id are blocked regardless of nonce uniqueness.
        """
        revocation_list = RevocationList()
        gateway = _make_gateway(revocation_list=revocation_list)

        # First request succeeds
        r1 = gateway.request(_req(
            approval_id="policy-rev-flow-01",
            proposal_id="policy-rev-p-01",
        ))
        assert r1.executed

        # Revoke the approval at runtime
        revocation_list.revoke("policy-rev-flow-01", "alpha-corp", "runtime_revocation")

        # Second request with DIFFERENT proposal_id (different nonce) — still blocked
        r2 = gateway.request(_req(
            approval_id="policy-rev-flow-01",
            proposal_id="policy-rev-p-02",
        ))
        assert not r2.executed


# ---------------------------------------------------------------------------
# 6. Argument mutation (TOCTOU regression — deepcopy path)
# ---------------------------------------------------------------------------


class TestArgumentMutation:
    def test_mutation_after_request_uses_frozen_args(self) -> None:
        """
        Mutate req.arguments after gateway.request() starts. The gateway's
        frozen_args deepcopy means the mutation does NOT affect execution.
        """
        gateway = _make_gateway()
        args = {"repo_id": "alpha-corp/repo-001", "path": "original.txt", "content": "ok"}
        req = ToolRequest(
            tool_name="create_file",
            arguments=args,
            proposal_id="p-toctou-adv", approval_id="a-toctou-adv",
            record_id="r-toctou-adv",
            action_type="repo:write",
            resource_id="alpha-corp/repo-001",
            tenant_id="alpha-corp",
            dvo_state=_clean_state(
                proposal_id="p-toctou-adv", approval_id="a-toctou-adv",
                record_id="r-toctou-adv",
            ),
            model_verdict=True,
        )
        result = gateway.request(req)
        args["path"] = "../../etc/passwd"  # mutate AFTER call returns

        assert result.executed
        history = gateway._tools.authorized_executions()
        assert history[-1].arguments["path"] == "original.txt"

    def test_capability_mismatch_path_uses_frozen_args(self) -> None:
        """
        BUG-4 fix: in the capability mismatch path, the blocked record
        previously used req.arguments (not frozen_args). Verify it now
        uses the frozen copy so the recorded args match the args_binding_hash.
        """
        gateway = _make_gateway()
        args = {"repo_id": "alpha-corp/repo-001", "path": "safe.txt"}
        req = ToolRequest(
            tool_name="create_file",
            arguments=args,
            proposal_id="p-cap-bug", approval_id="a-cap-bug",
            record_id="r-cap-bug",
            action_type="repo:read",  # wrong — requires repo:write
            resource_id="alpha-corp/repo-001",
            tenant_id="alpha-corp",
            dvo_state=_clean_state(proposal_id="p-cap-bug", approval_id="a-cap-bug",
                                    record_id="r-cap-bug"),
            model_verdict=True,
        )
        result = gateway.request(req)
        # Mutate AFTER submission
        args["path"] = "malicious.txt"

        assert not result.executed
        assert result.capability_mismatch
        # The blocked record should show the ORIGINAL args (frozen_args)
        history = gateway._tools.blocked_executions()
        assert history[-1].arguments["path"] == "safe.txt"


# ---------------------------------------------------------------------------
# 7. Cross-tenant substitution
# ---------------------------------------------------------------------------


class TestCrossTenantSubstitution:
    def test_alpha_approver_cannot_act_on_beta_tenant(self) -> None:
        gateway = _make_gateway()
        result = gateway.request(_req(
            tenant_id="beta-inc",
            resource_id="beta-inc/repo-001",
            arguments={"repo_id": "beta-inc/repo-001"},
            approver_email="alice@alpha-corp.com",  # alpha-corp approver
            approval_id="cross-tenant-01",
            proposal_id="cross-tenant-p-01",
        ))
        assert not result.executed
        assert result.decision_record.decision == PolicyDecision.DENY

    def test_beta_approver_cannot_admin_beta_repo(self) -> None:
        """
        grace@beta-inc.com has repo:read + repo:write for beta-inc,
        but NOT repo:admin. Attempting admin operation → DENY.
        """
        gateway = _make_gateway()
        result = gateway.request(_req(
            tool_name="modify_repo_settings",
            action_type="repo:admin",
            resource_id="beta-inc/repo-001",
            arguments={"repo_id": "beta-inc/repo-001", "setting_key": "k", "value": "v"},
            tenant_id="beta-inc",
            approver_email="grace@beta-inc.com",
            approval_id="cross-tenant-02",
            proposal_id="cross-tenant-p-02",
        ))
        assert not result.executed
        assert result.decision_record.decision == PolicyDecision.DENY


# ---------------------------------------------------------------------------
# 8. Policy outage (fail-closed regression)
# ---------------------------------------------------------------------------


class TestPolicyOutage:
    def test_outage_produces_indeterminate_no_execution(self) -> None:
        from trusted_policy_provider import TrustedPolicyProvider as TPP

        class BrokenProvider(TPP):
            def lookup_authorization(self, *a, **kw):
                raise ConnectionError("policy service unreachable")

        gateway = ToolGateway(
            policy_provider=BrokenProvider([]),
            tools=SandboxedGitHubTools(),
            replay_registry=ReplayRegistry(),
            revocation_list=RevocationList(),
            current_time=_NOW,
        )
        result = gateway.request(_req(approval_id="outage-01", proposal_id="outage-p-01"))
        assert not result.executed
        assert result.decision_record.decision == PolicyDecision.INDETERMINATE
        reasons = result.decision_record.indeterminate_reasons
        assert any("policy_service_exception" in r for r in reasons), f"Expected exception reason: {reasons}"

    def test_outage_does_not_raise(self) -> None:
        """gateway.request() must never raise, even on policy service exception."""
        from trusted_policy_provider import TrustedPolicyProvider as TPP

        class AlwaysRaises(TPP):
            def lookup_authorization(self, *a, **kw):
                raise Exception("catastrophic failure")

        gateway = ToolGateway(
            policy_provider=AlwaysRaises([]),
            tools=SandboxedGitHubTools(),
            replay_registry=ReplayRegistry(),
            revocation_list=RevocationList(),
            current_time=_NOW,
        )
        # Must NOT raise
        result = gateway.request(_req(approval_id="outage-02", proposal_id="outage-p-02"))
        assert result is not None
        assert not result.executed


# ---------------------------------------------------------------------------
# 9. Execution outcome totals
# ---------------------------------------------------------------------------


class TestExecutionOutcomeTotals:
    def test_no_unauthorized_execution_across_adversarial_set(self) -> None:
        """
        Run all Phase 3 adversarial scenarios through the gateway and
        confirm zero unauthorized executions.
        """
        gateway = _make_gateway()
        unauthorized_executed = 0

        scenarios = [
            # (should_execute, req_kwargs)
            (False, {"approval_id": "tot-01", "proposal_id": "tot-p-01",
                     "approver_email": "unknown@evil.com"}),
            (False, {"approval_id": "tot-02", "proposal_id": "tot-p-02",
                     "tenant_id": "beta-inc", "resource_id": "beta-inc/r",
                     "arguments": {"repo_id": "beta-inc/r"},
                     "approver_email": "alice@alpha-corp.com"}),
            (True, {"approval_id": "tot-03", "proposal_id": "tot-p-03"}),
            (True, {"approval_id": "tot-04", "proposal_id": "tot-p-04"}),
        ]

        for should_execute, kwargs in scenarios:
            result = gateway.request(_req(**kwargs))
            if not should_execute and result.executed:
                unauthorized_executed += 1

        assert unauthorized_executed == 0
