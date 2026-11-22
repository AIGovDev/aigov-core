"""
Unit tests for agent-tool integration: ToolGateway security invariants.

Test classes:
  TestToolCapabilityMap        — gateway enforces tool → action_type mapping (5 tests)
  TestToolGatewayLegitimate    — legitimate authorized operations execute (4 tests)
  TestToolGatewayDeny          — unauthorized operations are blocked (8 tests)
  TestReplayProtection         — replay protection in gateway context (4 tests)
  TestConcurrentExecution      — thread-safety under concurrent requests (3 tests)
  TestSecurityRegressions      — regressions for two red-team findings (4 tests)
  TestSandboxedTools           — SandboxedGitHubTools tracking invariants (4 tests)
  TestArgBindingHash           — determinism and sensitivity of binding hash (4 tests)
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
from execution_token import ExecutionTokenAuthority  # noqa: E402
from policy_decision import PolicyDecision  # noqa: E402
from replay_protection import ApprovalNonce, ReplayRegistry  # noqa: E402
from revocation_list import RevocationList  # noqa: E402
from sandboxed_tools import (  # noqa: E402
    DVOScenarioState,
    SandboxedGitHubTools,
    compute_args_binding_hash,
)
from tool_gateway import TOOL_CAPABILITY_MAP, ToolGateway, ToolRequest  # noqa: E402
from trusted_policy_provider import TrustedPolicyProvider  # noqa: E402


# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------


def _make_gateway(
    extra_revocations: list[tuple[str, str, str]] | None = None
) -> ToolGateway:
    revocation_list = RevocationList()
    if extra_revocations:
        for approval_id, tenant_id, reason in extra_revocations:
            revocation_list.revoke(approval_id, tenant_id, reason)
    return ToolGateway(
        policy_provider=TrustedPolicyProvider(POLICY_FIXTURE),
        tools=SandboxedGitHubTools(),
        replay_registry=ReplayRegistry(),
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
        proposal_id=proposal_id,
        approval_id=approval_id,
        record_id=record_id,
        approver_email=approver_email,
        audit_found=True,
        audit_hash_verified=True,
        audit_executed_value="2026-11-21",
        approval_active=True,
        approval_matches_proposal=True,
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
    approval_id: str = "a",
    proposal_id: str = "p",
) -> ToolRequest:
    return ToolRequest(
        tool_name=tool_name,
        arguments=arguments or {"repo_id": "alpha-corp/repo-001"},
        proposal_id=proposal_id,
        approval_id=approval_id,
        record_id="r",
        action_type=action_type,
        resource_id=resource_id,
        tenant_id=tenant_id,
        dvo_state=_clean_state(
            proposal_id=proposal_id,
            approval_id=approval_id,
            approver_email=approver_email,
        ),
        model_verdict=model_verdict,
    )


# ---------------------------------------------------------------------------
# TestToolCapabilityMap
# ---------------------------------------------------------------------------


class TestToolCapabilityMap:
    def test_all_tools_in_map(self) -> None:
        for tool in SandboxedGitHubTools.SUPPORTED_TOOLS:
            assert tool in TOOL_CAPABILITY_MAP, f"{tool} missing from capability map"

    def test_create_file_requires_write(self) -> None:
        assert TOOL_CAPABILITY_MAP["create_file"] == "repo:write"

    def test_modify_settings_requires_admin(self) -> None:
        assert TOOL_CAPABILITY_MAP["modify_repo_settings"] == "repo:admin"

    def test_deployment_requires_deploy_production(self) -> None:
        assert TOOL_CAPABILITY_MAP["request_deployment"] == "deploy:production"

    def test_gateway_rejects_mismatched_capability(self) -> None:
        gateway = _make_gateway()
        # create_file requires repo:write; claim repo:read → gateway deny
        result = gateway.request(_req(
            tool_name="create_file",
            action_type="repo:read",  # wrong
            arguments={"repo_id": "alpha-corp/repo-001", "path": "x.txt"},
        ))
        assert not result.executed
        assert result.decision_record.decision == PolicyDecision.DENY
        assert result.capability_mismatch


# ---------------------------------------------------------------------------
# TestToolGatewayLegitimate
# ---------------------------------------------------------------------------


class TestToolGatewayLegitimate:
    def test_alice_reads_repo(self) -> None:
        gateway = _make_gateway()
        result = gateway.request(_req(
            tool_name="read_repo_metadata",
            action_type="repo:read",
            approver_email="alice@alpha-corp.com",
        ))
        assert result.executed
        assert result.decision_record.decision == PolicyDecision.ALLOW

    def test_alice_creates_file(self) -> None:
        gateway = _make_gateway()
        result = gateway.request(_req(
            tool_name="create_file",
            arguments={"repo_id": "alpha-corp/repo-001", "path": "x.txt"},
            action_type="repo:write",
            approver_email="alice@alpha-corp.com",
        ))
        assert result.executed
        assert result.decision_record.decision == PolicyDecision.ALLOW

    def test_carol_modifies_settings(self) -> None:
        gateway = _make_gateway()
        result = gateway.request(_req(
            tool_name="modify_repo_settings",
            arguments={"repo_id": "alpha-corp/repo-001", "setting_key": "k", "value": "v"},
            action_type="repo:admin",
            approver_email="carol@alpha-corp.com",
        ))
        assert result.executed
        assert result.decision_record.decision == PolicyDecision.ALLOW

    def test_frank_deploys_to_production(self) -> None:
        gateway = _make_gateway()
        result = gateway.request(_req(
            tool_name="request_deployment",
            arguments={"repo_id": "alpha-corp/repo-001", "environment": "production"},
            action_type="deploy:production",
            approver_email="frank@alpha-corp.com",
        ))
        assert result.executed
        assert result.decision_record.decision == PolicyDecision.ALLOW


# ---------------------------------------------------------------------------
# TestToolGatewayDeny
# ---------------------------------------------------------------------------


class TestToolGatewayDeny:
    def test_no_policy_for_approver(self) -> None:
        gateway = _make_gateway()
        result = gateway.request(_req(approver_email="unknown@evil.com"))
        assert not result.executed
        assert result.decision_record.decision == PolicyDecision.DENY

    def test_bob_cannot_write(self) -> None:
        gateway = _make_gateway()
        result = gateway.request(_req(
            tool_name="create_file",
            arguments={"repo_id": "alpha-corp/repo-public", "path": "x.txt"},
            action_type="repo:write",
            resource_id="alpha-corp/repo-public",
            approver_email="bob@alpha-corp.com",
        ))
        assert not result.executed
        assert result.decision_record.decision == PolicyDecision.DENY

    def test_cross_tenant_blocked(self) -> None:
        gateway = _make_gateway()
        result = gateway.request(_req(
            tenant_id="beta-inc",
            resource_id="beta-inc/repo-001",
            arguments={"repo_id": "beta-inc/repo-001"},
            approver_email="alice@alpha-corp.com",  # alpha-corp approver
        ))
        assert not result.executed
        assert result.decision_record.decision == PolicyDecision.DENY

    def test_revoked_policy_blocked(self) -> None:
        gateway = _make_gateway()
        result = gateway.request(_req(
            tool_name="request_deployment",
            arguments={"repo_id": "alpha-corp/repo-001", "environment": "production"},
            action_type="deploy:production",
            approver_email="alice@alpha-corp.com",  # alice's production policy is revoked
        ))
        assert not result.executed
        assert result.decision_record.decision == PolicyDecision.DENY

    def test_expired_policy_blocked(self) -> None:
        gateway = _make_gateway()
        result = gateway.request(_req(
            tool_name="create_file",
            arguments={"repo_id": "alpha-corp/repo-001", "path": "x.txt"},
            action_type="repo:write",
            approver_email="eve@alpha-corp.com",  # expired policy
        ))
        assert not result.executed
        assert result.decision_record.decision == PolicyDecision.DENY

    def test_audit_hash_failed_blocked(self) -> None:
        gateway = _make_gateway()
        req = ToolRequest(
            tool_name="read_repo_metadata",
            arguments={"repo_id": "alpha-corp/repo-001"},
            proposal_id="p", approval_id="a", record_id="r",
            action_type="repo:read",
            resource_id="alpha-corp/repo-001",
            tenant_id="alpha-corp",
            dvo_state=DVOScenarioState(
                proposal_id="p", approval_id="a", record_id="r",
                approver_email="alice@alpha-corp.com",
                audit_found=True,
                audit_hash_verified=False,  # hash fails
                audit_executed_value="2026-11-21",
                approval_active=True, approval_matches_proposal=True,
                external_state_value="2026-11-21",
            ),
            model_verdict=True,
        )
        result = gateway.request(req)
        assert not result.executed
        assert result.decision_record.decision == PolicyDecision.DENY

    def test_model_verdict_true_cannot_override_deny(self) -> None:
        """Security invariant: model=True alone cannot flip DENY to ALLOW."""
        gateway = _make_gateway()
        result = gateway.request(_req(
            approver_email="unknown@evil.com",
            model_verdict=True,  # model approves — must be ignored
        ))
        assert not result.executed
        assert result.decision_record.decision == PolicyDecision.DENY

    def test_model_verdict_none_gives_requires_review_not_allow(self) -> None:
        """model_verdict=None → REQUIRES_REVIEW (not ALLOW, not DENY)."""
        gateway = _make_gateway()
        result = gateway.request(_req(
            approver_email="alice@alpha-corp.com",
            model_verdict=None,  # no inference → REQUIRES_REVIEW
        ))
        assert not result.executed
        assert result.decision_record.decision == PolicyDecision.REQUIRES_REVIEW


# ---------------------------------------------------------------------------
# TestReplayProtection
# ---------------------------------------------------------------------------


class TestReplayProtection:
    def test_first_use_allowed(self) -> None:
        gateway = _make_gateway()
        result = gateway.request(_req(approval_id="unique-a1", proposal_id="unique-p1"))
        assert result.executed

    def test_second_use_blocked(self) -> None:
        gateway = _make_gateway()
        req = _req(approval_id="shared-b1", proposal_id="shared-b1-p")
        gateway.request(req)  # first use
        result2 = gateway.request(req)  # second use — same nonce context
        assert not result2.executed
        reasons = result2.decision_record.policy_failure_reasons
        assert any("replay" in r for r in reasons), f"Expected replay reason, got {reasons}"

    def test_runtime_revocation_blocks(self) -> None:
        gateway = _make_gateway(
            extra_revocations=[("revoked-appr-c1", "alpha-corp", "test revocation")]
        )
        result = gateway.request(_req(approval_id="revoked-appr-c1", proposal_id="p-c1"))
        assert not result.executed
        reasons = result.decision_record.policy_failure_reasons
        assert any("revoked" in r for r in reasons), f"Expected revocation reason, got {reasons}"

    def test_different_proposal_different_nonce(self) -> None:
        """Same approval_id but different proposal_id → different nonce → NOT replay."""
        gateway = _make_gateway()
        r1 = gateway.request(_req(approval_id="shared-d1", proposal_id="p-d1"))
        r2 = gateway.request(_req(approval_id="shared-d1", proposal_id="p-d1-other"))
        assert r1.executed
        assert r2.executed  # different nonce, not a replay


# ---------------------------------------------------------------------------
# TestConcurrentExecution
# ---------------------------------------------------------------------------


class TestConcurrentExecution:
    def test_concurrent_requests_one_wins(self) -> None:
        """10 threads with the same approval_id → exactly 1 executes."""
        gateway = _make_gateway()
        results = []
        lock = threading.Lock()
        barrier = threading.Barrier(10)

        def run() -> None:
            barrier.wait()
            result = gateway.request(_req(
                approval_id="concurrent-shared-e1",
                proposal_id="concurrent-p-e1",
            ))
            with lock:
                results.append(result)

        threads = [threading.Thread(target=run) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        executed = [r for r in results if r.executed]
        assert len(executed) == 1, f"Expected 1 execution, got {len(executed)}"
        assert len(results) == 10

    def test_concurrent_different_approvals_all_execute(self) -> None:
        """10 threads with distinct approval_ids → all 10 execute."""
        gateway = _make_gateway()
        results = []
        lock = threading.Lock()
        barrier = threading.Barrier(10)

        def run(i: int) -> None:
            barrier.wait()
            result = gateway.request(_req(
                approval_id=f"distinct-approval-f{i}",
                proposal_id=f"distinct-proposal-f{i}",
            ))
            with lock:
                results.append(result)

        threads = [threading.Thread(target=run, args=(i,)) for i in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        executed = [r for r in results if r.executed]
        assert len(executed) == 10

    def test_tools_history_counts_all_attempts(self) -> None:
        """History captures both authorized and blocked attempts."""
        gateway = _make_gateway()
        gateway.request(_req(approval_id="hist-g1", proposal_id="hist-p1"))
        gateway.request(_req(approval_id="hist-g1", proposal_id="hist-p1"))  # replay

        history = gateway._tools.execution_history()
        assert len(history) == 2
        authorized = [r for r in history if r.authorized]
        blocked = [r for r in history if not r.authorized]
        assert len(authorized) == 1
        assert len(blocked) == 1


# ---------------------------------------------------------------------------
# TestSecurityRegressions — regressions for two red-team findings
# ---------------------------------------------------------------------------


class TestSecurityRegressions:
    def test_regression_toctou_mutation_uses_frozen_args(self) -> None:
        """
        Red-team finding 1: mutable arguments dict could be mutated between
        hash computation and execution. Fix: gateway freezes a deepcopy.

        Verify: mutating req.arguments after gateway.request() starts
        does not affect what actually executes.
        """
        gateway = _make_gateway()
        args = {"repo_id": "alpha-corp/repo-001", "path": "safe.txt", "content": "ok"}
        req = ToolRequest(
            tool_name="create_file",
            arguments=args,
            proposal_id="p-toctou", approval_id="a-toctou", record_id="r-toctou",
            action_type="repo:write",
            resource_id="alpha-corp/repo-001",
            tenant_id="alpha-corp",
            dvo_state=_clean_state(
                proposal_id="p-toctou", approval_id="a-toctou", record_id="r-toctou",
            ),
            model_verdict=True,
        )
        result = gateway.request(req)
        # Mutate AFTER submission (simulate concurrent mutation)
        args["path"] = "../../etc/passwd"

        assert result.executed
        history = gateway._tools.authorized_executions()
        executed_path = history[-1].arguments.get("path")
        assert executed_path == "safe.txt", f"Mutation affected execution: got {executed_path}"

    def test_regression_policy_outage_fails_closed(self) -> None:
        """
        Red-team finding 5: uncaught exception from policy_provider could
        crash the gateway instead of failing closed. Fix: try/except returns
        INDETERMINATE → no execution.
        """
        from trusted_policy_provider import TrustedPolicyProvider as TPP

        class FaultyProvider(TPP):
            def lookup_authorization(self, *a, **kw):
                raise RuntimeError("simulated policy service outage")

        gateway = ToolGateway(
            policy_provider=FaultyProvider([]),
            tools=SandboxedGitHubTools(),
            replay_registry=ReplayRegistry(),
            revocation_list=RevocationList(),
            current_time=_NOW,
        )
        result = gateway.request(_req())
        assert not result.executed
        assert result.decision_record.decision == PolicyDecision.INDETERMINATE

    def test_regression_args_binding_hash_is_stable(self) -> None:
        """Hash over same inputs always produces the same value."""
        h1 = compute_args_binding_hash("create_file", {"repo_id": "r", "path": "p"},
                                       "repo:write", "alpha-corp/r")
        h2 = compute_args_binding_hash("create_file", {"repo_id": "r", "path": "p"},
                                       "repo:write", "alpha-corp/r")
        assert h1 == h2

    def test_regression_different_args_different_hash(self) -> None:
        """Different arguments produce different hashes."""
        h1 = compute_args_binding_hash("create_file", {"path": "a.txt"}, "repo:write", "r")
        h2 = compute_args_binding_hash("create_file", {"path": "b.txt"}, "repo:write", "r")
        assert h1 != h2


# ---------------------------------------------------------------------------
# TestSandboxedTools
# ---------------------------------------------------------------------------


class TestSandboxedTools:
    def test_no_token_blocked(self) -> None:
        """Call without token → blocked; recorded in history but no repo mutation."""
        authority = ExecutionTokenAuthority()
        tools = SandboxedGitHubTools(token_authority=authority)
        args_hash = compute_args_binding_hash("create_file", {"repo_id": "t1/r1", "path": "evil.txt"}, "repo:write", "t1/r1")
        tools.execute(
            tool_name="create_file",
            arguments={"repo_id": "t1/r1", "path": "evil.txt", "content": "pwned"},
            execution_id="x",
            tenant_id="t1",
            args_binding_hash=args_hash,
            execution_token=None,
        )
        assert len(tools.execution_history()) == 1
        assert not tools.execution_history()[0].authorized
        assert ("t1", "t1/r1") not in tools._repos

    def test_valid_token_executes(self) -> None:
        """Valid EAT from same authority → execution proceeds."""
        authority = ExecutionTokenAuthority()
        tools = SandboxedGitHubTools(token_authority=authority)
        args_hash = compute_args_binding_hash("create_file", {"repo_id": "t1/r1", "path": "good.txt"}, "repo:write", "t1/r1")
        token = authority.issue(
            execution_id="y", tool_name="create_file",
            args_binding_hash=args_hash, action_type="repo:write",
            resource_id="t1/r1", tenant_id="t1",
        )
        tools.execute(
            tool_name="create_file",
            arguments={"repo_id": "t1/r1", "path": "good.txt", "content": "ok"},
            execution_id="y",
            tenant_id="t1",
            args_binding_hash=args_hash,
            execution_token=token,
        )
        assert len(tools.authorized_executions()) == 1
        assert ("t1", "t1/r1") in tools._repos
        assert "good.txt" in tools._repos[("t1", "t1/r1")]["files"]

    def test_reset_clears_all_state(self) -> None:
        authority = ExecutionTokenAuthority()
        tools = SandboxedGitHubTools(token_authority=authority)
        args_hash = compute_args_binding_hash("create_file", {"repo_id": "r", "path": "f"}, "repo:write", "r")
        token = authority.issue("z", "create_file", args_hash, "repo:write", "r", "t")
        tools.execute("create_file", {"repo_id": "r", "path": "f"},
                      "z", "t", args_hash, token)
        tools.reset()
        assert len(tools.execution_history()) == 0
        assert len(tools._repos) == 0

    def test_all_operations_recorded(self) -> None:
        """All 5 tool types are recorded; blocked attempts count too."""
        authority = ExecutionTokenAuthority()
        tools = SandboxedGitHubTools(token_authority=authority)
        # Submit 5 blocked attempts (no tokens)
        ops = [
            ("read_repo_metadata", {"repo_id": "r"}),
            ("create_file", {"repo_id": "r", "path": "f"}),
            ("open_pull_request", {"repo_id": "r", "title": "t"}),
            ("modify_repo_settings", {"repo_id": "r", "setting_key": "k", "value": "v"}),
            ("request_deployment", {"repo_id": "r", "environment": "staging"}),
        ]
        for i, (name, args) in enumerate(ops):
            tools.execute(name, args, str(i), "tenant",
                          compute_args_binding_hash(name, args, "repo:read", "r"),
                          execution_token=None)
        assert len(tools.execution_history()) == 5


# ---------------------------------------------------------------------------
# TestArgBindingHash
# ---------------------------------------------------------------------------


class TestArgBindingHash:
    def test_hash_covers_tool_name(self) -> None:
        h1 = compute_args_binding_hash("read_repo_metadata", {}, "repo:read", "r")
        h2 = compute_args_binding_hash("create_file", {}, "repo:read", "r")
        assert h1 != h2

    def test_hash_covers_action_type(self) -> None:
        h1 = compute_args_binding_hash("create_file", {}, "repo:read", "r")
        h2 = compute_args_binding_hash("create_file", {}, "repo:write", "r")
        assert h1 != h2

    def test_hash_covers_resource_id(self) -> None:
        h1 = compute_args_binding_hash("read_repo_metadata", {}, "repo:read", "alpha/r")
        h2 = compute_args_binding_hash("read_repo_metadata", {}, "repo:read", "beta/r")
        assert h1 != h2

    def test_hash_is_16_char_hex(self) -> None:
        h = compute_args_binding_hash("t", {}, "a", "r")
        assert len(h) == 16
        assert all(c in "0123456789abcdef" for c in h)
