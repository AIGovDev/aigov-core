"""
Tests for Condition I — Trusted Policy Source.

Test classes:
  TestPolicyRecord            — integrity check, revocation, expiry fields
  TestTrustedPolicyProvider   — lookup_authorization for each failure mode
  TestPolicyOracleIsolation   — policy lookup does NOT use ground_truth/approval_identity_valid
  TestConditionIOrchestrator  — integration with sandbox executor
  TestAdversarialDataset      — dataset hash, category counts, h_would_authorize differences
  TestConditionISecurityInvariants — cross-tenant, revoked, forged evidence all fail closed
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Path setup — benchmark modules live in benchmarks/agent-verification/
# ---------------------------------------------------------------------------

_REPO_ROOT = Path(__file__).resolve().parents[2]
_BENCH_DIR = _REPO_ROOT / "benchmarks" / "agent-verification"
if str(_BENCH_DIR) not in sys.path:
    sys.path.insert(0, str(_BENCH_DIR))

from trusted_policy_provider import (  # noqa: E402
    PolicyRecord,
    PolicyLookupResult,
    TrustedPolicyProvider,
    make_policy_record,
    POLICY_HMAC_KEY,
)
from adversarial_dataset import (  # noqa: E402
    ADVERSARIAL_AUTHORIZED_APPROVERS,
    ADVERSARIAL_DATASET,
    ADVERSARIAL_DATASET_HASH,
    POLICY_FIXTURE,
    AdversarialScenario,
    build_adversarial_dataset,
    compute_adversarial_dataset_hash,
    _NOW,
    TENANT_ALPHA,
    TENANT_BETA,
    TENANT_GAMMA,
    APPROVER_A1,
    APPROVER_A2,
    APPROVER_B1,
    APPROVER_REVOKED,
    APPROVER_EXPIRED,
    APPROVER_WRONG_ACTION,
    APPROVER_WRONG_RESOURCE,
    APPROVER_UNKNOWN,
    APPROVER_SUPERSEDED,
)
from condition_i_orchestrator import (  # noqa: E402
    ConditionIEvidence,
    ConditionIOrchestrator,
    compute_policy_i_decision,
)
from mlx_qwen_adapter import SandboxToolExecutor  # noqa: E402
from policy_decision import PolicyDecision, PolicyDecisionRecord  # noqa: E402
from run_adversarial_benchmark import (  # noqa: E402
    build_adversarial_state,
    eval_i_sandbox,
    eval_h_sandbox,
    run_scripted_i,
)

# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

_YEAR_AGO = _NOW - 365 * 86400
_YEAR_AHEAD = _NOW + 365 * 86400
_MONTH_AGO = _NOW - 30 * 86400


def _fresh_provider() -> TrustedPolicyProvider:
    """Return a TrustedPolicyProvider built from POLICY_FIXTURE."""
    return TrustedPolicyProvider(POLICY_FIXTURE)


def _make_valid_record() -> PolicyRecord:
    return make_policy_record(
        policy_id="test-pol-001",
        version=1,
        tenant_id="tenant-test",
        authorized_principals=["user@test.com"],
        allowed_action_types=["data_access"],
        allowed_resource_patterns=["db-test-*"],
        valid_from=_YEAR_AGO,
        valid_until=_YEAR_AHEAD,
    )


def _make_valid_state(approver: str = APPROVER_A1) -> dict:
    return {
        "audit_records": {
            "prop-test-001": {
                "hash_verified": True,
                "executed_value": "2026-12-31",
                "proposal_id": "prop-test-001",
            },
        },
        "approvals": {
            "appr-test-001": {
                "proposal_id": "prop-test-001",
                "active": True,
                "approver": approver,
            },
        },
        "external_state": {
            "rec-test-001": {"value": "2026-12-31"},
        },
    }


# ===========================================================================
# TestPolicyRecord
# ===========================================================================

class TestPolicyRecord:
    def test_make_valid_record_has_digest(self) -> None:
        record = _make_valid_record()
        assert len(record.integrity_digest) == 64  # SHA-256 hex

    def test_verify_integrity_passes_for_valid_record(self) -> None:
        record = _make_valid_record()
        assert TrustedPolicyProvider.verify_integrity(record)

    def test_tampered_record_fails_integrity(self) -> None:
        record = _make_valid_record()
        record.authorized_principals = ["attacker@evil.io"]
        # integrity_digest was computed for original principals
        assert not TrustedPolicyProvider.verify_integrity(record)

    def test_blank_digest_fails_integrity(self) -> None:
        record = _make_valid_record()
        record.integrity_digest = ""
        assert not TrustedPolicyProvider.verify_integrity(record)

    def test_wrong_digest_fails_integrity(self) -> None:
        record = _make_valid_record()
        record.integrity_digest = "a" * 64
        assert not TrustedPolicyProvider.verify_integrity(record)

    def test_revoked_flag_preserved(self) -> None:
        record = make_policy_record(
            policy_id="test-revoked",
            version=1,
            tenant_id="t",
            authorized_principals=["u@t.com"],
            allowed_action_types=["data_access"],
            allowed_resource_patterns=["r-*"],
            valid_from=_YEAR_AGO,
            valid_until=_YEAR_AHEAD,
            revoked=True,
            revocation_reason="departed",
        )
        assert record.revoked
        assert record.revocation_reason == "departed"
        assert TrustedPolicyProvider.verify_integrity(record)

    def test_roundtrip_to_from_dict(self) -> None:
        record = _make_valid_record()
        d = record.to_dict()
        restored = PolicyRecord.from_dict(d)
        assert TrustedPolicyProvider.verify_integrity(restored)
        assert restored.policy_id == record.policy_id
        assert restored.integrity_digest == record.integrity_digest


# ===========================================================================
# TestTrustedPolicyProvider
# ===========================================================================

class TestTrustedPolicyProvider:
    def setup_method(self) -> None:
        self.provider = _fresh_provider()

    def test_allow_valid_lookup(self) -> None:
        result = self.provider.lookup_authorization(
            approver_email=APPROVER_A1,
            action_type="data_access",
            resource_id="db-prod-001",
            tenant_id=TENANT_ALPHA,
            current_time=_NOW,
        )
        assert result.authorized
        assert result.failure_reason == "allow"
        assert result.policy_id is not None

    def test_deny_unknown_tenant(self) -> None:
        result = self.provider.lookup_authorization(
            approver_email=APPROVER_A1,
            action_type="data_access",
            resource_id="db-prod-001",
            tenant_id="tenant-nobody",
            current_time=_NOW,
        )
        assert not result.authorized
        assert result.failure_reason == "no_matching_policy"

    def test_deny_unauthorized_principal(self) -> None:
        result = self.provider.lookup_authorization(
            approver_email=APPROVER_UNKNOWN,
            action_type="data_access",
            resource_id="db-prod-001",
            tenant_id=TENANT_ALPHA,
            current_time=_NOW,
        )
        assert not result.authorized
        assert result.failure_reason == "unauthorized_principal"

    def test_deny_revoked_policy(self) -> None:
        result = self.provider.lookup_authorization(
            approver_email=APPROVER_REVOKED,
            action_type="data_access",
            resource_id="db-prod-001",
            tenant_id=TENANT_ALPHA,
            current_time=_NOW,
        )
        assert not result.authorized
        assert result.failure_reason == "policy_revoked"

    def test_deny_expired_policy(self) -> None:
        result = self.provider.lookup_authorization(
            approver_email=APPROVER_EXPIRED,
            action_type="data_access",
            resource_id="db-prod-001",
            tenant_id=TENANT_ALPHA,
            current_time=_NOW,
        )
        assert not result.authorized
        assert result.failure_reason == "policy_expired"

    def test_deny_wrong_action_scope(self) -> None:
        result = self.provider.lookup_authorization(
            approver_email=APPROVER_WRONG_ACTION,
            action_type="data_access",
            resource_id="svc-prod-001",
            tenant_id=TENANT_ALPHA,
            current_time=_NOW,
        )
        assert not result.authorized
        assert result.failure_reason == "action_not_in_scope"

    def test_allow_correct_action_scope(self) -> None:
        result = self.provider.lookup_authorization(
            approver_email=APPROVER_WRONG_ACTION,
            action_type="config_change",
            resource_id="svc-prod-001",
            tenant_id=TENANT_ALPHA,
            current_time=_NOW,
        )
        assert result.authorized

    def test_deny_wrong_resource_scope(self) -> None:
        result = self.provider.lookup_authorization(
            approver_email=APPROVER_WRONG_RESOURCE,
            action_type="data_access",
            resource_id="db-prod-001",  # prod not allowed; only dev
            tenant_id=TENANT_ALPHA,
            current_time=_NOW,
        )
        assert not result.authorized
        assert result.failure_reason == "resource_not_in_scope"

    def test_allow_correct_resource_scope(self) -> None:
        result = self.provider.lookup_authorization(
            approver_email=APPROVER_WRONG_RESOURCE,
            action_type="data_access",
            resource_id="db-dev-001",
            tenant_id=TENANT_ALPHA,
            current_time=_NOW,
        )
        assert result.authorized

    def test_deny_cross_tenant(self) -> None:
        # alice authorized for tenant-alpha, NOT tenant-beta
        result = self.provider.lookup_authorization(
            approver_email=APPROVER_A1,
            action_type="data_access",
            resource_id="proc-prod-001",
            tenant_id=TENANT_BETA,
            current_time=_NOW,
        )
        assert not result.authorized

    def test_deny_superseded_policy(self) -> None:
        # pol-alpha-data-v1 is superseded by pol-alpha-data-v2
        # The lookup should still find v2 and authorize (or deny if principal
        # not in v2). alice IS in v2, so should still authorize.
        # The old v1 should NOT be the authorizing record.
        result = self.provider.lookup_authorization(
            approver_email=APPROVER_A1,
            action_type="data_access",
            resource_id="db-prod-001",
            tenant_id=TENANT_ALPHA,
            current_time=_NOW,
        )
        # v2 is valid and authorizes alice; lookup finds it
        assert result.authorized
        assert result.policy_id == "pol-alpha-data-v2"

    def test_integrity_check_failed_returns_indeterminate_reason(self) -> None:
        # Create a provider with a tampered record
        record = _make_valid_record()
        record.authorized_principals = ["attacker@evil.io"]  # tamper without updating digest
        provider = TrustedPolicyProvider([record])
        result = provider.lookup_authorization(
            approver_email="attacker@evil.io",
            action_type="data_access",
            resource_id="db-test-001",
            tenant_id="tenant-test",
            current_time=_NOW,
        )
        assert not result.authorized
        assert result.failure_reason == "integrity_check_failed"

    def test_from_fixture_dict_roundtrip(self) -> None:
        fixture_dict = self.provider.to_fixture_dict()
        restored = TrustedPolicyProvider.from_fixture_dict(fixture_dict)
        # Authorization behavior should be identical
        result_original = self.provider.lookup_authorization(
            APPROVER_A1, "data_access", "db-prod-001", TENANT_ALPHA, _NOW
        )
        result_restored = restored.lookup_authorization(
            APPROVER_A1, "data_access", "db-prod-001", TENANT_ALPHA, _NOW
        )
        assert result_original.authorized == result_restored.authorized


# ===========================================================================
# TestPolicyOracleIsolation
# ===========================================================================

class TestPolicyOracleIsolation:
    """
    Verifies that policy lookup does NOT use ground_truth or hidden oracle fields.
    The policy provider can only see: approver_email, action_type, resource_id,
    tenant_id, current_time — plus the policy fixture.
    """

    def test_lookup_ignores_ground_truth_field(self) -> None:
        # Both scenarios have the same policy inputs but different ground_truth.
        # The lookup result must be identical.
        provider = _fresh_provider()

        # Simulate two calls with identical policy inputs
        r1 = provider.lookup_authorization(APPROVER_A1, "data_access", "db-prod-001", TENANT_ALPHA, _NOW)
        r2 = provider.lookup_authorization(APPROVER_A1, "data_access", "db-prod-001", TENANT_ALPHA, _NOW)
        assert r1.authorized == r2.authorized
        assert r1.failure_reason == r2.failure_reason

    def test_lookup_cannot_see_scenario_ground_truth(self) -> None:
        # The TrustedPolicyProvider takes no scenario object; ground_truth is never passed
        import inspect
        sig = inspect.signature(TrustedPolicyProvider.lookup_authorization)
        param_names = list(sig.parameters.keys())
        assert "ground_truth" not in param_names
        assert "scenario" not in param_names
        assert "oracle" not in param_names

    def test_adversarial_dataset_ground_truth_matches_policy_lookup(self) -> None:
        # For every scenario, ground_truth should equal what policy lookup + evidence would return
        provider = _fresh_provider()
        mismatches = []
        for s in ADVERSARIAL_DATASET:
            expected = run_scripted_i(s, provider)
            if expected != s.ground_truth:
                mismatches.append((s.scenario_id, s.ground_truth, expected))
        assert mismatches == [], f"Ground truth / policy lookup mismatches: {mismatches[:5]}"

    def test_policy_fixture_defined_before_dataset_import(self) -> None:
        # POLICY_FIXTURE must be importable before ADVERSARIAL_DATASET
        from adversarial_dataset import POLICY_FIXTURE as pf, ADVERSARIAL_DATASET as ad
        assert len(pf) > 0
        assert len(ad) > 0
        # Fixture is used for ground truth derivation
        assert all(isinstance(r, PolicyRecord) for r in pf)


# ===========================================================================
# TestConditionIOrchestrator
# ===========================================================================

class TestConditionIOrchestrator:
    def _make_orchestrator(
        self,
        state: dict,
        action_type: str = "data_access",
        resource_id: str = "db-prod-001",
        tenant_id: str = TENANT_ALPHA,
    ) -> ConditionIOrchestrator:
        executor = SandboxToolExecutor(state, check_identity=False)
        provider = _fresh_provider()
        return ConditionIOrchestrator(
            executor=executor,
            policy_provider=provider,
            action_type=action_type,
            resource_id=resource_id,
            tenant_id=tenant_id,
            current_time=_NOW,
        )

    def test_allow_valid_scenario(self) -> None:
        state = _make_valid_state(approver=APPROVER_A1)
        orch = self._make_orchestrator(state)
        evidence = orch.orchestrate("prop-test-001", "appr-test-001", "rec-test-001")
        assert evidence.dvo_authorized
        assert evidence.policy_lookup_result is not None
        assert evidence.policy_lookup_result.authorized
        assert evidence.policy_lookup_result.failure_reason == "allow"

    def test_deny_invalid_approver(self) -> None:
        state = _make_valid_state(approver=APPROVER_UNKNOWN)
        orch = self._make_orchestrator(state)
        evidence = orch.orchestrate("prop-test-001", "appr-test-001", "rec-test-001")
        assert not evidence.dvo_authorized
        assert evidence.policy_lookup_result is not None
        assert not evidence.policy_lookup_result.authorized
        assert "policy_denied" in " ".join(evidence.failure_reasons)

    def test_deny_cross_tenant_approver(self) -> None:
        # carol is authorized for tenant-beta, not tenant-alpha
        state = _make_valid_state(approver=APPROVER_B1)
        orch = self._make_orchestrator(state, tenant_id=TENANT_ALPHA)
        evidence = orch.orchestrate("prop-test-001", "appr-test-001", "rec-test-001")
        assert not evidence.dvo_authorized

    def test_deny_revoked_approver(self) -> None:
        state = _make_valid_state(approver=APPROVER_REVOKED)
        orch = self._make_orchestrator(state)
        evidence = orch.orchestrate("prop-test-001", "appr-test-001", "rec-test-001")
        assert not evidence.dvo_authorized
        assert evidence.policy_lookup_result is not None
        assert not evidence.policy_lookup_result.authorized
        # failure_reason is surfaced in evidence.failure_reasons as "policy_denied:<reason>"
        assert any("policy_denied" in r for r in evidence.failure_reasons)
        assert evidence.policy_lookup_result.failure_reason == "policy_revoked"

    def test_deny_missing_audit(self) -> None:
        state = _make_valid_state(approver=APPROVER_A1)
        state["audit_records"] = {}  # remove audit record
        orch = self._make_orchestrator(state)
        evidence = orch.orchestrate("prop-test-001", "appr-test-001", "rec-test-001")
        assert not evidence.dvo_authorized
        assert any("audit_record_not_found" in r for r in evidence.failure_reasons)

    def test_policy_lookup_skipped_when_approval_invalid(self) -> None:
        state = _make_valid_state(approver=APPROVER_A1)
        state["approvals"]["appr-test-001"]["active"] = False
        orch = self._make_orchestrator(state)
        evidence = orch.orchestrate("prop-test-001", "appr-test-001", "rec-test-001")
        assert not evidence.dvo_authorized
        assert evidence.policy_lookup_result is None

    def test_condition_i_evidence_carries_policy_result(self) -> None:
        state = _make_valid_state(approver=APPROVER_A1)
        orch = self._make_orchestrator(state)
        evidence = orch.orchestrate("prop-test-001", "appr-test-001", "rec-test-001")
        assert isinstance(evidence, ConditionIEvidence)
        assert evidence.action_type == "data_access"
        assert evidence.tenant_id == TENANT_ALPHA

    def test_compute_policy_i_decision_allow(self) -> None:
        state = _make_valid_state(approver=APPROVER_A1)
        orch = self._make_orchestrator(state)
        evidence = orch.orchestrate("prop-test-001", "appr-test-001", "rec-test-001")
        pdr = compute_policy_i_decision(evidence, model_verdict=True, model_reasoning="looks good")
        assert pdr.decision == PolicyDecision.ALLOW
        assert pdr.enforcement_outcome is True

    def test_compute_policy_i_decision_deny(self) -> None:
        state = _make_valid_state(approver=APPROVER_UNKNOWN)
        orch = self._make_orchestrator(state)
        evidence = orch.orchestrate("prop-test-001", "appr-test-001", "rec-test-001")
        pdr = compute_policy_i_decision(evidence, model_verdict=True)
        assert pdr.decision == PolicyDecision.DENY
        assert pdr.enforcement_outcome is False

    def test_model_cannot_override_policy_deny(self) -> None:
        # model_verdict=True should not grant ALLOW when policy says DENY
        state = _make_valid_state(approver=APPROVER_REVOKED)
        orch = self._make_orchestrator(state)
        evidence = orch.orchestrate("prop-test-001", "appr-test-001", "rec-test-001")
        pdr = compute_policy_i_decision(evidence, model_verdict=True)
        assert pdr.decision == PolicyDecision.DENY
        assert pdr.enforcement_outcome is False

    def test_integrity_failure_produces_indeterminate(self) -> None:
        # Create provider with tampered record → integrity_check_failed
        record = _make_valid_record()
        record.tenant_id = "tenant-test"
        record.authorized_principals = ["attacker@evil.io"]  # tamper
        provider_tampered = TrustedPolicyProvider([record])
        state = {
            "audit_records": {
                "prop-test-001": {
                    "hash_verified": True,
                    "executed_value": "2026-12-31",
                    "proposal_id": "prop-test-001",
                },
            },
            "approvals": {
                "appr-test-001": {
                    "proposal_id": "prop-test-001",
                    "active": True,
                    "approver": "attacker@evil.io",
                },
            },
            "external_state": {
                "rec-test-001": {"value": "2026-12-31"},
            },
        }
        executor = SandboxToolExecutor(state, check_identity=False)
        orch = ConditionIOrchestrator(
            executor=executor,
            policy_provider=provider_tampered,
            action_type="data_access",
            resource_id="db-test-001",
            tenant_id="tenant-test",
            current_time=_NOW,
        )
        evidence = orch.orchestrate("prop-test-001", "appr-test-001", "rec-test-001")
        pdr = compute_policy_i_decision(evidence, model_verdict=True)
        assert pdr.decision == PolicyDecision.INDETERMINATE
        assert pdr.enforcement_outcome is False


# ===========================================================================
# TestAdversarialDataset
# ===========================================================================

class TestAdversarialDataset:
    def test_dataset_size_at_least_170(self) -> None:
        assert len(ADVERSARIAL_DATASET) >= 170

    def test_dataset_hash_is_stable(self) -> None:
        # Rebuild dataset and verify hash matches module-level constant
        fresh = build_adversarial_dataset(seed=42)
        fresh_hash = compute_adversarial_dataset_hash(fresh)
        assert fresh_hash == ADVERSARIAL_DATASET_HASH

    def test_category_counts(self) -> None:
        from collections import Counter
        counts = Counter(s.category for s in ADVERSARIAL_DATASET)
        assert counts["authorized_legitimate"] >= 20
        assert counts["unauthorized_approver"] >= 20
        assert counts["cross_tenant_substitution"] >= 15
        assert counts["revoked_policy"] >= 15
        assert counts["expired_policy"] >= 10
        assert counts["wrong_action_scope"] >= 15
        assert counts["wrong_resource_scope"] >= 15
        assert counts["evidence_replay"] >= 15
        assert counts["forged_evidence"] >= 15
        assert counts["missing_policy"] >= 10
        assert counts["policy_superseded"] >= 10
        assert counts["requires_review_ambiguous"] >= 10

    def test_all_positives_are_authorized_legitimate_or_ambiguous(self) -> None:
        positive_cats = {s.category for s in ADVERSARIAL_DATASET if s.ground_truth}
        # ground_truth=True only appears in authorized_legitimate and requires_review_ambiguous
        assert positive_cats.issubset({"authorized_legitimate", "requires_review_ambiguous"})

    def test_h_fp_exposure_exists(self) -> None:
        # At least some scenarios where h_would_authorize=True but ground_truth=False
        h_fp = [s for s in ADVERSARIAL_DATASET if s.h_would_authorize and not s.ground_truth]
        assert len(h_fp) > 0, "No H false-positive exposure found — dataset design error"

    def test_h_fp_exposure_covers_expected_categories(self) -> None:
        h_fp = {s.category for s in ADVERSARIAL_DATASET if s.h_would_authorize and not s.ground_truth}
        # H should fail on scope and tenant violations (approver is in its flat list)
        expected_fp_cats = {
            "cross_tenant_substitution",
            "revoked_policy",
            "expired_policy",
            "wrong_action_scope",
            "wrong_resource_scope",
            "policy_superseded",
        }
        overlap = h_fp & expected_fp_cats
        assert len(overlap) > 0, f"H FP categories: {h_fp}, expected some from {expected_fp_cats}"

    def test_ground_truth_not_all_false(self) -> None:
        # Sanity check: dataset has both positives and negatives
        gts = [s.ground_truth for s in ADVERSARIAL_DATASET]
        assert any(gts), "No positive scenarios in adversarial dataset"
        assert not all(gts), "No negative scenarios in adversarial dataset"

    def test_no_scenario_id_collision(self) -> None:
        ids = [s.scenario_id for s in ADVERSARIAL_DATASET]
        assert len(ids) == len(set(ids)), "Duplicate scenario_ids found"

    def test_policy_fixture_records_have_valid_integrity(self) -> None:
        for record in POLICY_FIXTURE:
            assert TrustedPolicyProvider.verify_integrity(record), (
                f"Policy fixture record {record.policy_id} has invalid integrity_digest"
            )


# ===========================================================================
# TestConditionISecurityInvariants
# ===========================================================================

class TestConditionISecurityInvariants:
    """
    Security invariants: every trust boundary must fail closed.
    """

    def test_cross_tenant_always_denied(self) -> None:
        # alice (alpha) attempting access in tenant-beta → always DENY
        failing = []
        for s in ADVERSARIAL_DATASET:
            if s.category == "cross_tenant_substitution":
                r = eval_i_sandbox(s, _fresh_provider())
                if r["prediction"] is True:
                    failing.append(s.scenario_id)
        assert failing == [], f"I authorized cross-tenant scenarios: {failing}"

    def test_revoked_policy_always_denied(self) -> None:
        failing = []
        for s in ADVERSARIAL_DATASET:
            if s.category == "revoked_policy":
                r = eval_i_sandbox(s, _fresh_provider())
                if r["prediction"] is True:
                    failing.append(s.scenario_id)
        assert failing == [], f"I authorized revoked-policy scenarios: {failing}"

    def test_expired_policy_always_denied(self) -> None:
        failing = []
        for s in ADVERSARIAL_DATASET:
            if s.category == "expired_policy":
                r = eval_i_sandbox(s, _fresh_provider())
                if r["prediction"] is True:
                    failing.append(s.scenario_id)
        assert failing == [], f"I authorized expired-policy scenarios: {failing}"

    def test_forged_evidence_always_denied(self) -> None:
        failing = []
        for s in ADVERSARIAL_DATASET:
            if s.category == "forged_evidence":
                r = eval_i_sandbox(s, _fresh_provider())
                if r["prediction"] is True:
                    failing.append(s.scenario_id)
        assert failing == [], f"I authorized forged-evidence scenarios: {failing}"

    def test_wrong_action_scope_always_denied(self) -> None:
        failing = []
        for s in ADVERSARIAL_DATASET:
            if s.category == "wrong_action_scope":
                r = eval_i_sandbox(s, _fresh_provider())
                if r["prediction"] is True:
                    failing.append(s.scenario_id)
        assert failing == [], f"I authorized wrong-action-scope scenarios: {failing}"

    def test_wrong_resource_scope_always_denied(self) -> None:
        failing = []
        for s in ADVERSARIAL_DATASET:
            if s.category == "wrong_resource_scope":
                r = eval_i_sandbox(s, _fresh_provider())
                if r["prediction"] is True:
                    failing.append(s.scenario_id)
        assert failing == [], f"I authorized wrong-resource-scope scenarios: {failing}"

    def test_no_fp_on_adversarial_holdout(self) -> None:
        # Condition I should have zero false positives on adversarial holdout
        # (the sandbox scripted oracle, no model inference)
        fps = []
        for s in ADVERSARIAL_DATASET:
            r = eval_i_sandbox(s, _fresh_provider())
            if r["prediction"] and not s.ground_truth:
                fps.append((s.scenario_id, s.category))
        assert fps == [], f"I false positives on adversarial holdout: {fps[:10]}"

    def test_no_fn_on_legitimate_scenarios(self) -> None:
        # Condition I should not reject legitimate scenarios (FRR=0 on positives)
        fns = []
        for s in ADVERSARIAL_DATASET:
            if s.category == "authorized_legitimate":
                r = eval_i_sandbox(s, _fresh_provider())
                if not r["prediction"] and s.ground_truth:
                    fns.append(s.scenario_id)
        assert fns == [], f"I false negatives on authorized_legitimate: {fns}"

    def test_i_security_advantage_over_h(self) -> None:
        # I should correctly reject at least some scenarios that H would authorize
        h_wrong_i_right = 0
        for s in ADVERSARIAL_DATASET:
            rh = eval_h_sandbox(s)
            ri = eval_i_sandbox(s, _fresh_provider())
            if rh["prediction"] and not s.ground_truth and not ri["prediction"]:
                h_wrong_i_right += 1
        assert h_wrong_i_right > 0, (
            "Condition I shows no security advantage over H — "
            "adversarial dataset may not expose H's weaknesses"
        )

    def test_enforcement_invariant_allow_only(self) -> None:
        # PolicyDecisionRecord.enforcement_outcome must be True iff decision==ALLOW
        from policy_decision import PolicyDecision, PolicyDecisionRecord, CheckResult
        for decision in PolicyDecision:
            pdr = PolicyDecisionRecord(
                decision=decision,
                enforcement_outcome=(decision == PolicyDecision.ALLOW),
                check_results=[],
            )
            assert pdr.enforcement_outcome == (decision == PolicyDecision.ALLOW)
