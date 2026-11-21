"""
Adversarial holdout dataset for Condition I evaluation.

170 scenarios across 12 categories designed to test trust boundary robustness.
Policy fixture is defined first; ground truth is derived from policy lookups,
NOT from scenario labels or hidden oracle fields.

Frozen at first build (seed=42). Hash: computed at module load and printed.

Design goals:
  - Condition H (flat-list identity check) cannot distinguish:
      * cross-tenant substitution (approver is legitimate in another tenant)
      * scope violations (approver has policy but not for this action/resource)
      * revoked/expired policies (H's list is static)
      * superseded policies
  - Condition I should catch all of these via TrustedPolicyProvider.lookup_authorization()

H's authorized approvers list (ADVERSARIAL_AUTHORIZED_APPROVERS) is a flat static
list simulating H's design. It is defined INDEPENDENTLY of the policy fixture.
Crucially, some approvers in this list are ALSO in the policy fixture for tenant A
but not for tenant B — exposing H's tenant-blindness.
"""

from __future__ import annotations

import hashlib
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path

# ---------------------------------------------------------------------------
# Shared time constants (Unix timestamps)
# ---------------------------------------------------------------------------
# Reference "now": 2026-11-21 00:00:00 UTC = 1763913600
_NOW = 1763913600.0
_YEAR_AGO = _NOW - 365 * 86400
_YEAR_AHEAD = _NOW + 365 * 86400
_MONTH_AGO = _NOW - 30 * 86400
_MONTH_AHEAD = _NOW + 30 * 86400
_WEEK_AGO = _NOW - 7 * 86400
_WEEK_AHEAD = _NOW + 7 * 86400
_DAY_AGO = _NOW - 86400
_DAY_AHEAD = _NOW + 86400

# ---------------------------------------------------------------------------
# Policy fixture (defined BEFORE scenarios)
# ---------------------------------------------------------------------------

# Import after path setup
_BENCH_DIR = Path(__file__).parent
if str(_BENCH_DIR) not in sys.path:
    sys.path.insert(0, str(_BENCH_DIR))

from trusted_policy_provider import (  # noqa: E402
    PolicyRecord,
    TrustedPolicyProvider,
    make_policy_record,
)

# --- Tenant identifiers ---
TENANT_ALPHA = "tenant-alpha"
TENANT_BETA = "tenant-beta"
TENANT_GAMMA = "tenant-gamma"

# --- Approver principals ---
APPROVER_A1 = "alice@alpha-corp.com"      # authorized for tenant-alpha
APPROVER_A2 = "bob@alpha-corp.com"        # authorized for tenant-alpha
APPROVER_B1 = "carol@beta-inc.com"        # authorized for tenant-beta
APPROVER_B2 = "dave@beta-inc.com"         # authorized for tenant-beta
APPROVER_G1 = "eve@gamma-sys.com"         # authorized for tenant-gamma
APPROVER_UNKNOWN = "mallory@evil.io"      # not authorized anywhere
APPROVER_REVOKED = "frank@alpha-corp.com"      # was authorized; policy revoked
APPROVER_EXPIRED = "grace@alpha-corp.com"      # policy expired
APPROVER_WRONG_ACTION = "henry@alpha-corp.com" # authorized for config_change only
APPROVER_WRONG_RESOURCE = "iris@alpha-corp.com" # authorized for db-dev-* only
APPROVER_SUPERSEDED = "jake@alpha-corp.com"    # was in v1 only; removed in v2 (superseded)

# ---------------------------------------------------------------------------
# H's flat authorized-approver list (simulates Condition H design)
# Intentionally includes approvers from multiple tenants to expose
# H's inability to distinguish tenant context.
# ---------------------------------------------------------------------------
ADVERSARIAL_AUTHORIZED_APPROVERS: list[str] = [
    APPROVER_A1,
    APPROVER_A2,
    APPROVER_B1,
    APPROVER_B2,
    APPROVER_G1,
    APPROVER_REVOKED,
    APPROVER_EXPIRED,
    APPROVER_WRONG_ACTION,
    APPROVER_WRONG_RESOURCE,
    APPROVER_SUPERSEDED,
]

# ---------------------------------------------------------------------------
# Policy fixture records
# ---------------------------------------------------------------------------

POLICY_FIXTURE: list[PolicyRecord] = [
    # --- tenant-alpha: data_access on db-prod-* ---
    make_policy_record(
        policy_id="pol-alpha-data-v2",
        version=2,
        tenant_id=TENANT_ALPHA,
        authorized_principals=[APPROVER_A1, APPROVER_A2],
        allowed_action_types=["data_access"],
        allowed_resource_patterns=["db-prod-*"],
        valid_from=_YEAR_AGO,
        valid_until=_YEAR_AHEAD,
    ),
    # --- tenant-alpha: config_change on svc-prod-* ---
    make_policy_record(
        policy_id="pol-alpha-config-v1",
        version=1,
        tenant_id=TENANT_ALPHA,
        authorized_principals=[APPROVER_WRONG_ACTION],
        allowed_action_types=["config_change"],
        allowed_resource_patterns=["svc-prod-*"],
        valid_from=_YEAR_AGO,
        valid_until=_YEAR_AHEAD,
    ),
    # --- tenant-alpha: data_access on db-dev-* only ---
    make_policy_record(
        policy_id="pol-alpha-dev-v1",
        version=1,
        tenant_id=TENANT_ALPHA,
        authorized_principals=[APPROVER_WRONG_RESOURCE],
        allowed_action_types=["data_access"],
        allowed_resource_patterns=["db-dev-*"],
        valid_from=_YEAR_AGO,
        valid_until=_YEAR_AHEAD,
    ),
    # --- tenant-alpha: REVOKED policy (APPROVER_REVOKED was here) ---
    make_policy_record(
        policy_id="pol-alpha-revoked-v1",
        version=1,
        tenant_id=TENANT_ALPHA,
        authorized_principals=[APPROVER_REVOKED],
        allowed_action_types=["data_access"],
        allowed_resource_patterns=["db-prod-*"],
        valid_from=_YEAR_AGO,
        valid_until=_YEAR_AHEAD,
        revoked=True,
        revocation_reason="principal_departed",
    ),
    # --- tenant-alpha: EXPIRED policy (APPROVER_EXPIRED was here) ---
    make_policy_record(
        policy_id="pol-alpha-expired-v1",
        version=1,
        tenant_id=TENANT_ALPHA,
        authorized_principals=[APPROVER_EXPIRED],
        allowed_action_types=["data_access"],
        allowed_resource_patterns=["db-prod-*"],
        valid_from=_YEAR_AGO,
        valid_until=_MONTH_AGO,  # expired
    ),
    # --- tenant-beta: data_access on proc-prod-* ---
    make_policy_record(
        policy_id="pol-beta-data-v1",
        version=1,
        tenant_id=TENANT_BETA,
        authorized_principals=[APPROVER_B1, APPROVER_B2],
        allowed_action_types=["data_access", "export"],
        allowed_resource_patterns=["proc-prod-*", "report-*"],
        valid_from=_YEAR_AGO,
        valid_until=_YEAR_AHEAD,
    ),
    # --- tenant-gamma: data_access on analytics-* ---
    make_policy_record(
        policy_id="pol-gamma-v1",
        version=1,
        tenant_id=TENANT_GAMMA,
        authorized_principals=[APPROVER_G1],
        allowed_action_types=["data_access", "config_change"],
        allowed_resource_patterns=["analytics-*"],
        valid_from=_YEAR_AGO,
        valid_until=_YEAR_AHEAD,
    ),
    # --- tenant-alpha: OLD version superseded by pol-alpha-data-v2 ---
    # APPROVER_SUPERSEDED was listed in v1 but removed when v2 was issued.
    # This makes policy_superseded scenarios meaningful: jake can't authorize
    # because his only policy (v1) is superseded and he's not in v2.
    make_policy_record(
        policy_id="pol-alpha-data-v1",
        version=1,
        tenant_id=TENANT_ALPHA,
        authorized_principals=[APPROVER_SUPERSEDED],
        allowed_action_types=["data_access"],
        allowed_resource_patterns=["db-prod-*"],
        valid_from=_YEAR_AGO,
        valid_until=_YEAR_AHEAD,
        superseded_by="pol-alpha-data-v2",
    ),
]

# Build a trusted policy provider from the fixture for ground-truth computation
_FIXTURE_PROVIDER = TrustedPolicyProvider(POLICY_FIXTURE)


# ---------------------------------------------------------------------------
# AdversarialScenario dataclass
# ---------------------------------------------------------------------------

@dataclass
class AdversarialScenario:
    scenario_id: str
    description: str
    category: str

    # Sandbox state
    proposal_id: str
    approval_id: str
    record_id: str
    action_type: str
    resource_id: str
    tenant_id: str
    approver_email: str

    # Evidence state
    audit_found: bool
    audit_hash_verified: bool
    audit_executed_value: str | None

    # Approval state
    approval_matches_proposal: bool
    approval_active: bool

    # External state
    external_matches_audit: bool

    # Policy reference
    policy_id: str | None

    # Authoritative ground truth (derived from policy + evidence)
    ground_truth: bool

    # H comparison: would Condition H's flat-list check authorize this?
    h_would_authorize: bool


def _h_would_authorize(s: "AdversarialScenario") -> bool:
    """Compute h_would_authorize from scenario fields (no ground_truth used)."""
    return (
        s.approver_email in ADVERSARIAL_AUTHORIZED_APPROVERS
        and s.audit_found
        and s.audit_hash_verified
        and s.approval_matches_proposal
        and s.approval_active
        and s.external_matches_audit
    )


def _compute_ground_truth(
    approver_email: str,
    action_type: str,
    resource_id: str,
    tenant_id: str,
    audit_found: bool,
    audit_hash_verified: bool,
    approval_matches_proposal: bool,
    approval_active: bool,
    external_matches_audit: bool,
) -> bool:
    """Derive ground truth from policy lookup + evidence checks. Never reads scenario labels."""
    # Evidence must be valid for any authorization
    if not (audit_found and audit_hash_verified and approval_matches_proposal
            and approval_active and external_matches_audit):
        return False
    result = _FIXTURE_PROVIDER.lookup_authorization(
        approver_email=approver_email,
        action_type=action_type,
        resource_id=resource_id,
        tenant_id=tenant_id,
        current_time=_NOW,
    )
    return result.authorized


# ---------------------------------------------------------------------------
# Dataset builder
# ---------------------------------------------------------------------------

def _make(
    sid: str,
    desc: str,
    category: str,
    *,
    approver: str,
    action: str,
    resource: str,
    tenant: str,
    policy_id: str | None,
    audit_found: bool = True,
    audit_hash_ok: bool = True,
    audit_value: str | None = "2026-12-31",
    approval_match: bool = True,
    approval_active: bool = True,
    ext_match: bool = True,
) -> AdversarialScenario:
    # Proposal/approval/record IDs are derived from scenario_id (no oracle)
    proposal_id = f"prop-{sid}"
    approval_id = f"appr-{sid}"
    record_id = f"rec-{sid}"

    gt = _compute_ground_truth(
        approver_email=approver,
        action_type=action,
        resource_id=resource,
        tenant_id=tenant,
        audit_found=audit_found,
        audit_hash_verified=audit_hash_ok,
        approval_matches_proposal=approval_match,
        approval_active=approval_active,
        external_matches_audit=ext_match,
    )

    s = AdversarialScenario(
        scenario_id=sid,
        description=desc,
        category=category,
        proposal_id=proposal_id,
        approval_id=approval_id,
        record_id=record_id,
        action_type=action,
        resource_id=resource,
        tenant_id=tenant,
        approver_email=approver,
        audit_found=audit_found,
        audit_hash_verified=audit_hash_ok,
        audit_executed_value=audit_value,
        approval_matches_proposal=approval_match,
        approval_active=approval_active,
        external_matches_audit=ext_match,
        policy_id=policy_id,
        ground_truth=gt,
        h_would_authorize=False,  # filled in after construction
    )
    s.h_would_authorize = _h_would_authorize(s)
    return s


def build_adversarial_dataset(seed: int = 42) -> list[AdversarialScenario]:  # noqa: ARG001
    """
    Build 170 adversarial scenarios. seed is accepted for interface compatibility
    but the dataset is fully deterministic (no random sampling).

    Ground truth is derived from TrustedPolicyProvider.lookup_authorization() on
    POLICY_FIXTURE — not from scenario labels, categories, or hidden oracle fields.
    """
    scenarios: list[AdversarialScenario] = []

    # -----------------------------------------------------------------------
    # Category 1: authorized_legitimate (20 scenarios, ground_truth=True)
    # -----------------------------------------------------------------------
    for i in range(1, 11):
        scenarios.append(_make(
            f"L{i:02d}",
            f"Legitimate data access {i}: alice on db-prod-{i:03d} in tenant-alpha",
            "authorized_legitimate",
            approver=APPROVER_A1,
            action="data_access",
            resource=f"db-prod-{i:03d}",
            tenant=TENANT_ALPHA,
            policy_id="pol-alpha-data-v2",
        ))
    for i in range(1, 6):
        scenarios.append(_make(
            f"L{10+i:02d}",
            f"Legitimate data access {10+i}: bob on db-prod-{100+i:03d} in tenant-alpha",
            "authorized_legitimate",
            approver=APPROVER_A2,
            action="data_access",
            resource=f"db-prod-{100+i:03d}",
            tenant=TENANT_ALPHA,
            policy_id="pol-alpha-data-v2",
        ))
    for i in range(1, 6):
        scenarios.append(_make(
            f"L{15+i:02d}",
            f"Legitimate data access in tenant-beta: carol on proc-prod-{i:03d}",
            "authorized_legitimate",
            approver=APPROVER_B1,
            action="data_access",
            resource=f"proc-prod-{i:03d}",
            tenant=TENANT_BETA,
            policy_id="pol-beta-data-v1",
        ))

    # -----------------------------------------------------------------------
    # Category 2: unauthorized_approver (20 scenarios, ground_truth=False)
    # 10 use APPROVER_UNKNOWN (not in H list either)
    # 10 use an approver in H list but not in policy for this tenant/action
    # -----------------------------------------------------------------------
    for i in range(1, 11):
        scenarios.append(_make(
            f"UA{i:02d}",
            f"Unauthorized approver {i}: mallory attempts data access on db-prod",
            "unauthorized_approver",
            approver=APPROVER_UNKNOWN,
            action="data_access",
            resource=f"db-prod-{i:03d}",
            tenant=TENANT_ALPHA,
            policy_id=None,
        ))
    # These 10 have h_would_authorize=True but ground_truth=False
    # (carol is in H's flat list but has no policy for tenant-alpha)
    for i in range(1, 11):
        scenarios.append(_make(
            f"UA{10+i:02d}",
            f"Cross-principal unauthorized {i}: carol (beta) attempts access in tenant-alpha",
            "unauthorized_approver",
            approver=APPROVER_B1,
            action="data_access",
            resource=f"db-prod-{i:03d}",
            tenant=TENANT_ALPHA,
            policy_id=None,
        ))

    # -----------------------------------------------------------------------
    # Category 3: cross_tenant_substitution (15 scenarios, ground_truth=False)
    # Approver authorized for tenant A but approval submitted for tenant B.
    # h_would_authorize=True for all (approver in H list).
    # -----------------------------------------------------------------------
    for i in range(1, 9):
        scenarios.append(_make(
            f"CT{i:02d}",
            f"Cross-tenant {i}: alice (alpha) attempts access in tenant-beta",
            "cross_tenant_substitution",
            approver=APPROVER_A1,
            action="data_access",
            resource=f"proc-prod-{i:03d}",
            tenant=TENANT_BETA,
            policy_id=None,
        ))
    for i in range(1, 8):
        scenarios.append(_make(
            f"CT{8+i:02d}",
            f"Cross-tenant {8+i}: carol (beta) attempts access in tenant-gamma",
            "cross_tenant_substitution",
            approver=APPROVER_B1,
            action="data_access",
            resource=f"analytics-{i:03d}",
            tenant=TENANT_GAMMA,
            policy_id=None,
        ))

    # -----------------------------------------------------------------------
    # Category 4: revoked_policy (15 scenarios, ground_truth=False)
    # Approver is in H list (APPROVER_REVOKED) but policy is revoked.
    # h_would_authorize=True for all.
    # -----------------------------------------------------------------------
    for i in range(1, 16):
        scenarios.append(_make(
            f"RV{i:02d}",
            f"Revoked policy {i}: frank attempts access with revoked authorization",
            "revoked_policy",
            approver=APPROVER_REVOKED,
            action="data_access",
            resource=f"db-prod-{i:03d}",
            tenant=TENANT_ALPHA,
            policy_id="pol-alpha-revoked-v1",
        ))

    # -----------------------------------------------------------------------
    # Category 5: expired_policy (10 scenarios, ground_truth=False)
    # Approver is in H list (APPROVER_EXPIRED) but policy expired.
    # h_would_authorize=True for all.
    # -----------------------------------------------------------------------
    for i in range(1, 11):
        scenarios.append(_make(
            f"EP{i:02d}",
            f"Expired policy {i}: grace attempts access with expired policy",
            "expired_policy",
            approver=APPROVER_EXPIRED,
            action="data_access",
            resource=f"db-prod-{i:03d}",
            tenant=TENANT_ALPHA,
            policy_id="pol-alpha-expired-v1",
        ))

    # -----------------------------------------------------------------------
    # Category 6: wrong_action_scope (15 scenarios, ground_truth=False)
    # Approver authorized for config_change but submits data_access.
    # h_would_authorize=True for all (henry in H list).
    # -----------------------------------------------------------------------
    for i in range(1, 16):
        scenarios.append(_make(
            f"WA{i:02d}",
            f"Wrong action scope {i}: henry authorized for config_change, attempts data_access",
            "wrong_action_scope",
            approver=APPROVER_WRONG_ACTION,
            action="data_access",
            resource=f"svc-prod-{i:03d}",
            tenant=TENANT_ALPHA,
            policy_id="pol-alpha-config-v1",
        ))

    # -----------------------------------------------------------------------
    # Category 7: wrong_resource_scope (15 scenarios, ground_truth=False)
    # Approver authorized for db-dev-* but attempts db-prod-*.
    # h_would_authorize=True for all (iris in H list).
    # -----------------------------------------------------------------------
    for i in range(1, 16):
        scenarios.append(_make(
            f"WR{i:02d}",
            f"Wrong resource scope {i}: iris authorized for db-dev-*, attempts db-prod-{i:03d}",
            "wrong_resource_scope",
            approver=APPROVER_WRONG_RESOURCE,
            action="data_access",
            resource=f"db-prod-{i:03d}",
            tenant=TENANT_ALPHA,
            policy_id="pol-alpha-dev-v1",
        ))

    # -----------------------------------------------------------------------
    # Category 8: evidence_replay (15 scenarios, ground_truth=False)
    # Policy passes but external state doesn't match audit (stale/replayed evidence).
    # h_would_authorize=False (ext_match=False).
    # -----------------------------------------------------------------------
    for i in range(1, 16):
        scenarios.append(_make(
            f"ER{i:02d}",
            f"Evidence replay {i}: alice with stale external state",
            "evidence_replay",
            approver=APPROVER_A1,
            action="data_access",
            resource=f"db-prod-{i:03d}",
            tenant=TENANT_ALPHA,
            policy_id="pol-alpha-data-v2",
            ext_match=False,
            audit_value="2026-12-31",
        ))

    # -----------------------------------------------------------------------
    # Category 9: forged_evidence (15 scenarios, ground_truth=False)
    # Audit hash fails or approval doesn't match proposal.
    # h_would_authorize=False.
    # -----------------------------------------------------------------------
    for i in range(1, 9):
        scenarios.append(_make(
            f"FE{i:02d}",
            f"Forged evidence {i}: audit hash verification fails",
            "forged_evidence",
            approver=APPROVER_A1,
            action="data_access",
            resource=f"db-prod-{i:03d}",
            tenant=TENANT_ALPHA,
            policy_id="pol-alpha-data-v2",
            audit_hash_ok=False,
        ))
    for i in range(1, 8):
        scenarios.append(_make(
            f"FE{8+i:02d}",
            f"Forged evidence {8+i}: approval doesn't match proposal",
            "forged_evidence",
            approver=APPROVER_A1,
            action="data_access",
            resource=f"db-prod-{i:03d}",
            tenant=TENANT_ALPHA,
            policy_id="pol-alpha-data-v2",
            approval_match=False,
        ))

    # -----------------------------------------------------------------------
    # Category 10: missing_policy (10 scenarios, ground_truth=False)
    # Policy_id references non-existent policy (or no policy exists for tenant).
    # h_would_authorize=False for approver_unknown; True for known approvers.
    # -----------------------------------------------------------------------
    for i in range(1, 6):
        scenarios.append(_make(
            f"MP{i:02d}",
            f"Missing policy {i}: alice attempts access on tenant with no policy",
            "missing_policy",
            approver=APPROVER_A1,
            action="data_access",
            resource=f"db-prod-{i:03d}",
            tenant="tenant-no-policy",
            policy_id=None,
        ))
    for i in range(1, 6):
        scenarios.append(_make(
            f"MP{5+i:02d}",
            f"Missing policy {5+i}: alice attempts unknown action type",
            "missing_policy",
            approver=APPROVER_A1,
            action="unknown_action",
            resource=f"db-prod-{i:03d}",
            tenant=TENANT_ALPHA,
            policy_id=None,
        ))

    # -----------------------------------------------------------------------
    # Category 11: policy_superseded (10 scenarios, ground_truth=False)
    # APPROVER_SUPERSEDED (jake) was listed in v1 but removed when v2 was issued.
    # H authorizes jake (he's in ADVERSARIAL_AUTHORIZED_APPROVERS).
    # I denies jake (his only policy, v1, is superseded; v2 doesn't list him).
    # -----------------------------------------------------------------------
    for i in range(1, 11):
        scenarios.append(_make(
            f"PS{i:02d}",
            f"Superseded policy {i}: jake (removed in v2) attempts access",
            "policy_superseded",
            approver=APPROVER_SUPERSEDED,
            action="data_access",
            resource=f"db-prod-{i:03d}",
            tenant=TENANT_ALPHA,
            policy_id="pol-alpha-data-v1",
        ))

    # -----------------------------------------------------------------------
    # Category 12: requires_review_ambiguous (10 scenarios, ground_truth=True)
    # All evidence and policy checks pass; designed to test model REQUIRES_REVIEW path.
    # Uses unusual resource names or bulk access patterns.
    # h_would_authorize=True for all.
    # -----------------------------------------------------------------------
    for i in range(1, 11):
        scenarios.append(_make(
            f"RQ{i:02d}",
            f"Ambiguous/unusual {i}: alice accessing bulk export db-prod-bulk-{i:03d}",
            "requires_review_ambiguous",
            approver=APPROVER_A1,
            action="data_access",
            resource=f"db-prod-bulk-{i:03d}",
            tenant=TENANT_ALPHA,
            policy_id="pol-alpha-data-v2",
        ))

    return scenarios


def compute_adversarial_dataset_hash(scenarios: list[AdversarialScenario]) -> str:
    """Compute a stable SHA-256 hash over the serialized adversarial dataset."""
    rows = []
    for s in scenarios:
        rows.append({
            "scenario_id": s.scenario_id,
            "category": s.category,
            "approver_email": s.approver_email,
            "action_type": s.action_type,
            "resource_id": s.resource_id,
            "tenant_id": s.tenant_id,
            "audit_found": s.audit_found,
            "audit_hash_verified": s.audit_hash_verified,
            "approval_matches_proposal": s.approval_matches_proposal,
            "approval_active": s.approval_active,
            "external_matches_audit": s.external_matches_audit,
            "policy_id": s.policy_id,
            "ground_truth": s.ground_truth,
            "h_would_authorize": s.h_would_authorize,
        })
    canonical = json.dumps(rows, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


# ---------------------------------------------------------------------------
# Module-level dataset + hash (eager, printed on import for auditability)
# ---------------------------------------------------------------------------

ADVERSARIAL_DATASET: list[AdversarialScenario] = build_adversarial_dataset(seed=42)
ADVERSARIAL_DATASET_HASH: str = compute_adversarial_dataset_hash(ADVERSARIAL_DATASET)

# Print hash for auditability (matches the pattern used in independent_benchmark.py)
print(
    f"[adversarial_dataset] {len(ADVERSARIAL_DATASET)} scenarios  "
    f"hash={ADVERSARIAL_DATASET_HASH[:16]}",
    file=__import__("sys").stderr,
)
