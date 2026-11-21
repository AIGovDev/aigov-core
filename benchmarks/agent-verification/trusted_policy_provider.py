"""
Trusted Policy Provider — Condition I.

Production-representative authorization policy provider with:
  - Versioned PolicyRecord dataclass with tenant/principal/resource/action/scope constraints
  - HMAC-SHA256 cryptographic integrity verification
  - Revocation and supersession handling
  - Fail-closed behavior when policy evidence cannot be trusted

Trust boundary:
  TRUSTED:  PolicyRecord fields verified by HMAC-SHA256 (key: POLICY_HMAC_KEY)
  ADVISORY: none — policy decisions are fully deterministic
  UNTRUSTED: caller-supplied approver_email, action_type, resource_id, tenant_id
             (these are inputs to be validated, not trusted assertions)

Security invariants:
  - Integrity check failure → "integrity_check_failed" (treated as INDETERMINATE by caller)
  - Revoked policy → "policy_revoked" (DENY)
  - Expired policy → "policy_expired" (DENY)
  - Superseded policy → "policy_superseded" (DENY)
  - No matching policy → "no_matching_policy" (DENY)
  - authorized only when failure_reason == "allow"
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from dataclasses import dataclass, field
from typing import Any

POLICY_HMAC_KEY = b"aigov-policy-integrity-benchmark-2026"


@dataclass
class PolicyRecord:
    """
    Versioned authorization policy record.

    Integrity invariant: integrity_digest == compute_integrity(fields_dict(self))
    Records with invalid integrity_digest are treated as INDETERMINATE (possible tampering).
    """
    policy_id: str
    version: int
    tenant_id: str
    authorized_principals: list[str]
    allowed_action_types: list[str]
    allowed_resource_patterns: list[str]
    valid_from: float
    valid_until: float
    revoked: bool
    revocation_reason: str | None
    superseded_by: str | None
    integrity_digest: str = field(default="", repr=False)

    def to_signable_dict(self) -> dict[str, Any]:
        """Return fields dict suitable for integrity computation (excludes integrity_digest)."""
        return {
            "policy_id": self.policy_id,
            "version": self.version,
            "tenant_id": self.tenant_id,
            "authorized_principals": sorted(self.authorized_principals),
            "allowed_action_types": sorted(self.allowed_action_types),
            "allowed_resource_patterns": sorted(self.allowed_resource_patterns),
            "valid_from": self.valid_from,
            "valid_until": self.valid_until,
            "revoked": self.revoked,
            "revocation_reason": self.revocation_reason,
            "superseded_by": self.superseded_by,
        }

    def to_dict(self) -> dict[str, Any]:
        d = self.to_signable_dict()
        d["integrity_digest"] = self.integrity_digest
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "PolicyRecord":
        return cls(
            policy_id=d["policy_id"],
            version=d["version"],
            tenant_id=d["tenant_id"],
            authorized_principals=d["authorized_principals"],
            allowed_action_types=d["allowed_action_types"],
            allowed_resource_patterns=d["allowed_resource_patterns"],
            valid_from=d["valid_from"],
            valid_until=d["valid_until"],
            revoked=d["revoked"],
            revocation_reason=d.get("revocation_reason"),
            superseded_by=d.get("superseded_by"),
            integrity_digest=d.get("integrity_digest", ""),
        )


@dataclass
class PolicyLookupResult:
    """Result of a TrustedPolicyProvider.lookup_authorization call."""
    authorized: bool
    policy_id: str | None
    failure_reason: str


def _resource_matches(resource_id: str, pattern: str) -> bool:
    """Match resource_id against a pattern that may end with '*'."""
    if pattern.endswith("*"):
        return resource_id.startswith(pattern[:-1])
    return resource_id == pattern


class TrustedPolicyProvider:
    """
    Versioned, integrity-verified authorization policy store.

    Records are stored in memory (fixture-loaded). Real deployments would
    back this with an append-only signed log store.

    Lookup algorithm:
      1. Find all records for the requested tenant_id
      2. Verify integrity of each candidate; skip integrity failures (→ INDETERMINATE)
      3. Find the best matching record: highest version that is not revoked,
         not expired, not superseded, with principal + action + resource in scope
      4. If exactly one valid matching record found → "allow"
      5. If integrity check fails on any candidate → "integrity_check_failed"
         (reported even if another valid record exists, to flag store anomalies)
      6. If no valid record → most specific rejection reason

    Policy matching precedence (checked in order):
      integrity → revocation → expiry → supersession → principal → action → resource
    """

    def __init__(self, records: list[PolicyRecord]) -> None:
        self._records = records
        self._by_id: dict[str, PolicyRecord] = {r.policy_id: r for r in records}

    def lookup_authorization(
        self,
        approver_email: str,
        action_type: str,
        resource_id: str,
        tenant_id: str,
        current_time: float | None = None,
    ) -> PolicyLookupResult:
        if current_time is None:
            current_time = time.time()

        tenant_records = [r for r in self._records if r.tenant_id == tenant_id]
        if not tenant_records:
            return PolicyLookupResult(authorized=False, policy_id=None,
                                      failure_reason="no_matching_policy")

        # --- Phase 1: Integrity check on all records ---
        # An integrity failure anywhere is surfaced immediately (possible store tampering).
        valid_records: list[PolicyRecord] = []
        for record in tenant_records:
            if not self.verify_integrity(record):
                return PolicyLookupResult(
                    authorized=False,
                    policy_id=None,
                    failure_reason="integrity_check_failed",
                )
            valid_records.append(record)

        sorted_records = sorted(valid_records, key=lambda r: r.version, reverse=True)

        # --- Phase 2: Separate active from inactive records ---
        active_records: list[PolicyRecord] = []
        # Track the reason from inactive records where THIS principal is listed
        # (more specific than a reason from a record the principal wasn't even in)
        principal_inactive_reason: str | None = None
        any_inactive_reason: str | None = None

        for record in sorted_records:
            inactive_r: str | None = None
            if record.revoked:
                inactive_r = "policy_revoked"
            elif current_time < record.valid_from or current_time > record.valid_until:
                inactive_r = "policy_expired"
            elif record.superseded_by is not None:
                superseding = self._by_id.get(record.superseded_by)
                if superseding is not None and self.verify_integrity(superseding):
                    inactive_r = "policy_superseded"

            if inactive_r is not None:
                if any_inactive_reason is None:
                    any_inactive_reason = inactive_r
                if approver_email in record.authorized_principals:
                    # Principal IS in this inactive record — track the specific reason
                    if principal_inactive_reason is None:
                        principal_inactive_reason = inactive_r
                continue
            active_records.append(record)

        if not active_records:
            # All records are inactive
            best = principal_inactive_reason or any_inactive_reason or "no_matching_policy"
            return PolicyLookupResult(authorized=False, policy_id=None, failure_reason=best)

        # --- Phase 3: Progressive match among active records ---
        principal_match_found = False
        action_match_found = False

        for record in active_records:
            if approver_email not in record.authorized_principals:
                continue
            principal_match_found = True

            action_ok = any(
                action_type == a or action_type.startswith(a.rstrip("*"))
                for a in record.allowed_action_types
            )
            if not action_ok:
                continue
            action_match_found = True

            resource_ok = any(
                _resource_matches(resource_id, pat)
                for pat in record.allowed_resource_patterns
            )
            if not resource_ok:
                continue

            # All checks passed
            return PolicyLookupResult(
                authorized=True,
                policy_id=record.policy_id,
                failure_reason="allow",
            )

        # No active record authorized — return most specific reason
        if not principal_match_found:
            # Was principal listed in an inactive record?
            if principal_inactive_reason is not None:
                return PolicyLookupResult(
                    authorized=False,
                    policy_id=None,
                    failure_reason=principal_inactive_reason,
                )
            return PolicyLookupResult(
                authorized=False,
                policy_id=None,
                failure_reason="unauthorized_principal",
            )

        if not action_match_found:
            return PolicyLookupResult(
                authorized=False,
                policy_id=None,
                failure_reason="action_not_in_scope",
            )

        return PolicyLookupResult(
            authorized=False,
            policy_id=None,
            failure_reason="resource_not_in_scope",
        )

    @staticmethod
    def compute_integrity(fields: dict[str, Any]) -> str:
        """Compute HMAC-SHA256 of a canonical JSON serialization of fields."""
        canonical = json.dumps(fields, sort_keys=True, separators=(",", ":"))
        return hmac.new(POLICY_HMAC_KEY, canonical.encode(), hashlib.sha256).hexdigest()

    @staticmethod
    def verify_integrity(record: PolicyRecord) -> bool:
        """Return True iff the record's integrity_digest is valid."""
        expected = TrustedPolicyProvider.compute_integrity(record.to_signable_dict())
        return hmac.compare_digest(record.integrity_digest, expected)

    def to_fixture_dict(self) -> list[dict[str, Any]]:
        return [r.to_dict() for r in self._records]

    @classmethod
    def from_fixture_dict(cls, data: list[dict[str, Any]]) -> "TrustedPolicyProvider":
        return cls([PolicyRecord.from_dict(d) for d in data])


def make_policy_record(
    policy_id: str,
    version: int,
    tenant_id: str,
    authorized_principals: list[str],
    allowed_action_types: list[str],
    allowed_resource_patterns: list[str],
    valid_from: float,
    valid_until: float,
    revoked: bool = False,
    revocation_reason: str | None = None,
    superseded_by: str | None = None,
) -> PolicyRecord:
    """Create a PolicyRecord with a computed integrity_digest."""
    record = PolicyRecord(
        policy_id=policy_id,
        version=version,
        tenant_id=tenant_id,
        authorized_principals=authorized_principals,
        allowed_action_types=allowed_action_types,
        allowed_resource_patterns=allowed_resource_patterns,
        valid_from=valid_from,
        valid_until=valid_until,
        revoked=revoked,
        revocation_reason=revocation_reason,
        superseded_by=superseded_by,
        integrity_digest="",
    )
    record.integrity_digest = TrustedPolicyProvider.compute_integrity(record.to_signable_dict())
    return record
