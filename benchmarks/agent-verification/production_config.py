"""
Production startup configuration validator.

Checks that an AIGov deployment is configured correctly for production use.
Call validate_or_raise() during application startup to catch misconfigurations
before the first tool call is processed.

Failure modes caught:
  - Missing audit store (write/delete tools are blocked without one)
  - In-memory SQLite audit store (:memory:) — does not survive restarts
  - bypass_mandatory_audit=True — test-isolation flag left on in production
  - Unmanaged in-process key provider — per-process key, tokens cannot cross workers
  - SQLite-backed approval registry for distributed deployments
  - SQLite-backed replay registry for distributed deployments

Usage:
    from production_config import validate_or_raise, DeploymentMode

    validate_or_raise(
        audit_store=audit_store,
        approval_registry=approval_registry,
        replay_registry=replay_registry,
        key_provider=key_provider,
        bypass_mandatory_audit=False,
        mode=DeploymentMode.DISTRIBUTED,
    )
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class DeploymentMode(Enum):
    SINGLE_PROCESS = "single_process"   # one worker, SQLite backends allowed
    DISTRIBUTED    = "distributed"      # multiple workers, requires PostgreSQL


class ProductionConfigError(Exception):
    """Raised when the deployment configuration violates production requirements."""

    def __init__(self, violations: list[str]) -> None:
        self.violations = violations
        lines = "\n  ".join(f"[{i+1}] {v}" for i, v in enumerate(violations))
        super().__init__(
            f"{len(violations)} production configuration violation(s):\n  {lines}"
        )


@dataclass
class ConfigValidationResult:
    violations: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def is_valid(self) -> bool:
        return len(self.violations) == 0


def validate(
    audit_store: Any,
    approval_registry: Any,
    replay_registry: Any,
    key_provider: Any,
    bypass_mandatory_audit: bool,
    mode: DeploymentMode = DeploymentMode.DISTRIBUTED,
) -> ConfigValidationResult:
    """
    Validate production configuration. Returns a result with violations and warnings.

    Does NOT raise — call validate_or_raise() for fail-fast startup behavior.
    """
    result = ConfigValidationResult()

    # 1. Audit store must be configured
    if audit_store is None:
        result.violations.append(
            "audit_store is None: write/delete tools are blocked without an audit store. "
            "Configure a SqlAuditStore backed by a persistent database."
        )
    else:
        # 2. In-memory SQLite audit store does not survive restarts
        backend = getattr(audit_store, "_backend", None)
        path = getattr(audit_store, "_path", None)
        if backend == "sqlite" and path in (":memory:", "", None):
            result.violations.append(
                "audit_store uses in-memory SQLite (':memory:'). "
                "Audit records will be lost on restart. "
                "Use a persistent file path or PostgreSQL backend in production."
            )
        # 3. Distributed mode requires PostgreSQL audit store
        if mode == DeploymentMode.DISTRIBUTED and backend == "sqlite":
            result.warnings.append(
                "audit_store uses SQLite backend in DISTRIBUTED mode. "
                "Consider PostgreSQL for cross-host audit consistency."
            )

    # 4. bypass_mandatory_audit must be False in production
    if bypass_mandatory_audit:
        result.violations.append(
            "bypass_mandatory_audit=True: this test-isolation flag must NEVER be "
            "set in production. It disables mandatory pre-execution audit checks "
            "for write/delete tools."
        )

    # 5. Key provider must be managed (not in-process bytes)
    is_managed = getattr(key_provider, "is_managed", False)
    if not is_managed:
        result.violations.append(
            "key_provider.is_managed is False: the ExecutionTokenAuthority is using "
            "an unmanaged in-memory signing key. Tokens cannot be verified across "
            "worker processes. Use SqlRotatingKeyProvider backed by a shared SQL "
            "store (or a real KMS provider) in production."
        )

    # 5b. Distributed mode: key provider must use asymmetric signing (private key in KMS).
    #     HMAC/symmetric providers (EnvKMSClient, SqlKeyStore) return raw key bytes to the
    #     application and are only suitable for single-process staging deployments.
    if mode == DeploymentMode.DISTRIBUTED:
        is_asymmetric = getattr(key_provider, "is_asymmetric", False)
        if not is_asymmetric:
            result.violations.append(
                "key_provider.is_asymmetric is False in DISTRIBUTED mode: HMAC/symmetric "
                "providers expose raw signing key bytes to the application process. "
                "Use an asymmetric KMS provider (LocalEd25519KMSProvider for staging, "
                "VercelKMSProvider or equivalent for production) where the private key "
                "never leaves the KMS boundary."
            )

    # 6. Distributed mode: approval registry must be PostgreSQL
    if mode == DeploymentMode.DISTRIBUTED:
        reg_safe = getattr(approval_registry, "is_distributed_safe", False)
        if not reg_safe:
            result.violations.append(
                "approval_registry is not distributed-safe: approval consumption "
                "is not atomic across worker processes. Use SqlApprovalRegistry "
                "with backend='postgresql' for distributed deployments."
            )

    # 7. Distributed mode: replay registry (nonce store) must be PostgreSQL
    if mode == DeploymentMode.DISTRIBUTED:
        replay_safe = getattr(replay_registry, "is_distributed_safe", False)
        if not replay_safe:
            result.violations.append(
                "replay_registry is not distributed-safe: nonce consumption is "
                "not atomic across worker processes. Use ReplayRegistry backed "
                "by SqlNonceStore(backend='postgresql') for distributed deployments."
            )

    return result


def validate_or_raise(
    audit_store: Any,
    approval_registry: Any,
    replay_registry: Any,
    key_provider: Any,
    bypass_mandatory_audit: bool,
    mode: DeploymentMode = DeploymentMode.DISTRIBUTED,
) -> None:
    """
    Validate production configuration and raise ProductionConfigError if invalid.

    Call during application startup, before accepting any requests. This
    prevents misconfigured deployments from silently operating in a degraded
    or insecure state.

    Raises ProductionConfigError listing all violations (not just the first).
    Returns None when the configuration is valid for the specified mode.
    """
    result = validate(
        audit_store=audit_store,
        approval_registry=approval_registry,
        replay_registry=replay_registry,
        key_provider=key_provider,
        bypass_mandatory_audit=bypass_mandatory_audit,
        mode=mode,
    )
    if not result.is_valid:
        raise ProductionConfigError(result.violations)
