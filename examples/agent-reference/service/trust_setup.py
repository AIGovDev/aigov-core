"""The reference's per-run identities and Core configuration. The implementation is the SDK's (``aigov_py.trusted``).

Identities (each with its own API key, which is its principal in Core):

- ``agent``: ``agent:release-bot``. Requests approvals and submits calls. Cannot approve, revoke, or write receipts.
- ``maintainer``: approver with identity ``maintainer@acme-corp.example`` (on the allowlist).
- ``lead``: approver with identity ``lead@acme-corp.example`` (on the allowlist).
- ``intern``: approver with identity ``intern@acme-corp.example`` (not on the allowlist, so its approvals are refused).
- ``executor``: ``executor:ref``. Verifies authorizations and records receipts. Cannot approve or submit calls.

Keys held by Core, never given to any actor: the policy-bundle signing key, and the execution-authorization signing seed.
The public authorization key is handed to the executor, which pins it.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

from aigov_agent_reference.core_policy import (
    CREATED,
    FUTURE,
    ISSUER,
    policy_document,
)
from aigov_py.trusted.provision import provision

TENANT = "ref-tenant"
AGENT_PRINCIPAL = "agent:release-bot"
EXECUTOR_PRINCIPAL = "executor:ref"
EXECUTOR_AUDIENCE = "executor:ref"
AUTH_TTL_SECONDS = 30
APPROVER_IDENTITIES = {
    "maintainer": "maintainer@acme-corp.example",
    "lead": "lead@acme-corp.example",
    "intern": "intern@acme-corp.example",
}


def build(
    state_dir: Path,
    *,
    approver_identities: dict[str, str] | None = None,
    document: dict[str, Any] | None = None,
    tenant: str = TENANT,
    agent_principal: str = AGENT_PRINCIPAL,
    executor_principal: str = EXECUTOR_PRINCIPAL,
    executor_audience: str = EXECUTOR_AUDIENCE,
    auth_ttl_seconds: int = AUTH_TTL_SECONDS,
) -> dict[str, Any]:
    """Create keys and configuration for one Core, with the reference's policy unless ``document`` is given."""
    return provision(
        state_dir,
        tenant=tenant,
        approvers=dict(
            APPROVER_IDENTITIES if approver_identities is None else approver_identities
        ),
        agent_identity=agent_principal,
        executor_identity=executor_principal,
        policy_document=policy_document() if document is None else document,
        policy_issuer_id=ISSUER,
        policy_signer="aigov-reference",
        policy_created_at_utc=CREATED,
        policy_expires_at_utc=FUTURE,
        auth_ttl_seconds=auth_ttl_seconds,
        executor_audience=executor_audience,
    )
