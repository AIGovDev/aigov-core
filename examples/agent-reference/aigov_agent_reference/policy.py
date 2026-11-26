"""Load the declarative example policy into signed authorization records.

The policy file is JSON (see ``policies/example_policy.json``). Each grant becomes one
``PolicyRecord``, signed with a synthetic key generated for this process. The benchmark's
built-in key is a public constant and is not used here.

Policy answers one question: may this principal, acting on this action type and resource
for this tenant, be authorized? The gate asks it about the approver of record, or about
the agent itself for actions that need no approval.
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from trusted_policy_provider import (
    PolicyKeyProvider,
    TrustedPolicyProvider,
    make_policy_record,
)

POLICY_SCHEMA = "aigov.reference.policy.v1"
DEFAULT_POLICY = (
    Path(__file__).resolve().parents[1] / "policies" / "example_policy.json"
)


@dataclass(frozen=True)
class ReferencePolicy:
    tenant_id: str
    resource_pattern: str
    agent_principal: str
    allowed_tools: frozenset[str]
    approval_required_action_types: frozenset[str]
    provider: TrustedPolicyProvider


def load_policy(
    path: Path = DEFAULT_POLICY, now: float | None = None
) -> ReferencePolicy:
    raw: dict[str, Any] = json.loads(Path(path).read_text())
    if raw.get("schema") != POLICY_SCHEMA:
        raise ValueError(f"unsupported policy schema: {raw.get('schema')!r}")
    tenant = raw["tenant_id"]
    pattern = raw["resource_pattern"]
    issued = time.time() if now is None else now
    key = os.urandom(32)
    keys = PolicyKeyProvider(
        keys={"reference-process": key}, active_key_id="reference-process"
    )
    records = []
    for index, grant in enumerate(raw["grants"]):
        records.append(
            make_policy_record(
                policy_id=f"{tenant}-grant-{index:02d}",
                version=1,
                tenant_id=tenant,
                authorized_principals=[grant["principal"]],
                allowed_action_types=list(grant["action_types"]),
                allowed_resource_patterns=[pattern],
                valid_from=issued - 3600,
                valid_until=issued + 365 * 86400,
                revoked=False,
                revocation_reason=None,
                superseded_by=None,
                key_provider=keys,
            )
        )
    return ReferencePolicy(
        tenant_id=tenant,
        resource_pattern=pattern,
        agent_principal=raw["agent"]["principal"],
        allowed_tools=frozenset(raw["agent"]["allowed_tools"]),
        approval_required_action_types=frozenset(raw["approval_required_action_types"]),
        provider=TrustedPolicyProvider(records, key_provider=keys),
    )
