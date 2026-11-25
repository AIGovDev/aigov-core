"""Configuration for the customer pilot: a synthetic enterprise workflow on AIGov Core.

Everything here is synthetic. The records are invented, the identities are example addresses under ``example.test``,
and the tenant is a pilot tenant. Nothing contacts an external system.

The pilot uses the public SDK (``aigov_py.trusted``) and nothing from the reference. Its tools are explicit: every tool
is registered so its argument digest can be computed, but only the read and write tools are on the policy allowlists.
The delete tool is registered and not allowed, so Core refuses it by policy.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from aigov_py.trusted import ToolSpec, build_policy_document, provision, tool_registry

TENANT = "acme-retail-pilot"
POLICY_ID = "acme-retail-pilot-policy"
ISSUER_ID = "acme-retail-pilot-issuer"
SIGNER = "acme-retail-pilot"
CREATED = "2026-11-25T00:00:00Z"
EXPIRES = "2999-01-01T00:00:00Z"
AGENT_IDENTITY = "agent:support-assistant"
EXECUTOR_IDENTITY = "executor:records-service"
EXECUTOR_AUDIENCE = "executor:records-service"
AUTH_TTL_SECONDS = 60
APPROVAL_MAX_AGE_SECONDS = (
    30  # demonstration window; a production policy would set minutes
)

# Approvers: a data steward and a records owner (both allowlisted), and an outsider with a credential that is not allowed.
APPROVER_IDENTITIES = {
    "steward": "steward@acme-retail.example",
    "owner": "owner@acme-retail.example",
    "outsider": "outsider@contractor.example",
}
APPROVER_ALLOWLIST = [APPROVER_IDENTITIES["steward"], APPROVER_IDENTITIES["owner"]]

READ_TOOLS = ["read_customer_record"]
WRITE_TOOLS = ["export_customer_data", "update_customer_record"]
# Registered so the agent can attempt it and Core can refuse it. On neither allowlist.
UNAUTHORIZED_TOOLS = ["delete_customer_record"]

PILOT_TOOLS = tool_registry(
    [
        ToolSpec("read_customer_record", "customer:read", "read", "customer_id"),
        ToolSpec("export_customer_data", "customer:export", "write", "customer_id"),
        ToolSpec("update_customer_record", "customer:update", "write", "customer_id"),
        ToolSpec("delete_customer_record", "customer:delete", "write", "customer_id"),
    ]
)


def pilot_policy_document() -> dict[str, Any]:
    """The pilot's signed policy: its tools, its allowlisted approvers, and its approval window."""
    return build_policy_document(
        policy_id=POLICY_ID,
        issuer_id=ISSUER_ID,
        issuer_display_name="Acme Retail pilot (synthetic)",
        created_at_utc=CREATED,
        read_tools=READ_TOOLS,
        write_tools=WRITE_TOOLS,
        approvers=APPROVER_ALLOWLIST,
        approval_max_age_seconds=APPROVAL_MAX_AGE_SECONDS,
    )


def generate(state_dir: Path) -> dict[str, Any]:
    """Per-run identities, keys, signed policy, and Core environment for the pilot."""
    return provision(
        state_dir,
        tenant=TENANT,
        approvers=APPROVER_IDENTITIES,
        agent_identity=AGENT_IDENTITY,
        executor_identity=EXECUTOR_IDENTITY,
        executor_audience=EXECUTOR_AUDIENCE,
        policy_document=pilot_policy_document(),
        policy_issuer_id=ISSUER_ID,
        policy_signer=SIGNER,
        policy_created_at_utc=CREATED,
        policy_expires_at_utc=EXPIRES,
        auth_ttl_seconds=AUTH_TTL_SECONDS,
    )
