"""Configuration for the customer pilot: a synthetic enterprise workflow on AIGov Core.

Everything here is synthetic. The records are invented, the identities are example addresses under ``example.test``,
and the tenant is a pilot tenant. Nothing contacts an external system.

The pilot reuses the trusted-execution machinery of ``examples/agent-reference``: the same Core policy construction,
identity generation, authenticated principals, execution authorizations, and receipts. Only the tools, identities, and
policy named here are the pilot's own.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parents[1]
REF_DIR = REPO_ROOT / "examples" / "agent-reference"
sys.path.insert(0, str(REF_DIR))
sys.path.insert(0, str(REF_DIR / "service"))

from aigov_agent_reference.core_policy import policy_document
from aigov_agent_reference.core_trusted import register_tool

TENANT = "acme-retail-pilot"
POLICY_ID = "acme-retail-pilot-policy"
AGENT_IDENTITY = "agent:support-assistant"
EXECUTOR_IDENTITY = "executor:records-service"
EXECUTOR_AUDIENCE = "executor:records-service"
AUTH_TTL_SECONDS = 60
APPROVAL_MAX_AGE_SECONDS = (
    30  # demonstration window; a production policy would set minutes
)

# Approvers: a data steward (on the allowlist), a records owner (on the allowlist), and an outsider (not on it).
APPROVER_IDENTITIES = {
    "steward": "steward@acme-retail.example",
    "owner": "owner@acme-retail.example",
    "outsider": "outsider@contractor.example",
}
APPROVER_ALLOWLIST = [APPROVER_IDENTITIES["steward"], APPROVER_IDENTITIES["owner"]]

READ_TOOLS = ["read_customer_record"]
WRITE_TOOLS = ["export_customer_data", "update_customer_record"]
# The delete tool is registered (so it can be attempted and refused) but is on neither allowlist.
UNAUTHORIZED_TOOLS = ["delete_customer_record"]

# (action type, the argument that names the resource). Action types follow the reference's naming style.
TOOLS: dict[str, tuple[str, str]] = {
    "read_customer_record": ("customer:read", "customer_id"),
    "export_customer_data": ("customer:export", "customer_id"),
    "update_customer_record": ("customer:update", "customer_id"),
    "delete_customer_record": ("customer:delete", "customer_id"),
}


def register_pilot_tools() -> None:
    """Register the pilot's tools with the trusted layer's registry (process-wide, idempotent)."""
    for tool, (action, resource_key) in TOOLS.items():
        register_tool(tool, action, resource_key)


def pilot_policy_document() -> dict[str, Any]:
    """The pilot's signed policy. Same rules as the reference, with the pilot's tools, approvers, and TTL."""
    return policy_document(
        policy_id=POLICY_ID,
        read_tools=READ_TOOLS,
        write_tools=WRITE_TOOLS,
        approvers=APPROVER_ALLOWLIST,
        approval_max_age_seconds=APPROVAL_MAX_AGE_SECONDS,
    )


register_pilot_tools()
