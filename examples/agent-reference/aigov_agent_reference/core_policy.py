"""The reference's Core policy. The builder is the SDK's (``aigov_py.trusted.policy``).

This module supplies the reference's tools, approvers, issuer, and dates. ``policy_document()`` with no arguments
reproduces the committed ``policies/core_policy.unsigned.json``, which a test checks.

The policy signing key is generated per bundle here. It is for this example and for tests. A deployment uses its own
managed key.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from aigov_py.trusted.policy import (
    build_policy_document,
    generate_signing_keys,
)
from aigov_py.trusted.policy import (
    trust_store_json as _sdk_trust_store_json,
)
from aigov_py.trusted.policy import (
    write_signed_policy as _sdk_write_signed_policy,
)

ISSUER = "aigov-reference-issuer"
POLICY_ID = "aigov-agent-reference"
CREATED = "2026-11-25T00:00:00Z"
FUTURE = "2999-01-01T00:00:00Z"
READ_TOOLS = ["read_repo_metadata"]
WRITE_TOOLS = ["create_file"]
APPROVERS = ["maintainer@acme-corp.example", "lead@acme-corp.example"]
APPROVAL_MAX_AGE_SECONDS = 5  # demo TTL; a production policy would use minutes
APPROVAL_MAX_SKEW_SECONDS = 60
APPROVAL_SCOPE = "tool_execution"
APPROVAL_LINKAGE = ["tool_name", "tool_call_id", "args_binding_hash", "policy_revision"]


def policy_document(
    *,
    policy_id: str = POLICY_ID,
    read_tools: list[str] | None = None,
    write_tools: list[str] | None = None,
    approvers: list[str] | None = None,
    approval_max_age_seconds: int = APPROVAL_MAX_AGE_SECONDS,
) -> dict[str, Any]:
    """The reference policy. Defaults reproduce the committed reference file."""
    return build_policy_document(
        policy_id=policy_id,
        issuer_id=ISSUER,
        issuer_display_name="AIGov agent reference (synthetic)",
        created_at_utc=CREATED,
        read_tools=READ_TOOLS if read_tools is None else read_tools,
        write_tools=WRITE_TOOLS if write_tools is None else write_tools,
        approvers=APPROVERS if approvers is None else approvers,
        approval_max_age_seconds=approval_max_age_seconds,
        approval_max_skew_seconds=APPROVAL_MAX_SKEW_SECONDS,
        approval_scope=APPROVAL_SCOPE,
        approval_linkage=APPROVAL_LINKAGE,
    )


def signing_keys() -> tuple[str, str]:
    """Return (seed_b64, pubkey_b64) for a fresh synthetic policy signing key."""
    return generate_signing_keys()


def write_signed_policy(
    out_dir: Path, seed_b64: str, document: dict[str, Any] | None = None
) -> Path:
    """Write the signed bundle to ``out_dir/policy.bundle.staging.json`` and return its path."""
    return _sdk_write_signed_policy(
        out_dir,
        seed_b64,
        policy_document() if document is None else document,
        issuer_id=ISSUER,
        signer="aigov-reference",
        created_at_utc=CREATED,
        expires_at_utc=FUTURE,
    )


def trust_store_json(pubkey_b64: str) -> str:
    return _sdk_trust_store_json(ISSUER, pubkey_b64)
