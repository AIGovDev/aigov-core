"""Signed AIGov Core policy for agent tool calls.

The policy is an ordinary ``govai.policy.v1`` bundle. Core verifies its Ed25519 signature at
startup and enforces the ingest rules on every ``POST /evidence``. Nothing here runs in the
agent process. The agent only submits events to Core and reads back the result.

Event types:

- ``tool_approval_requested``: a tool call that needs a human decision is recorded.
- ``human_approved``: a human decision (approve or reject), with an approver allowlist and a
  server-time freshness check.
- ``tool_call``: a read-only tool call. Allowed for the tools on the read allowlist.
- ``consequential_tool_call``: a write call. Core accepts it only with an unconsumed, in-date,
  approved approval for the same run and the same tool call.

Keys: the signing key is generated for each bundle. It is for this example and for tests. A
deployment must use its own managed key.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any

from nacl.signing import SigningKey

ISSUER = "aigov-reference-issuer"
POLICY_ID = "aigov-agent-reference"
CREATED = "2026-11-25T00:00:00Z"
FUTURE = "2999-01-01T00:00:00Z"
READ_TOOLS = ["read_repo_metadata"]
WRITE_TOOLS = ["create_file"]
APPROVERS = ["maintainer@acme-corp.example", "lead@acme-corp.example"]
APPROVAL_MAX_AGE_SECONDS = 5  # demo TTL; a production policy would use minutes
APPROVAL_MAX_SKEW_SECONDS = 60


def policy_document() -> dict[str, Any]:
    return {
        "schema": "govai.policy.v1",
        "policy_id": POLICY_ID,
        "version": "1",
        "created_at_utc": CREATED,
        "issuer": {
            "issuer_id": ISSUER,
            "display_name": "AIGov agent reference (synthetic)",
        },
        "selectors": {"tenants": ["*"], "environments": ["*"]},
        "inherits": [],
        "ingest_rules": {
            "unknown_event_types": {"behavior": "reject"},
            "event_types": {
                "tool_approval_requested": {
                    "schema": {
                        "required_types": {},
                        "required_nonempty_strings": ["tool_name", "tool_call_id"],
                    },
                    "gates": [],
                },
                "human_approved": {
                    "schema": {
                        "required_types": {},
                        "required_nonempty_strings": [
                            "approver",
                            "decision",
                            "scope",
                            "tool_call_id",
                            "args_binding_hash",
                        ],
                    },
                    "gates": [
                        {
                            "type": "requires_approver_allowlist",
                            "field": "approver",
                            "allowlist": APPROVERS,
                            "code": "approver_not_allowlisted",
                            "message_prefix": "policy_violation: human_approved approver",
                        },
                        {
                            "type": "requires_timestamp_near_server_time",
                            "max_skew_seconds": APPROVAL_MAX_SKEW_SECONDS,
                            "code": "approval_not_fresh",
                            "message": "policy_violation: approval timestamp is not near server time",
                        },
                    ],
                },
                "tool_call_blocked": {
                    "schema": {
                        "required_types": {},
                        "required_nonempty_strings": [
                            "tool_name",
                            "tool_call_id",
                            "reason",
                        ],
                    },
                    "gates": [],
                },
                "tool_call": {
                    "schema": {
                        "required_types": {},
                        "required_nonempty_strings": ["tool_name", "tool_call_id"],
                    },
                    "gates": [
                        {
                            "type": "requires_decision_enum",
                            "field": "tool_name",
                            "allowed": READ_TOOLS,
                            "code": "tool_not_permitted",
                            "message": "policy_violation: tool is not permitted for this agent",
                        }
                    ],
                },
                "consequential_tool_call": {
                    "schema": {
                        "required_types": {},
                        "required_nonempty_strings": [
                            "tool_name",
                            "approval_event_id",
                            "tool_call_id",
                            "args_binding_hash",
                        ],
                    },
                    "gates": [
                        {
                            "type": "requires_decision_enum",
                            "field": "tool_name",
                            "allowed": WRITE_TOOLS,
                            "code": "tool_not_permitted",
                            "message": "policy_violation: tool is not permitted for this agent",
                        },
                        {
                            "type": "requires_unconsumed_approval",
                            "approval_field": "approval_event_id",
                            "scope": "tool_execution",
                            "max_age_seconds": APPROVAL_MAX_AGE_SECONDS,
                            "linkage_keys": ["tool_call_id", "args_binding_hash"],
                            "code": "approval_required",
                            "message": "policy_violation: a human approval is required",
                        },
                    ],
                },
            },
        },
        "verdict_rules": {"required_evidence_codes": [], "invalid_conditions": []},
        "signatures": [],
    }


def signing_keys() -> tuple[str, str]:
    """Return (seed_b64, pubkey_b64) for a fresh synthetic signing key."""
    sk = SigningKey.generate()
    return (
        base64.b64encode(bytes(sk)).decode("ascii"),
        base64.b64encode(bytes(sk.verify_key)).decode("ascii"),
    )


def write_signed_policy(out_dir: Path, seed_b64: str) -> Path:
    """Write the signed bundle to ``out_dir/policy.bundle.staging.json`` and return its path."""
    from aigov_py.policy_bundle_signing import sign_policy_bundle_ed25519

    out_dir.mkdir(parents=True, exist_ok=True)
    unsigned = out_dir / "policy.unsigned.json"
    unsigned.write_text(json.dumps(policy_document(), indent=2), encoding="utf-8")
    out = out_dir / "policy.bundle.staging.json"
    sign_policy_bundle_ed25519(
        unsigned,
        out_path=out,
        issuer_id=ISSUER,
        signer="aigov-reference",
        private_key_base64=seed_b64,
        created_at_utc=CREATED,
        expires_at_utc=FUTURE,
    )
    unsigned.unlink()
    return out


def trust_store_json(pubkey_b64: str) -> str:
    return json.dumps([{"issuer_id": ISSUER, "pubkeys_base64": [pubkey_b64]}])
