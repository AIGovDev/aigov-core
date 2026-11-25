"""Signed AIGov Core policy for agent tool calls (trusted-execution version).

The policy is an ordinary ``govai.policy.v1`` bundle. Core verifies its Ed25519 signature at startup, and
enforces the ingest rules on every ``POST /evidence``. The agent process never sees the policy signing key.

Event types, and which principal role may post each one (enforced by Core, see ``rust/src/principals.rs``):

- ``tool_approval_requested`` (agent): records that a write needs a human decision. Core stamps the requester.
- ``human_approved`` (approver): approve or reject. Core checks that the approver named in the payload is the
  authenticated identity, that the approver is on the allowlist, that the approver is not the requester, and
  that the timestamp is fresh.
- ``human_approval_revoked`` (approver): withdraws an approval. Only the approver who gave it may revoke it.
- ``tool_call`` (agent): a read-only call on the read allowlist. No approval needed.
- ``consequential_tool_call`` (agent): a write. Core accepts it only with an approval that is recorded, approved,
  in scope, not revoked, unconsumed, in date, and bound to the same run, tool, argument digest, and policy
  revision. Core then issues a signed execution authorization (see ``rust/src/execution_authorization.rs``).
- ``execution_receipt`` (executor): records that the executor ran an authorized call. It needs an issued
  authorization for the same tool and argument digest, and only one receipt per authorization.
- ``tool_call_blocked`` (agent): the agent's record of a refusal.

Keys: the policy signing key is generated per bundle here. It is for this example and for tests. A deployment
must use its own managed key.
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
APPROVAL_SCOPE = "tool_execution"
APPROVAL_LINKAGE = ["tool_name", "tool_call_id", "args_binding_hash", "policy_revision"]


def _nonempty(*fields: str) -> dict[str, Any]:
    return {"required_types": {}, "required_nonempty_strings": list(fields)}


def policy_document(
    *,
    policy_id: str = POLICY_ID,
    read_tools: list[str] | None = None,
    write_tools: list[str] | None = None,
    approvers: list[str] | None = None,
    approval_max_age_seconds: int = APPROVAL_MAX_AGE_SECONDS,
) -> dict[str, Any]:
    """The reference policy. Defaults reproduce the committed reference file. Other deployments (for example the
    customer pilot) pass their own tools, approvers, and policy identifier."""
    read_tools = READ_TOOLS if read_tools is None else read_tools
    write_tools = WRITE_TOOLS if write_tools is None else write_tools
    approvers = APPROVERS if approvers is None else approvers
    return {
        "schema": "govai.policy.v1",
        "policy_id": policy_id,
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
                    "schema": _nonempty(
                        "tool_name", "tool_call_id", "args_binding_hash"
                    ),
                    "gates": [],
                },
                "human_approved": {
                    "schema": _nonempty(
                        "approver",
                        "decision",
                        "scope",
                        "tool_name",
                        "tool_call_id",
                        "args_binding_hash",
                        "policy_revision",
                        "request_event_id",
                    ),
                    "gates": [
                        {
                            "type": "requires_approver_allowlist",
                            "field": "approver",
                            "allowlist": approvers,
                            "code": "approver_not_allowlisted",
                            "message_prefix": "policy_violation: human_approved approver",
                        },
                        {
                            "type": "requires_field_matches_field",
                            "field": "approver",
                            "other_field": "authenticated_identity",
                            "code": "approver_identity_mismatch",
                            "message": "policy_violation: approver does not match the authenticated identity",
                        },
                        {
                            "type": "requires_principal_relation",
                            "reference_field": "request_event_id",
                            "relation": "distinct",
                            "code": "self_approval_refused",
                            "message": "policy_violation: an approver may not approve their own request",
                        },
                        {
                            "type": "requires_timestamp_near_server_time",
                            "max_skew_seconds": APPROVAL_MAX_SKEW_SECONDS,
                            "code": "approval_not_fresh",
                            "message": "policy_violation: approval timestamp is not near server time",
                        },
                    ],
                },
                "human_approval_revoked": {
                    "schema": _nonempty("approval_event_id", "reason"),
                    "gates": [
                        {
                            "type": "requires_principal_relation",
                            "reference_field": "approval_event_id",
                            "relation": "same",
                            "code": "revocation_not_by_approver",
                            "message": "policy_violation: only the approver who gave the approval may revoke it",
                        }
                    ],
                },
                "tool_call_blocked": {
                    "schema": _nonempty("tool_name", "tool_call_id", "reason"),
                    "gates": [],
                },
                "tool_call": {
                    "schema": _nonempty(
                        "tool_name", "tool_call_id", "args_binding_hash"
                    ),
                    "gates": [
                        {
                            "type": "requires_decision_enum",
                            "field": "tool_name",
                            "allowed": read_tools,
                            "code": "tool_not_permitted",
                            "message": "policy_violation: tool is not permitted for this agent",
                        }
                    ],
                },
                "consequential_tool_call": {
                    "schema": _nonempty(
                        "tool_name",
                        "approval_event_id",
                        "tool_call_id",
                        "args_binding_hash",
                        "policy_revision",
                    ),
                    "gates": [
                        {
                            "type": "requires_decision_enum",
                            "field": "tool_name",
                            "allowed": write_tools,
                            "code": "tool_not_permitted",
                            "message": "policy_violation: tool is not permitted for this agent",
                        },
                        {
                            "type": "requires_unconsumed_approval",
                            "approval_field": "approval_event_id",
                            "scope": APPROVAL_SCOPE,
                            "max_age_seconds": approval_max_age_seconds,
                            "linkage_keys": APPROVAL_LINKAGE,
                            "code": "approval_required",
                            "message": "policy_violation: a human approval is required",
                        },
                    ],
                },
                "execution_receipt": {
                    "schema": _nonempty(
                        "execution_authorization_id",
                        "tool_name",
                        "args_binding_hash",
                        "outcome",
                        "result_digest",
                    ),
                    "gates": [
                        {
                            "type": "requires_issued_authorization",
                            "authorization_field": "execution_authorization_id",
                            "code": "authorization_not_issued",
                            "message": "policy_violation: no issued authorization matches this receipt",
                        }
                    ],
                },
            },
        },
        "verdict_rules": {"required_evidence_codes": [], "invalid_conditions": []},
        "signatures": [],
    }


def signing_keys() -> tuple[str, str]:
    """Return (seed_b64, pubkey_b64) for a fresh synthetic policy signing key."""
    sk = SigningKey.generate()
    return (
        base64.b64encode(bytes(sk)).decode("ascii"),
        base64.b64encode(bytes(sk.verify_key)).decode("ascii"),
    )


def write_signed_policy(
    out_dir: Path, seed_b64: str, document: dict[str, Any] | None = None
) -> Path:
    """Write the signed bundle to ``out_dir/policy.bundle.staging.json`` and return its path."""
    from aigov_py.policy_bundle_signing import sign_policy_bundle_ed25519

    out_dir.mkdir(parents=True, exist_ok=True)
    unsigned = out_dir / "policy.unsigned.json"
    doc = policy_document() if document is None else document
    unsigned.write_text(json.dumps(doc, indent=2), encoding="utf-8")
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
