"""The Core policy for trusted execution: a signed ``govai.policy.v1`` bundle built from the tools and approvers.

Event types, and the role that may post each one (Core enforces this, see ``rust/src/principals.rs``):

- ``tool_approval_requested`` (agent): records that a write needs a human decision.
- ``human_approved`` (approver): approve or reject. Core checks that the approver is on the allowlist, is the
  authenticated identity, is not the requester, and that the timestamp is fresh.
- ``human_approval_revoked`` (approver): withdraws an approval. Only the approver who gave it may revoke it.
- ``tool_call`` (agent): a read on the read allowlist. No approval needed.
- ``consequential_tool_call`` (agent): a write. Accepted only with a recorded, approved, in-scope, unrevoked,
  unconsumed, in-date approval, bound to the same run, tool, argument digest, and policy revision.
- ``execution_receipt`` (executor): records an executed call. Needs an issued authorization for the same tool and
  digest, and only one receipt per authorization.
- ``tool_call_blocked`` (agent): the agent's record of a refusal.

The signing key is held by the party that signs the bundle, never by an agent or an executor.
"""

from __future__ import annotations

import base64
import json
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from nacl.signing import SigningKey

APPROVAL_LINKAGE: tuple[str, ...] = (
    "tool_name",
    "tool_call_id",
    "args_binding_hash",
    "policy_revision",
)


def _nonempty(*fields: str) -> dict[str, Any]:
    return {"required_types": {}, "required_nonempty_strings": list(fields)}


def build_policy_document(
    *,
    policy_id: str,
    issuer_id: str,
    issuer_display_name: str,
    created_at_utc: str,
    read_tools: Iterable[str],
    write_tools: Iterable[str],
    approvers: Iterable[str],
    approval_max_age_seconds: int = 30,
    approval_max_skew_seconds: int = 60,
    approval_scope: str = "tool_execution",
    approval_linkage: Iterable[str] = APPROVAL_LINKAGE,
    tenants: Iterable[str] = ("*",),
    environments: Iterable[str] = ("*",),
) -> dict[str, Any]:
    """The unsigned policy. Every tool not named in ``read_tools`` or ``write_tools`` is refused by Core."""
    read_list = list(read_tools)
    write_list = list(write_tools)
    approver_list = list(approvers)
    linkage = list(approval_linkage)
    return {
        "schema": "govai.policy.v1",
        "policy_id": policy_id,
        "version": "1",
        "created_at_utc": created_at_utc,
        "issuer": {"issuer_id": issuer_id, "display_name": issuer_display_name},
        "selectors": {"tenants": list(tenants), "environments": list(environments)},
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
                            "allowlist": approver_list,
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
                            "max_skew_seconds": approval_max_skew_seconds,
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
                            "allowed": read_list,
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
                            "allowed": write_list,
                            "code": "tool_not_permitted",
                            "message": "policy_violation: tool is not permitted for this agent",
                        },
                        {
                            "type": "requires_unconsumed_approval",
                            "approval_field": "approval_event_id",
                            "scope": approval_scope,
                            "max_age_seconds": approval_max_age_seconds,
                            "linkage_keys": linkage,
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


def generate_signing_keys() -> tuple[str, str]:
    """Return (seed_b64, pubkey_b64) for a new Ed25519 key. Generated per deployment; never reuse a demo key."""
    sk = SigningKey.generate()
    return (
        base64.b64encode(bytes(sk)).decode("ascii"),
        base64.b64encode(bytes(sk.verify_key)).decode("ascii"),
    )


def write_signed_policy(
    out_dir: Path,
    seed_b64: str,
    document: dict[str, Any],
    *,
    issuer_id: str,
    signer: str,
    created_at_utc: str,
    expires_at_utc: str,
) -> Path:
    """Sign ``document`` and write ``out_dir/policy.bundle.staging.json``. Returns that path."""
    from aigov_py.policy_bundle_signing import sign_policy_bundle_ed25519

    out_dir.mkdir(parents=True, exist_ok=True)
    unsigned = out_dir / "policy.unsigned.json"
    unsigned.write_text(json.dumps(document, indent=2), encoding="utf-8")
    out = out_dir / "policy.bundle.staging.json"
    sign_policy_bundle_ed25519(
        unsigned,
        out_path=out,
        issuer_id=issuer_id,
        signer=signer,
        private_key_base64=seed_b64,
        created_at_utc=created_at_utc,
        expires_at_utc=expires_at_utc,
    )
    unsigned.unlink()
    return out


def trust_store_json(issuer_id: str, pubkey_b64: str) -> str:
    """The trust store Core loads to verify the bundle: one issuer and its public key."""
    return json.dumps([{"issuer_id": issuer_id, "pubkeys_base64": [pubkey_b64]}])
