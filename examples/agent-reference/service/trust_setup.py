"""Generate the identities, keys, and Core configuration for the trusted-execution reference.

Every credential is generated per run and kept outside the repository. Nothing here is a production key.

Identities (each with its own API key, which is its principal in Core):

- ``agent``: ``agent:release-bot``. Requests approvals and submits calls. Cannot approve, revoke, or write receipts.
- ``maintainer``: approver with identity ``maintainer@acme-corp.example`` (on the allowlist).
- ``lead``: approver with identity ``lead@acme-corp.example`` (on the allowlist).
- ``intern``: approver with identity ``intern@acme-corp.example`` (not on the allowlist, so its approvals are refused).
- ``executor``: ``executor:ref``. Verifies authorizations and records receipts. Cannot approve or submit calls.

Keys held by Core, never given to any actor:

- the policy-bundle signing key (signs the policy), and
- the execution-authorization signing seed (Ed25519, domain-separated, used only for authorizations).

The public authorization key is handed to the executor, which pins it.
"""

from __future__ import annotations

import base64
import json
import secrets
import sys
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

from nacl.signing import SigningKey

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


def _key() -> str:
    return "aigov-ref-" + secrets.token_urlsafe(24)


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
    """Create keys and configuration for one Core. Returns the environment and the public state.

    Defaults give the reference's identities and policy. A deployment (for example the customer pilot) passes its
    own approver identities (name -> identity), its policy document, and its tenant. The approver names are the keys
    of ``approver_identities``, and each gets one key and one principal ``approver:<name>``.
    """
    from aigov_agent_reference.core_policy import (
        signing_keys,
        trust_store_json,
        write_signed_policy,
    )

    identities = dict(
        APPROVER_IDENTITIES if approver_identities is None else approver_identities
    )
    keys: dict[str, str] = {"agent": _key()}
    for name in identities:
        keys[name] = _key()
    keys["executor"] = _key()

    seed_b64, policy_pub = signing_keys()
    policy_dir = state_dir / "policies"
    write_signed_policy(policy_dir, seed_b64, document)

    auth_sk = SigningKey.generate()
    auth_seed_hex = bytes(auth_sk).hex()
    auth_pub_b64 = base64.b64encode(bytes(auth_sk.verify_key)).decode("ascii")

    principals: dict[str, Any] = {
        keys["agent"]: {
            "principal": agent_principal,
            "identity": agent_principal,
            "role": "agent",
            "tenant": tenant,
        },
    }
    for name, identity in identities.items():
        principals[keys[name]] = {
            "principal": f"approver:{name}",
            "identity": identity,
            "role": "approver",
            "tenant": tenant,
        }
    principals[keys["executor"]] = {
        "principal": executor_principal,
        "identity": executor_principal,
        "role": "executor",
        "tenant": tenant,
    }
    env = {
        "AIGOV_ENVIRONMENT": "staging",
        "AIGOV_POLICY_DIR": str(policy_dir),
        "AIGOV_POLICY_BUNDLE_FILE": str(policy_dir / "policy.bundle.staging.json"),
        "AIGOV_POLICY_TRUST_ED25519_JSON": trust_store_json(policy_pub),
        "GOVAI_API_KEYS": ",".join(keys.values()),
        "GOVAI_API_KEYS_JSON": json.dumps({k: tenant for k in keys.values()}),
        "GOVAI_PRINCIPALS_JSON": json.dumps(principals),
        "GOVAI_EXECUTION_AUTH_SIGNING_SEED_HEX": auth_seed_hex,
        "GOVAI_EXECUTOR_AUDIENCE": executor_audience,
        "GOVAI_EXECUTION_AUTH_TTL_SECONDS": str(auth_ttl_seconds),
        "GOVAI_AUTO_MIGRATE": "true",
    }
    public_state = {
        "tenant": tenant,
        "keys": keys,
        "agent_principal": agent_principal,
        "executor_principal": executor_principal,
        "approver_identities": identities,
        "executor_audience": executor_audience,
        "authorization_public_key": auth_pub_b64,
    }
    return {"env": env, "state": public_state}
