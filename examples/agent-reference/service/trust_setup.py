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


def build(state_dir: Path) -> dict[str, Any]:
    """Create keys and configuration for one Core. Returns the environment and the public state."""
    from aigov_agent_reference.core_policy import (
        signing_keys,
        trust_store_json,
        write_signed_policy,
    )

    keys = {
        "agent": _key(),
        "maintainer": _key(),
        "lead": _key(),
        "intern": _key(),
        "executor": _key(),
    }
    seed_b64, policy_pub = signing_keys()
    policy_dir = state_dir / "policies"
    write_signed_policy(policy_dir, seed_b64)

    auth_sk = SigningKey.generate()
    auth_seed_hex = bytes(auth_sk).hex()
    auth_pub_b64 = base64.b64encode(bytes(auth_sk.verify_key)).decode("ascii")

    principals = {
        keys["agent"]: {
            "principal": AGENT_PRINCIPAL,
            "identity": AGENT_PRINCIPAL,
            "role": "agent",
            "tenant": TENANT,
        },
        keys["maintainer"]: {
            "principal": "approver:maintainer",
            "identity": APPROVER_IDENTITIES["maintainer"],
            "role": "approver",
            "tenant": TENANT,
        },
        keys["lead"]: {
            "principal": "approver:lead",
            "identity": APPROVER_IDENTITIES["lead"],
            "role": "approver",
            "tenant": TENANT,
        },
        keys["intern"]: {
            "principal": "approver:intern",
            "identity": APPROVER_IDENTITIES["intern"],
            "role": "approver",
            "tenant": TENANT,
        },
        keys["executor"]: {
            "principal": EXECUTOR_PRINCIPAL,
            "identity": EXECUTOR_PRINCIPAL,
            "role": "executor",
            "tenant": TENANT,
        },
    }
    env = {
        "AIGOV_ENVIRONMENT": "staging",
        "AIGOV_POLICY_DIR": str(policy_dir),
        "AIGOV_POLICY_BUNDLE_FILE": str(policy_dir / "policy.bundle.staging.json"),
        "AIGOV_POLICY_TRUST_ED25519_JSON": trust_store_json(policy_pub),
        "GOVAI_API_KEYS": ",".join(keys.values()),
        "GOVAI_API_KEYS_JSON": json.dumps({k: TENANT for k in keys.values()}),
        "GOVAI_PRINCIPALS_JSON": json.dumps(principals),
        "GOVAI_EXECUTION_AUTH_SIGNING_SEED_HEX": auth_seed_hex,
        "GOVAI_EXECUTOR_AUDIENCE": EXECUTOR_AUDIENCE,
        "GOVAI_EXECUTION_AUTH_TTL_SECONDS": str(AUTH_TTL_SECONDS),
        "GOVAI_AUTO_MIGRATE": "true",
    }
    public_state = {
        "tenant": TENANT,
        "keys": keys,
        "agent_principal": AGENT_PRINCIPAL,
        "executor_principal": EXECUTOR_PRINCIPAL,
        "approver_identities": APPROVER_IDENTITIES,
        "executor_audience": EXECUTOR_AUDIENCE,
        "authorization_public_key": auth_pub_b64,
    }
    return {"env": env, "state": public_state}
