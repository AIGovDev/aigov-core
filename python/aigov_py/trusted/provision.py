"""Per-run identities, keys, and Core configuration for trusted execution.

Every credential is generated for one run and kept outside the repository. Nothing here is a production key. A
deployment issues its own keys from its secret manager and passes them to Core and to the actors by its own means.

Keys, and who holds them:

- one API key per principal (agent, each approver, executor). Each key maps to one principal and one role in Core.
- the policy-bundle signing key. Core holds it, and signs the policy with it.
- the execution-authorization signing seed (Ed25519, domain-separated). Core holds it. The public half is pinned by the
  executor.
"""

from __future__ import annotations

import base64
import json
import secrets
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from nacl.signing import SigningKey

from .policy import generate_signing_keys, trust_store_json, write_signed_policy


def _key() -> str:
    return "aigov-key-" + secrets.token_urlsafe(24)


def provision(
    state_dir: Path,
    *,
    tenant: str,
    approvers: Mapping[str, str],
    agent_identity: str,
    executor_identity: str,
    policy_document: dict[str, Any],
    policy_issuer_id: str,
    policy_signer: str,
    policy_created_at_utc: str,
    policy_expires_at_utc: str,
    auth_ttl_seconds: int = 60,
    executor_audience: str | None = None,
) -> dict[str, Any]:
    """Create keys and configuration for one Core. Returns ``{"env": ..., "state": ...}``.

    ``env`` is what Core needs in its environment. ``state`` is what the actors need: each key, each approver's
    identity, the executor audience, and the authorization public key. ``state`` contains no signing seed.

    ``approvers`` maps approver name to identity. Each name gets its own key and principal ``approver:<name>``, and
    each identity is the identity Core will authenticate for that key.
    """
    audience = executor_identity if executor_audience is None else executor_audience
    if not 1 <= auth_ttl_seconds <= 3600:
        raise ValueError("auth_ttl_seconds must be between 1 and 3600")
    if agent_identity == executor_identity or agent_identity in approvers.values():
        raise ValueError(
            "agent, executor, and approver identities must all be different"
        )

    keys: dict[str, str] = {"agent": _key()}
    for name in approvers:
        keys[name] = _key()
    keys["executor"] = _key()

    seed_b64, policy_pub = generate_signing_keys()
    policy_dir = state_dir / "policies"
    write_signed_policy(
        policy_dir,
        seed_b64,
        policy_document,
        issuer_id=policy_issuer_id,
        signer=policy_signer,
        created_at_utc=policy_created_at_utc,
        expires_at_utc=policy_expires_at_utc,
    )

    auth_sk = SigningKey.generate()
    auth_seed_hex = bytes(auth_sk).hex()
    auth_pub_b64 = base64.b64encode(bytes(auth_sk.verify_key)).decode("ascii")

    principals: dict[str, Any] = {
        keys["agent"]: {
            "principal": agent_identity,
            "identity": agent_identity,
            "role": "agent",
            "tenant": tenant,
        },
    }
    for name, identity in approvers.items():
        principals[keys[name]] = {
            "principal": f"approver:{name}",
            "identity": identity,
            "role": "approver",
            "tenant": tenant,
        }
    principals[keys["executor"]] = {
        "principal": executor_identity,
        "identity": executor_identity,
        "role": "executor",
        "tenant": tenant,
    }
    env = {
        "AIGOV_ENVIRONMENT": "staging",
        "AIGOV_POLICY_DIR": str(policy_dir),
        "AIGOV_POLICY_BUNDLE_FILE": str(policy_dir / "policy.bundle.staging.json"),
        "AIGOV_POLICY_TRUST_ED25519_JSON": trust_store_json(
            policy_issuer_id, policy_pub
        ),
        "GOVAI_API_KEYS": ",".join(keys.values()),
        "GOVAI_API_KEYS_JSON": json.dumps({k: tenant for k in keys.values()}),
        "GOVAI_PRINCIPALS_JSON": json.dumps(principals),
        "GOVAI_EXECUTION_AUTH_SIGNING_SEED_HEX": auth_seed_hex,
        "GOVAI_EXECUTOR_AUDIENCE": audience,
        "GOVAI_EXECUTION_AUTH_TTL_SECONDS": str(auth_ttl_seconds),
        "GOVAI_AUTO_MIGRATE": "true",
    }
    state = {
        "tenant": tenant,
        "keys": keys,
        "agent_principal": agent_identity,
        "executor_principal": executor_identity,
        "approver_identities": dict(approvers),
        "executor_audience": audience,
        "authorization_public_key": auth_pub_b64,
    }
    return {"env": env, "state": state}


def load_state(path: Path) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))
