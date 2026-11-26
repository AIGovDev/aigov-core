# Authentication guide

How Core authenticates callers. Two mechanisms, chosen by configuration:

1. **API keys** (existing, unchanged). Static keys in `GOVAI_API_KEYS_JSON` / `GOVAI_PRINCIPALS_JSON`, or hosted keys.
2. **OIDC/JWT** (new). Tokens from an explicitly configured identity provider, verified against its JWKS.

Both can be configured together. Nothing falls back from one to the other after a token fails.

## Configuring OIDC

All four variables are required together. A partial configuration fails at startup.

| Variable | Meaning |
|---|---|
| `GOVAI_OIDC_ISSUER` | The exact `iss` value that tokens must carry. `https` required. |
| `GOVAI_OIDC_AUDIENCE` | The `aud` value this API accepts. Tokens must include it. |
| `GOVAI_OIDC_JWKS_URL` | The key set. `https` required. Redirects are not followed. |
| `GOVAI_OIDC_RULES_JSON` | The identity rules (below). Only these identities get a principal. |

Optional: `GOVAI_OIDC_LEEWAY_SECONDS` (0–60, default 30), `GOVAI_OIDC_JWKS_MAX_AGE_SECONDS` (10–3600, default 300),
`GOVAI_OIDC_JWKS_MIN_REFRESH_SECONDS` (1–300, default 30).

`GOVAI_OIDC_ALLOW_LOOPBACK_JWKS=1` allows plain `http` to a loopback address for local tests. It is refused in production.

### Identity rules

```json
[
  {"issuer": "https://idp.example.com/realm", "kind": "human", "match": "alice-sub",
   "principal": "alice-approver", "identity": "alice@example.com", "role": "approver", "tenant": "tenant-a"},
  {"issuer": "https://idp.example.com/realm", "kind": "workload", "match": "svc-executor",
   "principal": "svc-executor", "identity": "svc-executor", "role": "executor", "tenant": "tenant-a"}
]
```

- `kind: human` matches a token's `sub`. A human token is one that is not issued to a workload client.
- `kind: workload` matches a token whose client (`client_id`, else `azp`) equals `sub` and equals `match`. This is the
  client-credentials shape.
- `role` is one of `agent`, `approver`, `executor`. **A workload rule may not carry `approver`.** Configuration refuses it.
- Roles and tenants come only from these rules. No token claim sets a role or a tenant.

## What a request must present

`Authorization: Bearer <jwt>`, where the JWT:

- is signed with **RS256** (the only accepted algorithm), by a key whose `kid` is in the trusted key set;
- has `iss` equal to the configured issuer, and `aud` containing the configured audience;
- has `sub`, `exp`, `iss`, and `aud`; `nbf` and `iat` are checked when present (`iat` may not be in the future beyond the leeway);
- is not expired.

Refusals are 401 with a stable code:

| Code | Cause |
|---|---|
| `JWT_MALFORMED` | not three segments, or undecodable header or payload |
| `JWT_UNSIGNED` | `alg: none`, or an empty signature |
| `JWT_ALGORITHM_NOT_PERMITTED` | any algorithm other than RS256, including HS256 keyed with the public key |
| `JWT_UNKNOWN_KEY` | `kid` absent from the trusted key set, even after a permitted refresh |
| `JWT_INVALID_SIGNATURE` | signature does not verify |
| `JWT_EXPIRED`, `JWT_NOT_YET_VALID`, `JWT_ISSUED_IN_FUTURE` | time claims |
| `JWT_INVALID_ISSUER`, `JWT_INVALID_AUDIENCE` | issuer or audience mismatch |
| `JWT_MISSING_CLAIM` | a required claim is absent |
| `JWT_UNMAPPED_IDENTITY` | no rule matches the identity, or the token is issued to a workload but its subject is a human |
| `JWKS_UNAVAILABLE` | the key set could not be fetched when a refresh was needed (fails closed) |
| `INVALID_AUTH_TOKEN`, `INVALID_API_KEY`, `MISSING_API_KEY` | non-JWT or missing credentials |

A bearer token that looks like a JWT is verified as a JWT, and its failure stops there. A non-JWT credential is checked as an
API key.

## Identity types and approval

Ingest enforces role and tenant. The role for each event type is fixed:

- `agent`: `tool_call`, `tool_approval_requested`, `consequential_tool_call`, `tool_call_blocked`
- `approver`: `human_approved`, `human_approval_revoked`
- `executor`: `execution_receipt`

**Approval is for humans only.** A workload credential cannot post `human_approved`, whatever its claims say. The tested
shapes are listed in `rust/tests/oidc_gate_http.rs` and in the audit report: a workload `sub` with a human `client_id`, a
human `sub` with a workload `client_id` or `azp`, and the reverse. Each is refused with `ROLE_NOT_PERMITTED` or
`JWT_UNMAPPED_IDENTITY`.

A human session issued to a different front-end client (`azp` is the front-end, `sub` is the person) is a human token, and it
maps to that person's rule.

## API keys (unchanged)

Existing configurations keep working with no change. With no OIDC variables set, Core behaves as before.

With OIDC configured and API keys also configured, API-key requests work as before. A JWT that fails verification is refused
and is not retried as an API key.

With OIDC configured and no API keys, a request without a verified token is refused.

## Limits

- Core verifies identity; it does not verify the identity provider's own security. Trusting an issuer is a configuration decision.
- The key set is cached for `GOVAI_OIDC_JWKS_MAX_AGE_SECONDS`. A key that is removed upstream keeps working until the cache ages out.
- A refresh triggered by an unknown `kid` happens at most once per `GOVAI_OIDC_JWKS_MIN_REFRESH_SECONDS`. A new key may be
  refused for up to that interval after it is published.
- No revocation list is consulted for access tokens. Revoke by removing the rule or the key at the identity provider, and
  restart Core or wait for the cache to age out.
- Not tested: a real hosted identity provider (the local test IdP stands in), and any specific provider's claim conventions.
