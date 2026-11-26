# Identity and key management: audit report (2026-11-26)

Scope: production-oriented identity (OIDC/JWT) and key-lifecycle boundaries, implemented without external infrastructure. Branch
`feat/identity-key-management`, from `origin/staging` at `3ef6a38` (PR #512 merged). Refs #501, which stays open: this change
does not address the policy-revision anti-rollback review that #501 tracks.

Related documents: `docs/threat-model.md` (section "Identity and key management"), `docs/authentication-guide.md`,
`docs/operations/key-management-runbook.md`, `docs/trusted-execution-sdk.md` (section "Keys, signers, and verification").

## Audit findings (before the change)

- The Supabase JWT verifier (`rust/src/auth.rs`) was compiled but never called. The API-key gate rejects any JWT by design.
- Principals were static API keys (`GOVAI_PRINCIPALS_JSON`). No identity-to-tenant mapping existed.
- The JWKS cache had no fetch timeout, no refresh on unknown key id, and no JWK `alg`/`use` checks. The audience check was optional.
- The execution-authorization key had no key id, and the executor pinned one public key. No rotation or revocation path existed.
- The policy trust store had no key ids, statuses, or purposes. Reconciliation keys lived in JSON seed files.

## Implemented

1. **OIDC/JWT verification** (`rust/src/oidc.rs`). RS256 only, checked from the header before any key lookup. Required claims
   `iss`, `aud`, `exp`, `sub`; `nbf` and `iat` checked. Exact issuer; audience must be in `aud`. Explicit JWKS URL, timeout, size
   cap, no redirects. Cache age and refresh interval are bounded. An unknown `kid` triggers at most one refresh per interval.
   Refresh failure fails closed (`JWKS_UNAVAILABLE`).
2. **Identity mapping.** Explicit rules (`GOVAI_OIDC_RULES_JSON`). Human rules match `sub`; workload rules match a client
   identity that equals `sub`. A token issued to any configured workload client never matches a human rule, whether the client
   is in `client_id` or `azp`. Config refuses a workload rule with the approver role.
3. **Gate wiring** (`rust/src/audit_api_key.rs`, `rust/src/principals.rs`, `rust/src/govai_api.rs`). A verified JWT sets the
   principal and tenant and skips the API-key checks. A JWT that fails verification returns 401 with no API-key fallback. Startup
   refuses a partial OIDC configuration, and refuses loopback JWKS in production.
4. **Key identifiers** (`rust/src/execution_authorization.rs`). Optional `signing_key_id` in the signed payload, from
   `AIGOV_EXECUTION_AUTH_KEY_ID`. Omitted when unset, so existing signed bytes are unchanged.
5. **Key registry** (`python/aigov_py/trusted/keys.py`). Public keys with a purpose, owner, and status. Hash-chained event log,
   authoritative; snapshot checked against it. Operator-signed requests with expected-version compare-and-swap, nonce, and freshness
   window. One active key per purpose. Assessments that separate signature validity, trust at signing time, current status, and
   compromise uncertainty.
6. **Operator tool** (`python/aigov_py/trusted/key_admin.py`). `inspect`, `new-operator-key`, `install-operator`, `request`,
   `apply`. Seeds are written owner-only and never printed.
7. **Signer interface** (`python/aigov_py/trusted/signers.py`). `LocalEd25519Signer` (seed hidden) and `ExternalSigner` (bounded
   timeout; every failure is an explicit error). Only the local test provider is exercised.
8. **Registry-based verification** (`python/aigov_py/trusted/authorization.py`, `executor.py`).
   `verify_authorization_with_registry` and an optional `registry=` on the executor. Without it, the pinned-key path is unchanged.

## Verified locally

| Check | Result |
|---|---|
| OIDC unit tests (`cargo test --lib oidc::`) | 30 passed |
| HTTP gate test with loopback test IdP and real router (`tests/oidc_gate_http.rs`) | passed |
| Policy anchor regression tests (`rust/src/policy_anchor.rs`, `rotation_regressions`) | 3 passed |
| Full Rust suite (`cargo test --locked`) | exit 0 (after the disk-full condition was cleared; the earlier failure was ENOSPC during linking) |
| Key registry tests (`test_key_registry.py`) | 25 passed |
| Operator CLI tests (`test_key_admin_cli.py`) | 5 passed |
| Authorization-through-registry tests (`test_authorization_registry.py`) | 7 passed |
| Key-rotation regressions against the real executor (`test_key_rotation_regressions.py`) | 5 passed |
| Executor lifecycle suite (`test_executor_lifecycle.py`, existing) | 43 passed |
| Full Python suite (`pytest python/tests`) | 1222 passed, 61 skipped (database-gated), exit 0 |
| `make gate` | passed |

### Live validation (release `aigov_audit` binary, local test IdP on loopback)

The test IdP serves a JWKS for two keys and mints tokens. Core ran with the OIDC environment, and each case was sent to
`POST /evidence`:

- Human approver: `human_approved` passes authentication and role checks. It returns 400 `policy_violation` only because the test
  payload lacks required fields.
- Workload credentials cannot approve: `ROLE_NOT_PERMITTED` for the workload `sub`, and `JWT_UNMAPPED_IDENTITY` for a human `sub`
  issued to a workload client (through `client_id` and through `azp`).
- Token defects: `JWT_INVALID_AUDIENCE`, `JWT_INVALID_ISSUER`, `JWT_EXPIRED`, `JWT_UNKNOWN_KEY`, `JWT_UNSIGNED`,
  `JWT_ALGORITHM_NOT_PERMITTED` (HS256 keyed with the public key), `MISSING_API_KEY`, `INVALID_API_KEY` for a non-JWT credential.
- JWKS rotation: a token signed with the newly published key was refused inside the refresh-throttle window, and accepted after it.
  The throttle is the designed behaviour, not a defect.
- Provider unavailable: an unknown key with the IdP down returns `JWKS_UNAVAILABLE` (fails closed). A key already cached still verifies
  until the cache ages out.

Live results are reproduced by `scratchpad` scripts and are not committed; the cases above are covered by the HTTP test in the repo.

### Negative controls against staging (`origin/staging` at `3ef6a38`, built from its own worktree)

The same 16 live cases were sent to a staging binary with the same environment. Staging does not read the OIDC variables. Every
JWT, valid or not, was refused with `INVALID_API_KEY` (or `MISSING_API_KEY` without a credential), including the valid human
approver. Staging cannot verify an identity token and cannot separate a human from a workload. That is the gap this change closes.

## Limits and unverified assumptions

- Core does not read the registry. It signs with one configured key id and seed. A Core key rotation is a configuration change
  and a restart. Core-side registry integration is not implemented.
- No trusted timestamps. `issued_at_utc` and `signed_at_utc` are claims by the signer. Historical verdicts depend on them.
- Truncation of the tail of the registry log is valid and shorter; detection depends on the snapshot or an off-host copy.
- A known key stays usable from the cache until `GOVAI_OIDC_JWKS_MAX_AGE_SECONDS` expires, even if the IdP is down. The bound was
  not exercised live beyond the cache window.
- The loopback test IdP stands in for a real provider. No claim is made about any hosted identity provider's claim conventions.
- No compatibility with any external key-management service is claimed or tested.
- Policy-bundle signing predates domain prefixes; its key separation is by registry purpose only.

## Not run in this change

These suites were not run in this change, so they are not claimed as passing: Acme Finance validation, customer pilot end to end,
reference-agent live tests, the container build and test, the SDK wheel check, the security harness, and the PostgreSQL-backed Rust
tests (`policy_anchor_pg`, `db_issued_keys_pg`). Their results must come from CI on the final HEAD before merge.

## Evaluation gate

Passes when: OIDC/JWT verification enforces issuer, audience, signature, time claims, and algorithm; identity mapping cannot give a
workload the approver role through any claim shape; API-key compatibility is preserved with no fallback after a JWT failure; key
purposes are separated and the registry is append-only and tamper-evident; rotation keeps historical evidence verifiable and does not
reset replay or policy-revision state; compromise yields uncertain or untrusted verdicts and refuses outstanding authorizations;
signers never expose key material and fail closed; and the local suites, the live checks, the negative controls against staging, and
`make gate` pass. These hold for the tree recorded above, subject to CI on the final HEAD. The "Not run" suites above are not covered.

## Human approval gate

Not approved for production by this report. Before production use, the owners must: review the OIDC rule configuration for each
tenant, since a mistake there is the main way to grant approval to a workload; decide how Core will read the registry, so that key
rotation does not require a restart; choose an off-host copy of the registry log; decide the JWKS cache bounds for each identity
provider; and run the "Not run" suites. Issue #501 remains open and is not addressed here. Merging into `staging` is a separate
decision, and this report does not make it.
