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

- Core reads the registry's event log and signs with its active key. Its seed files are on the Core host. Compromise of that host
  exposes the active seed until its key is revoked.
- No trusted timestamps. `issued_at_utc` and `signed_at_utc` are claims by the signer. Historical verdicts depend on them.
- Truncation of the tail of the registry log is valid and shorter; detection depends on the snapshot or an off-host copy.
- A known key stays usable from the cache until `GOVAI_OIDC_JWKS_MAX_AGE_SECONDS` expires, even if the IdP is down. The bound was
  not exercised live beyond the cache window.
- The loopback test IdP stands in for a real provider. No claim is made about any hosted identity provider's claim conventions.
- No compatibility with any external key-management service is claimed or tested.
- Policy-bundle signing predates domain prefixes; its key separation is by registry purpose only.

## Core-side registry integration

Core now issues execution authorizations from the trusted registry (`rust/src/execution_authorization.rs`,
`rust/src/key_registry.rs`). Core replays the authoritative event log, verifies the hash chain and every transition, and ignores
the snapshot file. It picks the active key when it prepares an authorization and re-checks that key before signing. Each refusal
is a stable code:

- no active key: `503 AUTHORIZATION_KEY_UNAVAILABLE`, nothing appended;
- signing refused after the append (revoked or retired since prepare, seed missing, unreadable, or mismatched): `503
  AUTHORIZATION_SIGNING_REFUSED` with the record hash. The record stays in the ledger and no authorization is issued;
- both a seed and a registry configured: refused at startup.

Seed files are base64, the format the operator tool produces, with owner-only permissions, and must derive the registered public key.
A first draft read them as hex and would have refused every operator-provisioned seed; a cross-language test now uses a seed generated
by Python.

### Live validation

A debug build of `aigov_audit` in dev mode, on loopback, with a scratch registry driven through the Python operator API. Each row was
sent to `POST /evidence` as the agent principal.

| Case | Result |
|---|---|
| Active `exe-k1` | 200. Authorization signed with `signing_key_id` `exe-k1`. Executor verifier accepts it. |
| Rotation to `exe-k2`, no restart | 200. Signed with `exe-k2`. |
| Revoke `exe-k2`, no active key | 503 `AUTHORIZATION_KEY_UNAVAILABLE`. Ledger lines unchanged (3 → 3). |
| Active `exe-k3` whose seed belongs to another key | 503 `AUTHORIZATION_SIGNING_REFUSED`. Ledger gained one record (3 → 4), as designed. |
| Executor verdict, `exe-k1` authorization after its rotation | Accepted (ordinary rotation, trusted at signing). |
| Executor verdict, `exe-k2` authorization issued 1.1 s before revocation | Refused: verdict `uncertain` (`signed_before_compromise_uncertain`). |
| Tampered payload on an accepted authorization | Refused: `authorization_signature_invalid`. |
| Garbage written over the snapshot `registry.json` | Core did not fail on it. The request reached the seed check. This is weaker than a clean run: the failing seed was from the case above. |
| Startup with a seed and a registry both set | Refused: "configure either ... not both". |

One observation outside this change, not investigated: in dev with the default policy, a `consequential_tool_call` naming a
non-existent `approval_event_id` was accepted (200). Whether that is expected in dev, and whether staging and prod enforce the
approval link, needs checking.

### Test results on this tree

- `cargo test --locked`: exit 0, no failures. PostgreSQL-gated tests are ignored and not run.
- Registry unit tests: 4 passed. Authorization unit tests: 27 passed, including the Core issuance path (rotation and revocation
  between prepare and sign, a missing seed, disabled mode, and configuration rules).
- `pytest python/tests` with the in-repo package on `PYTHONPATH`: 1214 passed, 0 failed, 77 skipped. The skips are gated on
  `DATABASE_URL` or a Docker image. An earlier run recorded 1222 passed and 61 skipped; that difference is not explained here.
  `PYTHONPATH` is needed because the active environment's editable `aigov_py` points at another checkout, and the lifecycle tests
  run child processes that do not get the path from `conftest.py`.
- `make gate`: passed.

## Follow-up: approval check, registry trust boundary, and verification (2026-11-26)

### Approval before authorization (confirmed defect, fixed)

Core issued an execution authorization for a `consequential_tool_call` that named an approval which did not exist. Reproduced on the
unfixed tree with `tests/approval_before_authorization.rs`: HTTP 200, a signed authorization, and a ledger record for an approval id
that was never recorded.

Where it applies. The built-in policy defines no approval gate for `consequential_tool_call`. Its `human_approved` rule accepts only
`scope=model_promoted`, so a tool approval cannot be recorded under it. Under the built-in dev policy, unknown event types are
allowed, so with issuance enabled the defect was reachable in dev. In staging and production the built-in policy rejects an undefined
event type, so an unapproved call is refused there. A signed bundle that defines `consequential_tool_call` with the reference
approval gate is also refused (`approval_not_found`). A bundle that defines the call without that gate would have been accepted by the
policy and authorized by Core. That case was not configured anywhere in this repository, but nothing in Core prevented it.

Fix. With issuance enabled, Core refuses a consequential call unless its `approval_event_id` names a `human_approved` event in the same
run with decision `approve`, the same `tool_call_id`, that is not revoked and not already used by another call. The check runs under the
ledger lock, before anything is appended, and returns `policy_violation ... reason=approval_*`. Deployments without an authorization key
are unchanged. Tests: 7 unit tests on the rule (`approval_tests`), 3 policy tests for each environment and the reference bundle
(`approval_policy_tests`), and the HTTP regression test, which passes on the fixed tree and fails on the unfixed one.

Limit. Under the built-in dev policy, a tool approval cannot be recorded at all, so with issuance enabled dev refuses every consequential
call. The positive path (an approval accepted and then used) is covered by the unit tests, not by HTTP, because the reference bundle's
approval path could not be reached through HTTP in this build. Tool calls that are not consequential still receive authorizations without
an approval; that matches the existing `read_repo_metadata` test, and it was not changed.

### Registry trust boundary (confirmed gap, not fixed; owner decision required)

Replay in both Python (`KeyRegistry._replay`) and Rust (`key_registry::load`) checks the hash chain, sequence, and transitions. It does
not verify operator signatures. The log keeps only `request_sha256`, so the signed requests cannot be re-checked from it. The first
operator is trusted by whoever creates the file. Demonstrated with `scratchpad/trust/demo.py` (throwaway registries):

- **Forgery.** A writer of `registry.json.events.jsonl` replaced the log with one they built (their own operator and key). The
  registry reported their key as the only active one. The executor verifier accepted an authorization they signed.
- **Rollback.** A writer truncated the log to a prefix from before a revocation. The revoked key became active again, the integrity
  check passed, and the executor accepted an authorization signed by it. The Rust reader reported the same key as active on the
  rolled-back log (probe, removed afterwards).

These are not defects of the approval check or of the hash chain; they are a missing root of trust. A fix needs an owner decision that
the implementation cannot make: where the root operator public key is pinned (outside the file, configured on Core and the executor),
where the last-seen version and head hash are kept so that rollback is detected (a store the file writer cannot change), and a format
change so that each lifecycle event carries and is verified against its signed request. Until then, treat the log file as a trust root:
restrict write access to the Core and executor operators, and keep an off-host copy to compare against. Issue #501 remains open.

### Python test counts and environment

The active environment's editable `aigov_py` pointed at another checkout (`verdict-scratch/staging/python`, which has no `trusted`
package). Child processes spawned by the lifecycle tests did not get the path from `conftest.py`, and 12 tests failed on that first run.
The suite now runs in an isolated environment (`~/verdict-scratch/iso-venv`, a non-editable install of this tree, `.[dev,agent-reference,runs-postgres]`
plus `openai-agents` and `cryptography`, as in the workflows), with no path tricks.

| Configuration (this tree, final code) | passed | skipped | failed |
|---|---|---|---|
| No `DATABASE_URL`, base extras | 1181 | 60 | 0 |
| No `DATABASE_URL`, agent extras | 1214 | 77 | 0 |
| PostgreSQL 18 (local), destructive flag, agent extras, release binary | 1251 | 40 | 0 |

The earlier figure of 1222 passed and 61 skipped in the first report does not match any configuration reproduced here. The report did not
record its environment. The skip reasons are environmental: 13 need the `aigov-core:test` image, and the rest need live identity
providers, Sigstore, or a release binary. The 1214/77 figure from earlier in this session is the no-database run with agent extras.

### Verification on this tree

- Rust `cargo test --locked -- --include-ignored` with PostgreSQL (`AIGOV_TEST_PG_ADMIN_URL`, `AIGOV_TEST_PG_AUTH=1`,
  `AIGOV_PG_TEST_DESTRUCTIVE=1`, `GOVAI_DATABASE_URL`): 403 passed, 0 failed, 0 ignored.
- Service-backed reference tests (`test_agent_reference_core.py`, 27) against the release Core started by
  `examples/agent-reference/service/start_core_binary.py` on PostgreSQL: 27 passed. Note this configuration does not enable
  execution authorization, so the approval check is not exercised by it.
- Customer pilot (`examples/customer-pilot/pilot.py run`, synthetic data): all checks passed, no failing rows.
- `make gate`, `governance-standards-check`, `reconstructible-demo-check`, `runtime-packaging-check`, `runtime-observability-check`,
  `lineage-governance-check`, `core-runtime-examples-check`, `reference-integrations-check`: passed.
- `scripts/downstream_python_consumption_smoke.py` and the portable-evidence tests: passed.
- SDK wheel built (20 trusted modules; no example or reference code); installed into a clean venv; `trusted_sdk_downstream_check.py
  offline`: passed.
- Operator and identity local validation: the earlier live matrix stands. The approval fix does not change the OIDC path.

Disk space stayed above 40 GiB free during the run.

## Not run in this change

Not run, so not claimed as passing: Acme Finance validation, the container build and test (the `aigov-core:test` image is not built,
so 13 Python tests skip), and the security harness. The customer pilot, the reference-agent live tests, the wheel check, and the
PostgreSQL-backed Rust and Python tests were run in the follow-up below.

## Evaluation gate

Passes when: OIDC/JWT verification enforces issuer, audience, signature, time claims, and algorithm; identity mapping cannot give a
workload the approver role through any claim shape; API-key compatibility is preserved with no fallback after a JWT failure; key
purposes are separated and the registry is append-only and detects edits that do not recompute the hash chain (a writer of the log
file can rewrite or roll it back; see the follow-up); rotation keeps historical evidence verifiable and does not
reset replay or policy-revision state; compromise yields uncertain or untrusted verdicts and refuses outstanding authorizations;
signers never expose key material and fail closed; and the local suites, the live checks, the negative controls against staging, and
`make gate` pass. These hold for the tree recorded above, subject to CI on the final HEAD. The "Not run" suites above are not covered.

## Human approval gate

Not approved for production by this report. Before production use, the owners must: review the OIDC rule configuration for each
tenant, since a mistake there is the main way to grant approval to a workload; choose an off-host copy of the registry log; decide
the JWKS cache bounds for each identity provider; and run the "Not run" suites. Issue #501 remains open and is not addressed here. Merging into `staging` is a separate
decision, and this report does not make it.
