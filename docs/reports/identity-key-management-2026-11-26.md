# Identity and key management: audit report (2026-11-26)

> Status: the registry was rewritten to format v2 in the follow-up section ("Follow-up: approval check, registry trust boundary, and verification"). Sections below that describe v1 (`eaab53f` and earlier) are the record of the first commits and are kept for that reason.

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

- Core verifies the registry against the pinned trust file and the PostgreSQL anchor, and signs with the active key. Its seed files
  are on the Core host. Compromise of that host exposes the active seed until its key is revoked.
- Simultaneous compromise of PostgreSQL write access and the trust file is not detected by the registry (see the residual threat above).
- No trusted timestamps. `issued_at_utc` and `signed_at_utc` are claims by the signer. Historical verdicts depend on them.
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

### Registry trust boundary (confirmed gap, now fixed in format v2)

Replay in both readers checked the hash chain and transitions but not signatures. The log kept only `request_sha256`, and the first
operator was trusted by whoever created the file. Two attacks reproduced against commit `eaab53f`, as negative controls:

- **Forgery.** A writer of the log replaced it with one built under their own operator and key. The registry showed their key as the
  only active one, and the executor verifier accepted an authorization they signed.
- **Rollback and resurrection.** A writer restored a prefix from before a revocation. The revoked key was active again, the integrity
  check passed, and the executor accepted an authorization signed by it.

Outputs: `scratchpad/trust/negative_control_eaab53f.txt` (Python executor), and the Rust reader probe on the same commit (forged log:
`active key = Some("exe-evil")`; rolled-back log: `exe-real status = Some("active")`).

The corrected design, in three parts:

1. **Pinned roots.** The root operator public keys are in a trust file, owner-only, outside the registry directory. The registry cannot
   supply, add, or replace a root. Roots install and remove operators and import legacy history. A retired root signs only up to a stated
   sequence number. Core and the executor refuse a trust file that is readable by others.
2. **Signed, versioned events.** Format `govai.key_event.v2`. Each event carries its signed request (`govai.key_op.v2`, domain
   `govai.key_op.v2\0`), which holds the expected version and a nonce. Replay verifies every signature, the signer's authority, the
   sequence, the hash chain, and every transition, from genesis. State is derived from signed fields only. Python writes; Rust and
   Python both read. The fixture is `rust/tests/fixtures/key_registry_v2/`.
3. **Independent anchor.** Table `key_registry_anchor` in PostgreSQL (migration `0004`), holding the sequence number and head hash of the
   last committed event. Writers hold the row lock for the whole append and commit, and compare-and-swap the anchor. Readers require the
   log to match the anchor exactly. Core reads the anchor on every issuance and before signing. The production anchor contains no DDL: the
   `DDL` boundary test in the repository enforces this for shipped packages.

Re-run of the same attacks against the corrected code (`scratchpad/trust/negative_control_v2.txt`):

| Attack | Before (`eaab53f`) | After |
|---|---|---|
| A. Log replaced by one built under another root and key | Executor accepts `exe-evil` | Reader refuses: `request_signature_invalid` (the pinned root's signature does not verify) |
| B. Rollback to before a revocation | Executor accepts `exe-real` after revocation | Reader refuses: `anchor_log_behind` |

Test coverage of the requested matrix (all run; the counts are per file):

- **Unauthorized insertion and substitution** (`test_registry_attacks.py`): a writer without an operator key; an operator signing a root
  operation; a role without authority; a whole log from another registry; an equal-length log with a different head; a trust file readable
  by others; a trust file with no current root. Rust: the same classes in `key_registry::tests`.
- **Rollback and revoked-key resurrection**: a restored prefix; an anchor moved back (detected as log-ahead).
- **Event deletion, modification, reordering, replay**: deletion (even with the anchor moved to match), modification with a recomputed hash
  (the signature still fails), reordering, duplication, an old request after the version moved.
- **Concurrent rotation and revocation**: six processes revoking the same key; a rotation racing a revocation. Exactly one applies. Run on SQLite
  and on PostgreSQL (the row lock).
- **Crash consistency**: a crash between append and commit leaves the log one event ahead; readers and writers refuse; `reconcile` anchors the
  single event after verifying it; two events ahead is refused. PostgreSQL: the transaction rolls back, and the anchor does not move.
- **Root and operator rotation**: root-a retired at a bound, root-b current; history verifies; root-a refused after its bound; a revoked
  operator refused after revocation, its history still verifiable.
- **Migration**: a v1 registry (built with the v1 writer from `eaab53f`, kept as a test-only module) migrates into one root-signed `legacy_import`
  event. Imported keys are `legacy_v1_unsigned` and their verdicts are at most `uncertain`. An altered v1 log, an existing target, an initialized
  anchor, a non-current root, and a v1 log used directly as v2 are all refused.
- **Cross-language**: Python verifies the committed fixture and refuses altered and removed events; Rust verifies it, and refuses altered,
  removed, deleted, duplicated, unauthorized, and wrong-root variants.
- **Preservation**: executed authorizations stay consumed across key rotation and across a root rotation; outstanding authorizations survive
  ordinary rotation; historical verdicts are unchanged for keys that were not imported.

Defects found and fixed during the work:

- The first Python readers and the first Rust reader read the log and the anchor without a consistent view. A commit landing between the two reads
  looked like a rollback, and a concurrency test failed intermittently (`anchor_log_behind`). Readers now retry a mismatch a bounded number of times
  and accept only a view in which the log and the anchor agree. A real mismatch still refuses after the last attempt.
- The first version put `CREATE TABLE` and a SQLite anchor in shipped code. The repository's DDL-boundary test caught it. The anchor is now
  PostgreSQL-only in shipped code, and the test anchor lives in the test directory.
- Adding migration `0004` changed the expected migration count from 3 to 4 (`EXPECTED_SQLX_MIGRATION_COUNT`, and the two docs that state it).
- The first PostgreSQL anchor reader used a 30-second pool acquire timeout. An unreachable anchor now refuses within 5 seconds.

### Residual threat (not defended by this code)

Simultaneous compromise of PostgreSQL write access and the trust file lets an attacker rewrite the anchor, replace the log, and substitute the
roots. The registry code cannot detect that, because both independent checks are then under the attacker's control. The runbook lists the
controls that have to sit outside this code: change control and an out-of-band hash of the trust file, restricted and audited write access to
the anchor table, and an off-host copy of the head hash. A compromised current root can sign within its bound, so root rotation must be prompt.
Operator and execution seeds are protected only by their owners. Timestamps are still signer claims.

### Python test counts and environment

The active environment's editable `aigov_py` pointed at another checkout (`verdict-scratch/staging/python`, which has no `trusted`
package). Child processes spawned by the lifecycle tests did not get the path from `conftest.py`, and 12 tests failed on that first run.
The suite now runs in an isolated environment (`~/verdict-scratch/iso-venv`, created with the framework Python 3.12,
a non-editable install of this tree with `.[dev,agent-reference,runs-postgres]` plus `openai-agents` and `cryptography`, as in the workflows).
Tests run with the in-repo package on `PYTHONPATH` so child processes use the same code.

Final counts on this tree (format v2):

| Configuration | passed | skipped | failed |
|---|---|---|---|
| PostgreSQL 18 (local, destructive flag, registry anchor URL), agent extras, release binary | 1295 | 40 | 0 |

The skips are environmental: 13 need the `aigov-core:test` image, and the rest need live identity providers, Sigstore, or a bundle. Earlier
counts in this report (1222 passed / 61 skipped in the first report, 1181 / 60 and 1214 / 77 without a database, 1251 / 40 before the registry
rewrite) were taken under different configurations and are not comparable with this one.

### Verification on this tree

- Rust `cargo test --locked -- --include-ignored` with PostgreSQL (`AIGOV_TEST_PG_ADMIN_URL`, `AIGOV_TEST_PG_AUTH=1`,
  `AIGOV_PG_TEST_DESTRUCTIVE=1`, `AIGOV_TEST_REGISTRY_PG_URL`, `GOVAI_DATABASE_URL`): 413 passed, 0 failed.
- Python: 1295 passed, 0 failed (above). Registry suites: attack matrix 22, key registry 25, operator CLI 9, authorization 9, rotation
  regressions 6, migration 8, fixture 3, PostgreSQL anchor 7.
- Service-backed reference tests (27) against a release Core on PostgreSQL: all passed.
- Customer pilot (synthetic data, release Core on PostgreSQL): all checks passed, no failing rows.
- `make gate` and the CI make targets (governance, reconstructible demo, packaging, observability, lineage, core-runtime examples, reference
  integrations): passed. `scripts/downstream_python_consumption_smoke.py` and the portable-evidence tests: passed.
- SDK wheel built (20 trusted modules; no example or reference code), installed into a clean venv, `trusted_sdk_downstream_check.py offline`:
  passed.

Disk space stayed above 40 GiB free during the run.

## Not run in this change

Not run, so not claimed as passing: Acme Finance validation, the container build and test (the `aigov-core:test` image is not built,
so 13 Python tests skip), and the security harness. The customer pilot, the reference-agent live tests, the wheel check, and the
PostgreSQL-backed Rust and Python tests were run in the follow-up below.

## Evaluation gate

Passes when: OIDC/JWT verification enforces issuer, audience, signature, time claims, and algorithm; identity mapping cannot give a
workload the approver role through any claim shape; API-key compatibility is preserved with no fallback after a JWT failure; key
purposes are separated; the registry is verified against pinned roots and an independent anchor, so a writer of the log file can neither
forge nor roll back history (see the follow-up, and its residual threat); rotation keeps historical evidence verifiable and does not
reset replay or policy-revision state; compromise yields uncertain or untrusted verdicts and refuses outstanding authorizations;
signers never expose key material and fail closed; and the local suites, the live checks, the negative controls against staging, and
`make gate` pass. These hold for the tree recorded above, subject to CI on the final HEAD. The "Not run" suites above are not covered.

## Human approval gate

Not approved for production by this report. Before production use, the owners must: review the OIDC rule configuration for each
tenant, since a mistake there is the main way to grant approval to a workload; set up the controls for the residual threat (trust-file
change control with an out-of-band hash, restricted and audited write access to the anchor, an off-host head-hash copy); decide the JWKS
cache bounds for each identity provider; and run the "Not run" suites. Issue #501 remains open and is not addressed here. Merging into `staging` is a separate
decision, and this report does not make it.
