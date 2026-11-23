# Authentication, authorization and tenant isolation — 2026-11-23

## Scope

Rust HTTP runtime `aigov_audit`, Python SDK clients, PostgreSQL-backed key store, and tenant-scoped ledgers. Live Supabase/OAuth was assessed separately (section 6).

## 1. Architecture (verified in code)

**Authentication of protected routes:** API-key bearer tokens only.

- `rust/src/govai_api.rs::build_router`: the ledger routes (`/evidence`, `/bundle*`, `/compliance-summary*`, `/api/export/{run_id}`, `/verify*`) are the only ones wrapped in `gate_audit_routes_with_state`. The other routes (`/`, `/health`, `/ready`, `/status`, `/metrics`) are open.
- `rust/src/audit_api_key.rs::gate_audit_routes_with_state`:
  1. Reads `Authorization: Bearer <token>`.
  2. Missing or unknown token returns 401 (`MISSING_API_KEY` / `INVALID_API_KEY`).
  3. Resolves the tenant with `resolve_ledger_tenant_id_for_bearer` (env map, hosted hash map, runtime map) or `bearer_token_is_authorized` (database).
  4. Inserts `ResolvedLedgerTenant` into the request extensions for the handler.
- Tenant identity: derived only from the key, never from headers. `rust/src/tenant_api_keys.rs::resolve_ledger_tenant_for_bearer` checks the env map first, then `lookup_tenant_by_key_hash`.
- Database: `public.govai_issued_api_keys` stores SHA-256 fingerprints only. Lookup is `where key_hash = $1 and revoked_at is null` (parameterized, `sqlx::query_as`).
- Ledger isolation: one JSONL file per tenant. `rust/src/project.rs::resolve_ledger_path` (sanitized tenant segment). Handlers call `resolve_tenant` and use that tenant's ledger path.
- Fail behavior: database error in key lookup returns `unknown_api_key` (401), and `bearer_token_is_authorized` returns false on error. Fail closed.

**JWT (Supabase):** `rust/src/auth.rs` (`require_user`, `get_jwks`, `pick_decoding_key`, `rs256_validation`) implements RS256-only verification, `exp` and `iss` checks, and a 300-second JWKS cache. **No route calls `require_user`** (`grep` across `rust/src`). In this runtime, JWTs are never accepted for any endpoint.

**Administrative surface:** `issue_api_key`, `revoke_api_key`, `rotate_api_key` (`rust/src/tenant_api_keys.rs`) have no HTTP route. Only `rotate_api_key` calls the other two, and nothing calls `rotate_api_key` over HTTP.

**Python SDK:** `python/govai/client.py` sends the bearer token and no tenant identifier. Tenant identity is enforced by the server, so the SDK cannot select a tenant.

## 2. Endpoint coverage

| Endpoint | Auth | Tenant source | Enforcement point | DB scoping | Failure |
|----------|------|---------------|-------------------|-----------|---------|
| `POST /evidence` | API key | key | `gate_audit_routes_with_state` | per-tenant ledger file | 401 |
| `GET /bundle`, `/bundle/{run_id}` | API key | key | gate + `resolve_tenant` | per-tenant ledger file | 401; unknown run 404 `run_not_found` |
| `GET /bundle-hash*` | API key | key | gate | per-tenant ledger file | 401 / 404 |
| `GET /compliance-summary*` | API key | key | gate | per-tenant ledger file | 401 / 404 |
| `GET /api/export/{run_id}` | API key | key | gate | per-tenant ledger file | 401 / 404 |
| `GET /verify`, `/verify/{run_id}` | API key | key | gate | per-tenant ledger file | 401 / 404 |
| `/`, `/health`, `/ready` | none | — | — | — | returns component booleans only |
| `/status` | none | — | — | — | configuration summary (see finding F2) |
| `/metrics` | none | — | — | — | counters with normalized paths; no tenant or key labels |

No endpoint relies on a client-supplied tenant ID. `x-govai-project` is read only for usage accounting (`project::usage_tenant_id`), which has no HTTP caller in this runtime.

## 3. Threat model results

| Scenario | Result | Evidence |
|----------|--------|----------|
| Missing auth | 401 on all ledger routes | `tests/tenant_isolation_http.rs` (missing header) |
| Invalid, empty, or Basic credentials | 401 | same test |
| JWT-shaped token on a ledger route | 401 (JWTs not accepted) | same test |
| Truncated key | 401 | same test |
| Tenant A reads tenant B run (9 routes) | 404 `run_not_found` | `tests/tenant_isolation_http.rs`, `tests/db_issued_keys_pg.rs` |
| Tenant B writes under tenant A run ID | Stored in tenant B ledger only; tenant A bundle does not include it | `tests/tenant_isolation_http.rs` |
| `x-govai-project` spoofing | Tenant unchanged (`audit_log__tenant-b.jsonl`) | `tests/tenant_isolation_http.rs` |
| Revoked issued key | 401 after revoke, other key still works | `tests/db_issued_keys_pg.rs` (PostgreSQL) |
| Cross-team revoke | Rejected (returns false, key still works) | `tests/db_issued_keys_pg.rs` |
| Ledger file name collision (`team.a` vs `team_a`) | **Demonstrated leak, fixed (F1)** | probe reproduced: tenant `team_a` read `team.a` evidence over HTTP |
| Algorithm confusion (HS256 with RS256 policy) | Rejected | `rust/src/auth.rs` tests (`hs256_token_is_rejected_by_rs256_policy`) |
| Expired JWT, wrong issuer | Rejected | `rust/src/auth.rs` tests |
| Missing tenant claim, forged claims | Not applicable: no route accepts JWT | section 1 |
| Privilege escalation to admin | No admin HTTP route | section 1 |
| Unauthenticated status information disclosure | **Demonstrated, fixed (F2)** | `tests/tenant_isolation_http.rs` fails on the old code |
| Confused deputy via service credentials | Theoretical in the runtime; **real risk in `python/aigov_py/supabase_db.py`** (see B2) | code review |
| Fail-open on provider outage | JWKS: no stale fallback, fails closed (unused path). DB key lookup: error returns 401 | `rust/src/auth.rs::get_jwks`, `rust/src/tenant_api_keys.rs` |

## 4. Confirmed vulnerabilities and fixes

**F1 — Tenant ledger collision (cross-tenant leak). Demonstrated; fixed.**
- Ledger file names come from the tenant ID after mapping every character outside `[A-Za-z0-9_-]` to `_` (`project::sanitize_project_segment`). `team.a` and `team_a` therefore share `audit_log__team_a.jsonl`.
- Probe through the real HTTP API: tenant `team.a` ingested an event; tenant `team_a` read it back with 200.
- Fix: `audit_api_key::check_tenant_ledger_collisions` refuses startup in every environment when two distinct tenant IDs share a segment. The error names the two tenant IDs, never a key. `audit_api_key::validate_issued_tenant_id` restricts database-issued tenant IDs to `[A-Za-z0-9_-]{1,128}`, enforced in `tenant_api_keys::issue_api_key`.
- Backward compatibility: configurations without collisions are unchanged. Existing ledger files are not renamed. A deployment that already has colliding tenant IDs will fail to start and must rename one tenant. This is a deliberate, documented change.
- Regression tests: `tests/tenant_collision_startup.rs`, plus unit tests in `audit_api_key.rs`.

**F2 — Unauthenticated status leaked absolute policy path. Demonstrated; fixed.**
- `runtime_diagnostics::configuration_block` returned `policy_source.path` unredacted, while the other path fields are redacted. With `AIGOV_POLICY_FILE` set to an absolute path, `/status` disclosed the server filesystem layout to anonymous callers.
- Fix: the field now uses `redact_path_label`.
- Regression test: `tests/tenant_isolation_http.rs` checks `/status` for the absolute path, the ledger directory, and API keys. It fails on the previous code and passes with the fix.

**F3 — Issued tenant IDs could collide with each other (preventive).** Fixed by the same validation as F1.

## 5. Test results

| Suite | Result |
|-------|--------|
| Rust `cargo test --locked` with the PostgreSQL auth test opted in | 191 passed, 0 failed, 0 ignored |
| Rust, new tenant-isolation HTTP test (`tests/tenant_isolation_http.rs`) | 1 passed (positive controls, 9 cross-tenant reads, 5 auth-failure cases, spoofing, status leak) |
| Rust, startup collision test (`tests/tenant_collision_startup.rs`) | 1 passed |
| Rust, PostgreSQL issued-key test (`tests/db_issued_keys_pg.rs`, opt-in `AIGOV_TEST_PG_AUTH=1`, isolated database `aigov_integration` on a local container) | 1 passed |
| Rust, audit-key unit tests | 12 passed (3 new) |
| Python full suite, no database | 937 passed, 84 skipped |
| `make` gates (8 targets) | all exit 0 |
| CLA workflow guard, report gate | PASS |
| `clippy` on changed files | 0 new findings (crate-wide pre-existing lints unchanged) |

Without the opt-in, `tests/db_issued_keys_pg.rs` prints "NOT RUN" and returns. That is a skip, not evidence. The opt-in run above is the evidence.

## 6. Live Supabase/OAuth status

**Not run. Not implemented as a harness.** Reason: no runtime path in this repository validates Supabase JWTs. `require_user` has no callers, so an OAuth test would exercise nothing that ships. Building a live harness now would create test code without a product path. The decision is recorded as blocker B1. No credentials were used, and none were invented.

## 7. Remaining blockers

- **B1 — Supabase JWT path is dead code.** Decide whether a hosted console will use Supabase JWTs. If yes, wire `require_user` to a route and add a live Supabase test. If no, delete the module. The JWKS path also has unfixed issues: an unknown `kid` never triggers a refresh, so a rotated key is rejected for up to 300 seconds, and `reqwest::get` has no timeout.
- **B2 — Operator run persistence uses the service-role key without a tenant column.** `python/aigov_py/supabase_db.py` and `python/aigov_py/ingest_run.py` upsert `runs` by `id = run_id` with `SUPABASE_SERVICE_ROLE_KEY`, which bypasses row-level security. The row has no tenant field, so any holder of that key can overwrite any run. The schema lives in Supabase, not in this repository, so I could not add tenant scoping here. Reachable only through `make ingest-run` (operator-run), not the API.
- **B3 — Residual cross-source collision.** Startup checks collisions among env-map tenants. A database-issued tenant can still collide with an env-map tenant that uses characters outside `[A-Za-z0-9_-]`. Mitigation: keep env-map tenant IDs in the safe set. A stronger fix needs an injective ledger naming scheme and a migration of existing files.
- **B4 — No live identity-provider test exists** (section 6).

## Evaluation gate

Passes when the Rust suite (with the PostgreSQL auth test opted in), the Python suite, and the `make` gates pass on the PR head, and when each fix has a regression test that fails on the previous behavior. F2 and F1 were confirmed to fail against the previous behavior (section 4).

## Human approval gate

Not approved for production by this report.

- Requires your decision: B1 (keep or remove the Supabase JWT path), and B2 (operator run persistence — tenant scoping in the Supabase schema, or remove the service-role path).
- Deployment note for F1: any deployment whose key map has tenant IDs that differ only in characters outside `[A-Za-z0-9_-]` must rename one tenant before upgrading. The service refuses to start otherwise.
- Production remains NO-GO until B2 is resolved or the operator path is removed from production procedures, and the production key map has been reviewed.
