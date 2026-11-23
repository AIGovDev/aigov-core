# Release-readiness audit — AIGov Core — 2026-11-23

## Scope

Final production release-readiness audit after PR #483 and PR #484 merged into `staging`. No new features, no component changes, no CLA workflow changes. Requirement status uses VERIFIED, FIXED, BLOCKED (cannot be verified in this environment), or UNVERIFIED (verified only partly).

## Requirements

| # | Requirement | Status | Evidence |
|---|-------------|--------|----------|
| 1 | Staging contains the PR #483 and #484 security fixes | VERIFIED | JWT: `rust/Cargo.toml` `jsonwebtoken` 12 with `aws_lc_rs`; `rs256_validation()` and tests in `rust/src/auth.rs`. PG guard: `python/tests/_pg_safety.py`, `AIGOV_PG_TEST_DESTRUCTIVE` in the nightly, release, and Postgres workflows. Client 404 contract: `python/govai/client.py`. Asymmetric KMS and signing (Pass 12): `benchmarks/agent-verification/` only (see requirement 3). |
| 2 | Production startup refuses invalid KMS, authorization, or audit configuration | FIXED with one open gap | Real binary startup matrix (below). Fixes in this PR: allowlisted keys without tenant mapping are refused in staging and prod; a configured immutable backend, or `GOVAI_IMMUTABLE_REQUIRED` without one, is refused at startup. Open gap: an unset `AIGOV_ENVIRONMENT` silently runs as `dev`. KMS is not part of the shipped startup path. |
| 3 | Verify the external KMS integration (Ed25519, no key export) | BLOCKED | The documented Vercel KMS API is not the one `VercelKMSProvider` assumes. Documented sign endpoint: `POST https://kms.vercel.com/v1/kms/issuers/{issuerId}/sign/message`, body `{"message": base64}`, response `signature` standard base64. Documented JWKS: `https://kms.vercel.com/<issuerId>/jwks.json`. The code uses `POST {base}/v1/sign` and `/.well-known/jwks.json`, so it is wrong. Ed25519 and the JWK `crv` value are not stated in the documentation. No export endpoint is documented, and none is claimed. The docstring is corrected in this PR to say the shape is unverified. |
| 4 | Live Supabase/OAuth and tenant-provisioning E2E | BLOCKED | No Supabase, OAuth, or Google/GitHub credentials exist in this environment. `test_f1_blocked_real_oauth_callback` and `test_f1_blocked_tenant_provisioning_requires_db` are explicit skips with no body. No mocks substitute for live evidence. |
| 5 | Sigstore bundle integrity and identity against a trusted policy | BLOCKED | No Sigstore bundle, no identity, and `cosign`/`rekor-cli` are not installed. The test `test_sigstore_verify_api_smoke` skips for these reasons. |
| 6 | PostgreSQL backup and restore on an isolated production-like database | VERIFIED (isolated, not production) | Local container `aigov_prodlike_test` migrated by the release binary, populated with synthetic rows. `pg_dump -Fc` produced `prodlike-202611231309.dump`, 5,956 bytes, SHA-256 `161e8de1dba1e175c7b3c7e11a499da7dd2c4939badb9a96a3e40b2d16dda560`. Restore into `aigov_restore_test` gave identical migration rows (2 of 2, same checksums) and identical usage rows (50, sum 1275). The release binary started against the restored database with `/ready` 200 and no re-migration. Production backup and restore are not rehearsed. |
| 7 | Resolve `GOVAI_API_KEYS_JSON` versus `GOVAI_API_KEYS` inconsistencies | FIXED | Startup matrix below. `validate_api_key_allowlist_consistency` now checks both directions in staging and prod: every mapped key must be allowlisted, and every allowlisted key must have a tenant. Before the fix, an allowlist without a tenant map started in prod and then returned `TENANT_RESOLUTION_FAILED` on every ledger read. Two new unit tests. |
| 8 | Regression, security, and release checks | VERIFIED (see below) | Results below, with skips. |

## Startup matrix (real `aigov_audit` binary, debug build from this branch)

| Case | Configuration | Result |
|------|---------------|--------|
| A | prod, JSON key not in allowlist | refused: fingerprint listed, raw key not logged |
| B | prod, consistent keys, DB up | started; `/ready` 200; no bearer on `/evidence` 401; bad bearer 401 |
| C | prod, malformed `GOVAI_API_KEYS_JSON` | refused |
| D | `AIGOV_ENVIRONMENT=production-eu` | refused (invalid value) |
| E | staging, JSON key not in allowlist | refused |
| F | unset environment (dev), mismatch | started with warning only (dev by design) |
| G | prod, allowlist with no tenant map | refused after fix (started before fix, then 401/`TENANT_RESOLUTION_FAILED`) |
| H | prod, JSON map with no allowlist | refused (orphan keys, unchanged behavior) |
| I | prod, `GOVAI_IMMUTABLE_REQUIRED=true`, no backend | refused after fix (started before fix) |
| J | prod, ledger directory `/dev/null/ledger` | refused |
| K | prod, `GOVAI_IMMUTABLE_BACKEND=aws_s3_object_lock` | refused after fix: adapter not wired (started before fix) |
| L | prod config against restored database | started; `/ready` 200 |

## Open gap

- **Unset `AIGOV_ENVIRONMENT` defaults to `dev`.** A production deployment that omits the variable skips every staging and prod fail-fast check (case F). Deployment configuration must set `AIGOV_ENVIRONMENT=prod`. The Dockerfile does not set it. This is not changed in this PR, because changing the default would affect dev and test harnesses. It is an owner decision.

## Regression results (committed tree plus this PR's changes)

| Suite | Result |
|-------|--------|
| Rust `cargo test --locked` with isolated PostgreSQL | 176 passed, 0 failed, 0 ignored |
| `cargo audit` on current lock | exit 0, 1 allowed warning (`chrono`) |
| Python, no database | 972 passed, 38 skipped |
| Python, isolated PostgreSQL, opt-in | 1006 passed, 4 skipped |
| CI `make` gates (8 targets) | all exit 0 |
| CLA regression tests (`test_cla_v2_*`) | 48 OK, not modified |
| CLA workflow security guard | PASS |
| Report gate | PASS |

Skipped in the PostgreSQL run:

- `test_f1_blocked_real_oauth_callback` (live OAuth, BLOCKED)
- `test_f1_blocked_tenant_provisioning_requires_db` (live Supabase, BLOCKED)
- `test_sigstore_verify_api_smoke` (real bundle and identity, BLOCKED)
- `test_deterministic_orchestrator` `mcnemar_F_vs_G` (report artifact not present)

## Evaluation gate

Passes when the Rust suite, the Python suites (with and without PostgreSQL), the make gates, `cargo audit`, and the CLA regression suite pass on the PR head. The results above come from local runs on this tree. CI results are on the PR.

## Human approval gate

Not approved for production by this report.

- **Staging:** GO for review and merge, once PR CI is green. The merge is the owner's decision.
- **Production:** NO-GO. The following must be complete first:
  - `AIGOV_ENVIRONMENT=prod` set in production configuration, and the open default-to-dev gap resolved or accepted by the owner;
  - requirement 3 resolved: a verified Vercel KMS integration (or another KMS), with Ed25519 support and no key export confirmed, and the asymmetric signing path wired into the shipped runtime (currently only in `benchmarks/`);
  - requirement 4 run against a live Supabase and OAuth environment;
  - requirement 5 run with a real Sigstore bundle and a trusted identity policy;
  - a production backup and restore rehearsal, performed by the operator with production access;
  - the jsonwebtoken provider fix is present in whatever build is promoted;
  - the deployment `GOVAI_API_KEYS` and `GOVAI_API_KEYS_JSON` values are reviewed, with every allowlisted key mapped to a tenant.
