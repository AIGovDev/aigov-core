# Production hardening audit — 2026-11-23

## Scope

Branch `fix/prod-hardening-pg-guards`, PR to `staging`. Covers destructive Postgres test guards, the `run_not_found` HTTP 404 contract, the jsonwebtoken 12 crypto provider, the sqlx 0.9 upgrade, and the runtime DDL boundary. No CLA files or workflows change.

## Changes

1. Destructive Postgres tests fail closed. `DROP TABLE` runs only with `AIGOV_PG_TEST_DESTRUCTIVE=1`, a local host, and a dedicated test database (`aigov_integration` or a name containing `test`). Nightly, release, and Postgres workflows use an ephemeral `aigov_integration` database.
2. `run_not_found` keeps the server's HTTP 404. The Python client preserves its pre-404 contract for that body. The OpenAPI `GET /bundle` spec documents the 404.
3. jsonwebtoken 12 enables the `aws_lc_rs` crypto provider. Version 12 has no default provider, so every JWT verification panicked before this change. The RS256 policy is extracted into `rs256_validation()`, with tests rejecting HS256, expired tokens, and wrong issuers.
4. Runtime DDL audit. The schema-creating stores are benchmark code and are not shipped. A boundary test blocks DDL and imports in `python/govai` and `python/aigov_py`. See `docs/operations/runtime-schema-ownership.md`.

## Evidence

| Check | Result |
|-------|--------|
| Rust `cargo test --locked`, isolated PostgreSQL | 171 passed, 0 failed, 0 ignored |
| `cargo audit` on the new lockfile | exit 0, one allowed warning (`chrono`, RUSTSEC-2026-0543) |
| Docker image from `rust/Dockerfile` | builds; `/ready` returns 200 against a migrated test database |
| sqlx 0.8 → 0.9 upgrade rehearsal | `origin/main` binary migrates; branch binary starts on the same database; migration checksums identical |
| Python without database | 972 passed, 38 skipped |
| Python with isolated PostgreSQL and opt-in | 1006 passed, 4 skipped |
| PostgreSQL integration file | 33 passed, 0 skipped |
| Staging E2E and F1 real-API tests (release binary) | 26 passed |
| Destructive guard, shared database or missing opt-in | fixture errors; no DROP executed |

Skips in the PostgreSQL run: two require a live Supabase or identity provider (blocked by design), one requires a real Sigstore bundle and identity, and one requires the `mcnemar_F_vs_G` report artifact.

## Evaluation gate

Gate passes when the Rust suite, the Python suite (with and without PostgreSQL), the upgrade rehearsal, and `cargo audit` pass on the PR head. The results above come from local runs on the committed tree. CI results for the PR are recorded on the PR.

## Human approval gate

Not approved for merge or deployment by this report.

- Staging: review and merge of the PR is the owner's decision.
- Production: NO-GO until the following are complete:
  - this change is in production, including the jsonwebtoken provider fix. Any promotion that brings in jsonwebtoken 12 without it panics on every JWT check;
  - live identity-provider and tenant-provisioning E2E have been run in a staging environment;
  - Sigstore verification has been run with a real bundle;
  - a backup and restore of the production database has been rehearsed;
  - the deployment configuration has been checked: the image run logged that `GOVAI_API_KEYS_JSON` contains a key not present in `GOVAI_API_KEYS`.
