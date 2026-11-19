# AIGov staging-equivalent API E2E audit — 2026-11-19

## Scope

PR #440 (`feat/staging-e2e-tests` → `staging`) adds `python/tests/test_staging_e2e.py`. This tests an isolated instance of the real Rust `aigov_audit` binary configured with `AIGOV_ENVIRONMENT=staging`, a temporary file ledger and ephemeral API credentials. It is **not** an end-to-end test of the deployed govbase.dev staging environment, OAuth providers, production tenant activation or database persistence.

Source: https://github.com/AIGovDev/aigov-core/pull/440

## Evaluation gate

- Source change reviewed: `python/tests/test_staging_e2e.py` (18 test cases).
- Author-reported local run before this report: 17 passed, 1 skipped. This report does not claim to have independently reproduced that local run.
- Existing PR #440 CI at commit `e8f1022cf081243ac5220788023a22aa5f74a245`: `aigov-ci`, `python-aigov`, `security-scan`, `supply-chain-audit`, `CLA v2 shadow tests`, `PR branch policy`, and `oss-developer-experience` succeeded. `compliance/report_gate` failed because no audit report was included, cascading into dependent compliance jobs.
- Re-run all PR CI after adding this report; a successful final run must be observed before merge.
- Tenant isolation test may skip when a second tenant credential is not provided. More importantly, the current test checks that each tenant can submit evidence, **not** that one tenant cannot retrieve the other's evidence. It should not be treated as proof of isolation.
- `test_compliance_summary_returns_run` accepts HTTP 404 as success, `test_metrics_endpoint_accessible` accepts HTTP 404, and concurrency accepts 409 on some requests. These are smoke tests, not evidence that compliance retrieval, metrics or full concurrent write success is implemented.
- Running with a pre-existing external `AIGOV_TEST_BASE_URL` skips unavailable infrastructure; do not interpret skipped tests as passing staging verification.

## Human approval gate

- Human code-review and merge authorization: **PENDING**. Do not merge until required checks pass and the maintainer reviews the E2E coverage limitations.
- Live staging OAuth, legal acceptance, tenant activation, two-tenant negative authorization tests and real database audit readback: **NOT VERIFIED**; require authorized test identities and environment access.
- No production data was changed during report preparation.

## Security and limitations

- Credentials in the added test harness are generated at runtime for the local instance, not hardcoded as real secrets.
- The test harness uses a localhost port selected randomly from a fixed range; a free-port reservation would reduce flaky address collisions.
- The isolated fixture sets `AIGOV_POLICY_STRICT=false` while loading staging policy: policy parity with deployed staging must be checked before calling this environment production-equivalent.
- A future follow-up should assert tenant-cross-read/deny paths with two keys and use exact expected response codes instead of accepting 404 for behavior the test claims to verify.

## Recommendation

**CONDITIONAL GO for merging a test harness only** after CI and maintainer approval. **NO-GO for claiming deployed staging E2E or production release readiness** based solely on these tests.
