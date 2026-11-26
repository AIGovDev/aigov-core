# Staging verification of signed policy bundles — 2026-11-23

## Scope

Establishes reproducible verification of signed Ed25519 v2 policy bundles and the verdict path in
staging, and separates what was verified locally from what requires a deployed staging service. Builds
on `docs/reports/verdict-trust-boundary-2026-11-23.md` (PR #492) and its formatting follow-up (PR #493),
both merged into `staging`.

No production deployment, no secret or variable changes, no changes to `main`, no CLA workflow changes,
no weakening of existing controls.

## 1. Does a real staging environment exist?

No, not in this repository's configuration, as checked on 2026-11-23:

- `gh api .../actions/variables` returns 0 variables; `GOVAI_AUDIT_BASE_URL` (used by the smoke workflow on
  another branch) is not set.
- `gh api .../actions/secrets` returns 0 secrets.
- `gh api .../environments` returns 0 environments.
- The repository contains deployment manifests (`deployments/docker-compose`, `deployments/helm`,
  `deployments/kubernetes`) that set `AIGOV_ENVIRONMENT=staging`, but no record of a running instance.

Live staging verification is therefore **blocked** on infrastructure. Section 7 lists the minimum needed.

## 2. Defect found by the verification

The first local run of the harness against `staging` failed 7 of 14 bundle and startup scenarios. The
cause: in staging, a configured signed bundle was ignored, and startup failed with
`no policy file found for env=staging`. The production fix in PR #492 had not been applied to staging.
Staging could not run a signed-only configuration at all.

Previous claims were wrong on this point. The report for PR #492 gave staging a conditional GO, on the
basis that signed bundles were verified in staging. The Rust test that covered this path only exercised
production.

**Fix in this PR:** when a signed bundle is configured in staging, the legacy policy path is not read,
and `AIGOV_POLICY_FILE`, `AIGOV_ALLOW_UNSIGNED_POLICY_FILE`, and `AIGOV_APPROVER_ALLOWLIST` are refused
(`rust/src/govai_api.rs`, `signed_bundle_configured`, `enforce_signed_bundle_only`). Staging without a
bundle keeps its previous behavior. This is stricter than before, not weaker.

Regression tests: `rust/tests/tb_staging_bundle_starts.rs`, `tb_staging_policy_file_refused.rs`,
`tb_staging_unsigned_override_refused.rs`.

## 3. Negative control

The harness was run against the pre-fix commit (`4dd15b3~1`, the state of `staging` before this PR):

| Run | Local checks passed | Failed |
|-----|---------------------|--------|
| Pre-fix commit | 7 | 7 (all staging bundle startup scenarios) |
| This PR | 27 | 0 |

The failures before the fix were the discriminating result: the harness detects a service that cannot
start with a valid signed bundle.

## 4. Verification harness

`scripts/staging_policy_verify.py` (not committed artifacts; output goes to `artifacts/staging-verify/`,
which is git-ignored).

- Local simulation: a fresh Ed25519 key per run, synthetic policies signed by the production signer, the
  release binary started once per scenario. Only public-key fingerprints are recorded.
- Live checks: infrastructure-level only (health, unauthenticated and invalid-key rejection, authorized
  verdict read). The target must carry a `staging`, `stg`, or `test` token; localhost requires an explicit
  self-test flag, and such a run is not staging evidence.
- Evidence: JSON with schema `govai.staging_policy_verification.v1`, each check labelled with its scope
  and status (`passed`, `failed`, or `blocked`), the git SHA, and the release binary's SHA-256.
- Reproducibility: two consecutive runs produced identical check IDs, scopes, and statuses.

Workflow: `.github/workflows/staging-policy-verify.yml`. The local job runs on pull requests into
`staging`. The live job runs only on manual dispatch, only when `GOVAI_STAGING_BASE_URL` is set, and uses
the `staging` environment. Actions are pinned to the SHAs already used in this repository. The workflow
is not a required check.

## 5. Local verification results

| Check group | Result |
|-------------|--------|
| Bundle loading and trust in staging: valid starts; expired, tampered, untrusted-key, unsigned, missing-file, v1-with-expiry refused | 7 of 7 passed |
| Overrides: unsigned file refused in staging; `AIGOV_POLICY_FILE`, `AIGOV_ALLOW_UNSIGNED_POLICY_FILE`, `AIGOV_APPROVER_ALLOWLIST` refused in production; production without bundle refused; dev unsigned control starts | 6 of 6 passed |
| HTTP: health; unauthenticated ingest and verdict reads 401; unknown run 404; allowed event admitted | 5 of 5 passed |
| Evaluation requirement: promotion refused without evaluation and after a failed one; failed evaluation recorded; admitted after a passed one | 5 of 5 passed |
| Approvals: allowlisted approver admitted; non-allowlisted refused | 2 of 2 passed |
| Verdict summary after the flow | 1 of 1 passed |
| Disposable key fingerprint recorded (private key never written) | 1 of 1 passed |

Total local simulation: **27 passed, 0 failed, 0 blocked**.

Refusals are matched on the specific gate or startup message. The gate code (`evaluation_not_passed`,
`approver_not_allowlisted`) is not returned to clients, so the message is the observable evidence.

## 6. Test results

Run on the final code in this PR.

| Suite | Result |
|-------|--------|
| Rust `cargo test --locked`, no database | 237 passed, 0 failed, 0 ignored |
| Rust `cargo test --locked`, PostgreSQL auth test opted in (throwaway database) | 237 passed, 0 failed, 0 ignored |
| Python `pytest python/tests`, no database | 1053 passed, 41 skipped (all database-gated) |
| Python `pytest python/tests`, PostgreSQL opted in (throwaway database) | 1082 passed, 12 skipped |
| Harness unit tests `python/tests/test_staging_policy_verify.py` | 17 passed |
| Local staging simulation | 27 passed, 0 failed |
| Live staging checks | 4 blocked (not configured), 0 passed, 0 failed |
| `make gate` | passes ("Report gate passed.") |
| `ruff` and `mypy` on changed Python | clean |
| `clippy` on changed Rust | no findings in changed or new code |
| `rustfmt --check` on `govai_api.rs` | 9 diffs, all pre-existing (baseline 9) |

Of the 12 skips in the PostgreSQL Python run, 8 are binary-backed integration tests. They skip when the
database URL is inherited, because the server then fails closed on the empty database with no schema,
which is correct behavior. Run without the URL, they pass (8 passed). The remaining 4 are live-service
items already listed as BLOCKED in earlier reports (live OAuth, live Supabase, a real Sigstore bundle,
and the `mcnemar_F_vs_G` artifact). Skips are not counted as passing.

Live self-test (localhost, labelled as a self-test, not staging evidence): health, both authentication
rejections, and the authorized verdict read all passed against a staging-mode server started by the
harness.

## 7. Minimum infrastructure for live staging verification

1. A deployed AIGov Core service with `AIGOV_ENVIRONMENT=staging`.
2. A hostname with an explicit `staging`, `stg`, or `test` token.
3. The service's signed bundle configured (`AIGOV_POLICY_BUNDLE_FILE` or `policy.bundle.staging.json`) and
   `AIGOV_POLICY_TRUST_ED25519_JSON` listing only staging public keys.
4. A staging API key stored as the secret `GOVAI_STAGING_API_KEY` in the `staging` environment.
5. The repository variable `GOVAI_STAGING_BASE_URL` set to the service's base URL.

Live checks cover infrastructure behavior only. The harness cannot confirm which bundle a deployed
service runs; an operator must confirm the bundle hash out of band.

## 8. Remaining risks

- Live staging has not been verified (blocked, section 7).
- Replay of a valid, unexpired bundle is not prevented.
- No monotonic version enforcement; rollback to an older valid bundle is accepted.
- Key custody is file-based; no KMS.
- Sigstore live verification has not been run.
- Gate refusals do not expose gate codes to clients (observability only).

## 9. Migration requirements

- Staging with a configured signed bundle no longer reads a legacy policy file, and refuses the
  legacy overrides. Any staging deployment that relied on a policy file together with a bundle must
  remove the file and the overrides before upgrading.
- Production requirements are unchanged from PR #492: a signed bundle is required.

## Evaluation gate

Passes when the local staging simulation passes on the PR head, the harness unit tests pass, the Rust
and Python suites (with and without PostgreSQL) pass, `make gate` passes, and every live check is either
passed against a configured staging service or reported as blocked. Section 5 and section 6 record the
local results. The live checks are blocked, so this gate is passed for local evidence only.

## Human approval gate

Not approved for production by this report.

- **STAGING: CONDITIONAL GO for the code.** The staging defect is fixed and covered by tests. Before
  treating staging as verified, an operator must deploy this build to staging with a signed bundle,
  configure the items in section 7, and run the `staging-policy-verify` workflow to produce live evidence.
- **PRODUCTION: NO-GO.** Live staging has not been verified, no production signed bundle exists, and the
  trust store for production has not been set up.
- Requires your decision: whether to accept the stricter staging behavior (refusal of legacy overrides
  when a bundle is configured), and whether to make the `staging-policy-verify` local job a required check.
- Requires an operator action outside this repository: provision a staging deployment and the
  configuration in section 7.
