# Verdict trust boundary: production decisions from a verified signed bundle — 2026-11-23

## Scope

Closes the gap in which the verdict engine made security-sensitive decisions from an unsigned policy
configuration in production. Builds on the signed-bundle mechanism (Ed25519, `govai.policy.v1`) and
the audit-export v2 binding from `docs/reports/artifact-integrity-supply-chain-2026-11-23.md`. No new
KMS, no CLA workflow changes, no deployment, no production data or credentials.

## 1. Trust boundary (traced)

| Input | Origin | Loaded by | Mutable after startup | Signed | Status before this change |
|-------|--------|-----------|-----------------------|--------|---------------------------|
| Policy bundle (`govai.policy.v1`) | Operator file (`AIGOV_POLICY_BUNDLE_FILE` or `policy.bundle.<env>.json`) | `PolicyStore::load_for_deployment` | No (loaded once into `Arc`) | Ed25519 over document digest | Verified, but signature did not bind signer, creation time or expiry; expiry not enforced; `verdict_rules`, `inherits`, `selectors` accepted and ignored |
| Legacy policy file (`PolicyConfig`) | `AIGOV_POLICY_FILE` / `policy.<env>.json` | `policy_config::load_for_deployment` | No | **No** | Drove export readiness and replay; in production allowed by `AIGOV_ALLOW_UNSIGNED_POLICY_FILE=1` |
| `AIGOV_APPROVER_ALLOWLIST` | Environment | `effective_approver_allowlist` | Environment | No | Overrode the allowlist in production |
| Built-in defaults | Code | `PolicyConfig::default()` | No | n/a | Allowed |

Trust store: `AIGOV_POLICY_TRUST_ED25519_JSON` (issuer id to public keys). Public keys only.

## 2. Vulnerabilities (demonstrated where marked)

| ID | Description | Evidence |
|----|-------------|----------|
| V1 | Production started with an unsigned policy file that controls verdicts when `AIGOV_ALLOW_UNSIGNED_POLICY_FILE=1` | **Demonstrated on previous commit**: `tb_unsigned_optin_prod_refused` starts successfully |
| V2 | Production could not start with a signed bundle alone; it required a legacy file present | **Demonstrated**: `tb_positive_v1_startup` and `tb_positive_v2_startup` fail on previous commit with "no policy file found" |
| V3 | Signature did not cover signer, creation time or expiry | Code review of `verify_ed25519`; v2 digest mismatch test `tb_v2_metadata_tamper_refused` (refused on new code) |
| V4 | Bundle expiry not enforced | `tb_expired_v2_refused` (new code refuses) |
| V5 | Expiry on a legacy (v1) record, which is not covered by the signature | `tb_expired_v1_refused` (new code refuses) |
| V6 | `AIGOV_APPROVER_ALLOWLIST` overrode the signed allowlist in production | `tb_approver_env_refused` (new code refuses) |
| V7 | Bundle declared `verdict_rules`, `inherits`, non-global `selectors`; the build ignores them while the signature vouches for them | `tb_verdict_rules_refused` (new code refuses); selector and inherits rules in `enforce_production_contract` |
| V8 | `human_approved` rule without an approver allowlist gate | `tb_missing_approver_gate_refused` (new code refuses) |

Caveat on the previous-commit results. In the baseline run, most negative scenarios fail on the old
code only because the old code cannot start in production without a legacy file (V2). That shows the
old code does not satisfy those scenarios; it does not, by itself, isolate each individual gap. V1 is
the one clean demonstration of an unsafe production start.

## 3. Contract

Enforced in `rust/src/policy_signing.rs`, `rust/src/policy_store.rs`, and `rust/src/govai_api.rs`:

- **Startup, production:** a verified signed bundle is the only policy source. Refused: no bundle;
  `AIGOV_POLICY_FILE`; `AIGOV_ALLOW_UNSIGNED_POLICY_FILE`; `AIGOV_APPROVER_ALLOWLIST`. No legacy file is read.
- **Signature record, `payload_version: 2`:** signed digest is the canonical JSON of
  `{payload_version, policy_digest_sha256, issuer_id, signer, created_at_utc, expires_at_utc}`.
  Expiry enforced in staging and production. Unknown versions refused.
- **Legacy records (no `payload_version`):** verify against the document digest only; an expiry is refused outside development.
- **Bundle contents, staging and production:** `policy_id` and `version` non-empty; `inherits` empty; `verdict_rules` empty; `selectors.tenants` is `["*"]`; `selectors.environments` contains `"*"` or the deployment environment; each `human_approved` rule has a non-empty `requires_approver_allowlist` gate.
- **Development:** unchanged compatibility path.
- **No bypass:** environment and command-line settings cannot override production checks.

Algorithm downgrade: only `kind: "ed25519"` is accepted, and the version field must be 2 or absent. There is no negotiation. Unsigned overrides after verification are impossible, because the production path does not read the file at all.

## 4. Migration

Documented in `docs/operations/policy-signing.md`:

- Production needs a signed bundle before deployment. An image with only `policy.prod.json` will no longer start.
- Legacy flags map to bundle gates (approver allowlist, risk review, evidence). Legacy flags with no bundle equivalent have no effect in production.
- Existing signed bundles without an expiry still verify. Re-sign with `--expires-at-utc`.

## Evaluation gate

Passes when the Rust suite (with PostgreSQL opted in), the Python suite (with and without PostgreSQL), the scenario tests, and the make gate pass on the pull request head. Results are in section 5.

## 5. Test results (local)

Final code, commit `96c56e4` (branch `verdict/signed-config`).

| Suite | Result |
|-------|--------|
| Rust `cargo test --locked`, no database | 234 passed, 0 failed, 0 ignored |
| Rust `cargo test --locked`, `AIGOV_TEST_PG_AUTH=1` on a disposable PostgreSQL database | 234 passed, 0 failed, 0 ignored |
| Python `pytest python/tests`, no database | 1036 passed, 41 skipped |
| Python `pytest python/tests`, PostgreSQL opted in on a disposable database | 1073 passed, 4 skipped |
| Skips with PostgreSQL | live OAuth and tenant provisioning (BLOCKED), real Sigstore bundle (BLOCKED), `mcnemar_F_vs_G` report artifact |
| Scenario tests `rust/tests/tb_*` on new code | 19 of 19 pass, each asserting the specific refusal reason |
| Scenario tests on previous commit | 18 of 19 fail (the dev control passes), see caveat in section 2 |
| `make gate` | exit 0 |
| `ruff` and `mypy` on changed Python | new code clean; `mypy` no issues |
| `clippy` on changed Rust | no findings in changed or new code |

Skips are not counted as passing. All of this is local evidence. No live staging or production
environment was exercised.

## 6. CI

- The first CI run on the pull request failed in `report_gate`, because core Rust changes require a
  `docs/reports/*.md` report. This file is that report. The other failures (`report_content`,
  `make_verify`, `evidence_pack`, `upload_evidence_packs`) are cascades from `report_gate`.
- CI results after this report is pushed are recorded in the pull request, not in this file.

## 7. Remaining blockers and residual risks

- Replay of a valid, unexpired bundle is not prevented.
- No monotonic version enforcement. An older valid bundle can be deployed deliberately.
- Staging still accepts the unsigned policy file when `AIGOV_ALLOW_UNSIGNED_POLICY_FILE=1` is set. That is a staging-only risk acceptance.
- Key custody is file-based. KMS-backed signing is not implemented.
- Sigstore live verification is still not run (unchanged from the previous report).

## Human approval gate

Not approved for production by this report.

- Requires your decision: whether to accept the breaking change (production requires a signed bundle), and whether staging should move to the same contract.
- Requires your action: produce and sign the production bundle with the production signing key, and place its public key in the trust store, outside this repository.

## 9. Staging and production decision

- **STAGING:** GO, conditional on CI passing on the pull request head and an operator re-signing any existing staging bundle that lacks a valid signature under the v2 contract. Staging bundles must satisfy the production contract.
- **PRODUCTION:** NO-GO. No production signed bundle exists, the production contract has not been exercised against a real bundle, and the human approval gate above is open.

## 10. Exact next action

Wait for CI on the pull request head, fix any failures caused by this change, then have an operator sign the staging bundle with the v2 signer and verify it starts in staging before any production decision.
