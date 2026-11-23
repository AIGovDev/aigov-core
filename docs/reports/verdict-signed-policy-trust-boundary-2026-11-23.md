# Signed verdict policy trust boundary — 2026-11-23

## Scope and evidence

PR #492 changes production verdict configuration to use an Ed25519-verified policy bundle as its sole trusted configuration source. It modifies Rust startup and verdict evaluation, Python policy-bundle signing, and associated Rust/Python regression tests. This report accompanies the core changes to satisfy the repository's required compliance report gate.

## Trust boundary

- The production runtime requires a signed policy bundle and a configured public-key trust store. It does not need a private signing key.
- Production startup refuses unsigned `AIGOV_POLICY_FILE`, `AIGOV_ALLOW_UNSIGNED_POLICY_FILE`, and the `AIGOV_APPROVER_ALLOWLIST` override rather than silently accepting unsigned verdict configuration.
- Policy-bundle signature record version 2 binds document content and signer/issuer/time metadata; the verifier checks signing key trust, digest consistency and expiry.
- Bundle contents are constrained where the current runtime does not implement the corresponding semantics: unresolved inheritance, unevaluated rule conditions, non-global selectors and missing approver allowlist gates are rejected.
- Staging retains a documented explicit unsigned-policy opt-in for compatibility. Production does not.

## Evaluation gate

The production verdict uses the verified policy bundle's explicit evaluation requirements; a legacy unsigned `require_passed_evaluation_for_promotion` flag does not control production behavior after migration. Operators must encode the intended event-type evaluation gate in the signed bundle and verify both a passing evaluation and a blocked or missing evaluation through the signed-bundle HTTP verdict tests before promotion. The proposed PR's tests do not substitute for live deployment configuration validation.

## Human approval gate

The signed bundle must explicitly carry the `human_approved` rule and a non-empty `requires_approver_allowlist` gate. Production rejects `AIGOV_APPROVER_ALLOWLIST` as an unsigned environment override; operators must migrate the allowlist into the signed bundle and test both authorized and unauthorized approvers. Missing or malformed approver gates fail closed at startup in the scenario tests.

## Demonstrated behavior and regression coverage

The changes add scenario tests in `rust/tests/tb_*.rs`, including production startup without a bundle, unsigned override refusal, invalid and expired signatures, untrusted keys, modified policy identifiers and rules, and a positive HTTP verdict path using a signed bundle. Python tests cover v2 signing and tampering in `python/tests/test_policy_bundle_v2.py` and `python/tests/test_cli_signing_key_input.py`.

These are local integration and regression tests, **not** proof of a live production deployment. Some scenario tests can fail on older code due to a missing legacy policy file; this is not independent evidence of each attack path. The unsigned-policy opt-in is the specifically identified exploitable old path.

## Validation

Final locally reported results from the PR implementation session:

- Rust suite without PostgreSQL: **234 passed, 0 failed, 0 ignored**.
- Rust suite with isolated PostgreSQL opt-in: **234 passed, 0 failed, 0 ignored**.
- Python suite without database: **1,036 passed, 41 skipped**.
- Python suite with isolated PostgreSQL opt-in: **1,073 passed, 4 skipped**.
- `make gate`: exit 0.

Four live-service tests remained skipped; no live OAuth, tenant provisioning, or production deployment was verified. CI results must be evaluated for the final pushed commit independently.

## Compatibility and migration

This is a **breaking startup requirement** for deployments previously relying on unsigned policy files. Before promoting a new image, operators must translate legacy verdict flags to the signed policy-bundle gates, sign a production bundle offline, configure `AIGOV_POLICY_TRUST_ED25519_JSON` and `AIGOV_POLICY_BUNDLE_FILE`, and validate startup and expected verdicts in a safe environment. No production configuration or data is migrated by this PR.

See `docs/operations/policy-signing.md` for key custody, signing commands, explicit bundle contract, key rotation and signed rollback guidance. An old, unexpired signed bundle may still be replayed; monotonic version enforcement is not implemented.

## Remaining gaps and decision

**STAGING:** GO for code review/CI merge once required checks are green; operational readiness requires a correctly signed staging policy.

**PRODUCTION:** NO-GO pending signed configuration and trust-store provisioning, migration validation, and the previously recorded live integration / backup-restore prerequisites.

No paid resources were provisioned, no production credentials accessed, no deployment performed, and no PR merge performed.
