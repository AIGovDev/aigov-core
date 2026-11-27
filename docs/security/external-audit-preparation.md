# Independent security audit preparation

**Prepared:** 2026-11-27  
**Purpose:** scope and evidence package for a future independent review.  
**Status:** internal preparation; no external audit has been commissioned or completed.

## Product boundary and architecture

AIGov Core is an AGPL-3.0 Rust audit runtime with Python tooling and integration examples. The Rust service accepts evidence, maps authenticated principals to tenants, appends ledger records, applies configured policy, and projects run state. Python tooling builds and verifies exports and signed bundles, manages some authorization and key-registry workflows, and supplies SDKs and examples. PostgreSQL-backed policy and key-registry anchors are optional deployment components. The hosted GovBase platform, website, and customer infrastructure are outside the Core repository assurance boundary.

The auditor should trace these boundaries from code and deployed configuration, not infer them from diagrams:

1. Caller and agent to HTTP authentication and authorization.
2. Authentication principal to server-side tenant mapping.
3. Evidence and policy input to ledger append and verdict projection.
4. Key and policy trust roots to authorization, signatures, replay protection, and revocation.
5. Core process to filesystem, PostgreSQL, container, CI, package and release supply chains.
6. Export producer to offline export and signed-bundle verifier.

Architecture references: ARCHITECTURE.md, docs/architecture/README.md, docs/trust-model.md, and docs/security/security-overview.md.

## Trust and cryptographic assumptions

- SHA-256 chain verification establishes consistency relative to the supplied records and head. It does not prove the truth, completeness, origin, trusted time, signer identity, occurrence of an external action, or regulatory compliance.
- Ed25519 signatures are only as trustworthy as the independently provisioned public-key roots and the security of their private-key custody. A signature authenticates bytes under a key; it does not establish that the signed statement is true.
- OIDC/JWT verification depends on issuer, audience, JWKS and claim configuration. JWKS outages and configured cache periods affect when key changes are observed.
- PostgreSQL anchors detect log rollback only while the database anchor and separately protected trust roots remain trustworthy. Compromise of both trust domains can defeat this assumption.
- Local seed files and operator credentials remain deployment-sensitive. The repository does not provide an external HSM/KMS integration whose production behavior has been independently validated.
- Timestamps are claims unless bound to an external trusted timestamp source.

## Invariant-to-evidence crosswalk

Paths below identify current implementation and regression evidence. A listed test is internal evidence, not proof that every configuration or deployment is safe.

| Security invariant | Implementation | Existing regression/adversarial evidence | External review question or gap |
|---|---|---|---|
| Evidence chain recomputes and rejects changed records | rust/src/verify_chain.rs, rust/src/ledger_storage.rs, python/aigov_py/ledger.py, python/aigov_py/audit_export.py | rust/tests/long_ledger_benchmark.rs; python/tests/test_audit_export_foundation.py; python/tests/test_hf_space_package.py; examples/reconstructible-agent-demo/viewer/test_hash_chain.mjs | Verify canonicalization, truncation, duplicate IDs, malformed records, export-head trust, and cross-language agreement. The browser demo is not a signed-bundle verifier. |
| Verdict derives from ledger and configured policy; missing or invalid prerequisites fail closed | rust/src/policy.rs, rust/src/policy_engine.rs, rust/src/replay_projection.rs, rust/src/govai_api.rs | rust/tests/tb_*; rust/tests/approval_before_authorization.rs; rust/tests/runtime_core_integration.rs; python/tests/test_policy_loader.py; python/tests/test_staging_policy_verify.py | Test signed-bundle and runtime configuration combinations, policy downgrade and concurrent policy changes. Cross-process key/policy issuance combinations remain unverified in the latest readiness report. |
| Approval is bound to the same run/tool call and cannot be reused | rust/src/govai_api.rs, rust/src/execution_authorization.rs, python/aigov_py/trusted/executor.py, replay-protection modules | rust/tests/approval_before_authorization.rs, rust/tests/tool_approval_gate.rs; python/tests/test_approval_single_use_two_instances.py, python/tests/test_mcp_preexecution_authorization.py | Assess the race between revocation and nonce consumption, distributed locking assumptions, and external side effects after authorization. |
| Authorization is tenant-, action-, resource-, proposal-, and policy-bound; replay is rejected | rust/src/execution_authorization.rs; python/aigov_py/trusted/authorization.py, replay_protection.py | python/tests/test_approval_single_use_two_instances.py, python/tests/test_authorization_registry.py, python/tests/test_mcp_preexecution_authorization.py; PostgreSQL-gated coverage in python/tests/test_postgres_integration.py | In-memory and PostgreSQL implementations have different persistence properties. PostgreSQL tests require a configured database and are not equivalent to an end-to-end multi-host deployment test. |
| Principal identity is authenticated; workload identities cannot act as human approvers | rust/src/auth.rs, rust/src/oidc.rs, rust/src/principals.rs, rust/src/audit_api_key.rs | rust/tests/oidc_gate_http.rs, rust/tests/prod_requires_principals.rs, rust/tests/staging_requires_principals.rs | Hosted IdP claim conventions, external provider behavior, operational JWKS rotation and outage recovery have not been independently reviewed. |
| Key changes are authorized, signed, versioned, replay-resistant and anchored | rust/src/key_registry.rs, rust/src/registry_anchor.rs, python/aigov_py/trusted/keys.py, migration rust/migrations/0004* | rust/tests/registry_anchor_pg.rs, rust/tests/db_issued_keys_pg.rs; python/tests/test_key_registry.py, test_key_rotation_regressions.py, test_authorization_registry.py | Root compromise, backup/restore rollback, operator recovery and live external KMS/HSM flows need review. Some PostgreSQL tests are gated. |
| Tenant data and ledger reads/writes do not cross API-key tenant boundaries | rust/src/tenant_api_keys.rs, rust/src/ledger_storage.rs, API middleware | rust/tests/tenant_isolation_http.rs, tenant_adversarial_ledger.rs, tenant_collision_startup.rs; python/tests/test_tenant_ledger.py, test_ingest_tenant_ownership.py, test_security_isolation.py | Verify every new route, migration, legacy tenant mode, error path and production configuration; test real PostgreSQL role and deployment isolation. |
| Concurrent use cannot silently duplicate a single-use authorization | python/aigov_py/trusted/replay_protection.py, nonce/revocation stores, executor lifecycle store | python/tests/test_approval_single_use_two_instances.py, test_distributed_core_ledger.py, test_executor_lifecycle.py, test_crash_consistency_core.py | A documented atomicity gap remains between consuming a nonce and writing an audit event. Exactly-once external side effects are not promised. Multi-host Core consistency is not a verified deployment profile. |
| Crash recovery does not silently re-run completed work or lose required state | python/aigov_py/trusted/executor.py and lifecycle persistence modules | python/tests/test_crash_consistency_core.py, test_executor_lifecycle.py; Rust two_volume_rollback_pg.rs | Validate realistic filesystem and database failure modes, power-loss durability, restore drills, lease expiry, and version-upgrade recovery. |
| Signed exports and policy bundles reject unknown, malformed, expired or altered signatures | rust/src/audit_export_signing.rs, audit_export_verification.rs, audit_export_bundle.rs, policy_signing.rs, key_registry.rs | rust/tests/export_signature_binding.rs, tb_malformed_signature_refused.rs, tb_unknown_key_refused.rs, tb_expired_v1_refused.rs, tb_expired_v2_refused.rs, tb_identifier_tamper_refused.rs, tb_rule_tamper_refused.rs; Python signing and bundle tests | Review format downgrade, key-purpose separation, canonical serialization, trust-root distribution, certificate/time assumptions, and parser limits. |
| Shipped dependency and release artifacts are screened | .github/workflows/supply-chain-audit.yml, .github/workflows/security-scan.yml, .github/workflows/release-validation.yml, scripts/generate_sbom.py, scripts/release_provenance.py | CI jobs run Cargo Audit, pip-audit, Gitleaks and Trivy; offline local tests cover report generation | A clean scan is point-in-time, not a full supply-chain audit. Current-run results must be checked at the exact commit. Provenance is not necessarily signed; the latest readiness report records incomplete full reproducible-build validation. |

## Known residual risks and limits

1. No independent third-party penetration test, source audit, or attestation is known to have been completed for the current Core head. Internal reviews and test reports are not independent assurance.
2. Cross-process issuance during simultaneous key or policy mutation is not verified in the latest production-readiness report.
3. PostgreSQL persistence of a consumed replay nonce and append of its audit record are not one atomic transaction. A crash can leave an authorization consumed without its audit append; this is fail-closed for replay but creates an evidence gap.
4. Exactly-once execution of external actions is outside the runtime guarantee. Downstream idempotency and reconciliation remain operator responsibilities.
5. Full multi-host ledger consistency and active-active writes are not a supported verified profile; release documentation specifies single-writer limitations.
6. Reproducible builds are incomplete: prior evidence compared a Core crate rebuild in the same target directory, not a full clean rebuild of all dependencies.
7. No trusted timestamp proves when an event or signature was created. Input truth, evidence completeness, runtime behavior, and regulatory compliance cannot be established by the hash chain.
8. Browser viewer limits and safety tests do not replace server-side validation or the Rust signed-export verifier.
9. A dependency scan can miss zero-days, malicious upstream changes, configuration flaws, and vulnerabilities in unscanned build/runtime environments.

Source references include docs/reports/pilot-readiness-closure-2026-11-26.md, docs/reports/identity-key-management-2026-11-26.md, docs/reports/distributed-execution-2026-11-26.md, and docs/reports/aigov-security-audit-2026-11-19.md. Their scopes and tested commits differ; read their own verification sections before relying on a result.

## Proposed independent audit scope and deliverables

**In scope:** Rust HTTP service and ledger; policy and verdict path; authentication, tenant mapping and OIDC; approval/authorization binding and replay protection; key registry and rotation; signed export and policy-bundle parsing; Python authorization/executor lifecycle; PostgreSQL concurrency and crash behavior; CI/release supply chain; deployment defaults and trust boundaries.

**Suggested work:** architecture and threat-model review; manual source review; adversarial tests and fuzzing for parsers, ledger and cryptographic formats; configuration review; multi-process and database fault testing; dependency/build pipeline review; severity-ranked findings with reproductions; remediation retest; public report with sensitive details coordinated through responsible disclosure.

**Out of scope unless separately agreed:** legal certification, proof of real-world action truth, customer-specific infrastructure, model quality, the hosted GovBase SaaS control plane, or a claim that evidence is complete.

Request an independent reviewer to record the exact commit and dependency lockfiles, tool versions, excluded paths, test data, environment assumptions, review dates, findings, remediation status and report publication permissions. Do not announce an audit until there is a signed scope and named reviewer; do not call preparation or a funding request an audit.

## Internal validation checklist before handoff

- [ ] Freeze and record target commit SHA, tags and lockfile hashes.
- [ ] Run the full supported Rust and Python test suites, including database-gated tests on an isolated PostgreSQL service.
- [ ] Run cargo audit, pip-audit, Gitleaks, Trivy, static analysis, license inventory and dependency diff.
- [ ] Run current fuzz targets with reproducible seeds and retain corpus fingerprints.
- [ ] Reconcile every security invariant with tests and note exclusions.
- [ ] Provide a sanitized demo deployment/configuration with no production evidence or credentials.
- [ ] List open issues and known gaps, including multi-host support and nonce/audit atomicity.
- [ ] Agree written scope, independence, fee/funding, confidentiality and publication terms before any paid engagement.

## Assurance status

| Claim | Status |
|---|---|
| Internal adversarial and regression tests exist for many core invariants | Verified in repository; exact current-head run pending |
| Security and dependency workflows are configured | Verified in repository |
| Current-head local cargo audit, pip-audit, Gitleaks, Trivy and Rust tests ran in this environment | Not run: required tools/toolchain and credentials are not present |
| Independent external security review is complete | No evidence found; not complete |
| Audit request/application has been submitted or accepted | Not submitted or accepted |
