# Artifact integrity, verification, and supply-chain provenance — 2026-11-23

## Scope

Evidence and audit-export integrity, policy trust, Sigstore/DSSE verification, the container and release supply chain, and GitHub Actions hardening. CLA workflows are not changed.

## 1. What exists, and what is enforced

| Mechanism | Where | Enforced in a runtime or CI path? |
|-----------|-------|-----------------------------------|
| Hash-chained ledger (`prev_hash` / `record_hash`), non-tail corruption detection | `rust/src/audit_store.rs` | Yes, on read and repair. Tests: `non_tail_corruption_still_fails`, `repair_errors_on_non_tail_corruption`. |
| Evidence events digest (`events_content_sha256`) | `rust/src/bundle.rs::portable_evidence_digest_v1`, `rust/src/audit_export_signing.rs::validate_events_content_sha256` | Yes, recomputed on verification. Tests: `detects_tampered_events_content_sha256`. |
| Ed25519 signatures on audit exports | `rust/src/audit_export_signing.rs`, `python/aigov_py/audit_export_signing.py` | Verification is enforced where it is called. Signing is offline operator tooling (see section 3). |
| Ed25519 signatures on policy bundles | `rust/src/policy_signing.rs`, `rust/src/policy_store.rs` | **Yes**, fail-closed in staging and production (bundle paths only). |
| Policy files controlling verdicts | `rust/src/policy_config.rs` (`legacy_policy`) | **No signature check.** Gap, fixed by a startup gate (section 4). |
| Sigstore/DSSE attestation verification | `python/aigov_py/sigstore_verify.py`, `aigov crypto verify-evidence-pack` | Implemented, but **not invoked by any workflow, runtime, or release path.** Live verification has not been run. |
| `aigov.evidence_attestation.v1` producer | none in repository | **Absent.** The verifier can only check externally produced attestations. |
| Container image provenance, SBOM, build attestations, image signing | none | **Absent.** No workflow generates them, and no publish or distribution step exists to consume them. |
| GitHub Actions: least-privilege permissions, pinned actions, pinned base images | `.github/workflows/`, `Dockerfile`, `rust/Dockerfile` | Partly. Fixed in this PR (section 5). |

## 2. Trust boundaries of production-relevant artifacts

| Artifact | Producer | Verifier | Trust root | Gap before this PR |
|----------|----------|----------|------------|--------------------|
| Audit export (`aigov.audit_export.v1`) | audit service / operator | `verify_audit_export_ed25519_signature` (Rust and Python) | `AIGOV_POLICY_TRUST_ED25519_JSON` (issuer → public key) | Signature did not cover signer, time, expiry, or unsigned fields. Expiry not enforced. |
| Policy bundle (`govai.policy.v1`) | operator | `verify_policy_signatures` | same trust store | None in staging and production bundle paths. |
| Policy file (verdict configuration) | operator | none | none | Unsigned, and it controls verdicts. |
| Sigstore DSSE attestation | external producer (none in repo) | `verify_dsse_bundle` | Sigstore TUF root, identity and issuer | Not exercised by any workflow. |
| Container image (`Dockerfile`) | CI build | none | none | Base images were mutable tags. |
| Third-party GitHub Actions | GitHub Marketplace | GitHub | none | Mutable tags and branches (`@v4`, `@stable`). |

## 3. Signing utilities actually distributed

- The Python CLI `aigov` (shipped in `aigov_py`) provides `sign-audit-export` and `policy sign-bundle`. These run offline, with the seed supplied as a file (preferred) or as a legacy command-line value (opt-in).
- The Rust binaries `sign_audit_export_once` and `signing_pubkey_from_seed_once` are not in the runtime image.
- No CI job or deployment invokes any signing utility, so no private key is used by automation in this repository.

## 4. Threat model results

| Scenario | Result before this PR | Result after | Evidence |
|----------|-----------------------|--------------|----------|
| Tampered signer label on an export signature | **Accepted (demonstrated)** | Rejected | `rust/tests/export_signature_binding.rs::tampering_the_signer_label_invalidates_the_signature`; Python mirror |
| Tampered creation time | **Accepted (demonstrated)** | Rejected | `tampering_the_creation_time_invalidates_the_signature` |
| Extended expiry | **Accepted (demonstrated)** | Rejected | `extending_the_expiry_invalidates_the_signature` |
| Expired signature | **Accepted (demonstrated)** | Rejected | `expired_signature_is_rejected` |
| Modified unsigned evidence field (`log_chain`) | **Accepted (demonstrated)** | Rejected | `tampering_unsigned_evidence_fields_invalidates_the_signature` |
| Expiry on a legacy (v1) record | not checked | Rejected (cannot be trusted) | `legacy_signature_with_unsigned_expiry_is_rejected` |
| Downgrade by stripping `payload_version` | n/a (v1 is the old format) | Rejected: the v1 digest does not match a v2 signature | digest comparison, covered by the tampering tests |
| Legacy signature without expiry | verifies | verifies (compatibility) | `legacy_signature_without_expiry_still_verifies` |
| Unsigned staging/production policy file controlling verdicts | **Started (demonstrated)** | Refused unless explicitly opted in | `rust/tests/policy_unsigned_file.rs`; opt-in path `policy_unsigned_optin.rs` |
| Malformed or empty Sigstore bundle | rejected (library) | rejected, CLI exit non-zero | `python/tests/test_sigstore_fail_closed.py` (offline) |
| Missing identity or issuer for DSSE verification | rejected | rejected | same file |
| Floating-point numbers in signed exports (serializer disagreement) | not checked | refused by both implementations | `signing_a_document_with_floats_is_refused` (Rust and Python) |
| Substituted or truncated evidence, ledger corruption | detected | detected (unchanged) | existing tests listed in section 1 |
| Replay of a valid, unexpired export | accepted | **still accepted (not addressed)** | section 6 |
| Forged signature or wrong issuer | rejected | rejected (unchanged) | `verify` returns "no trusted keys for issuer" / "ed25519 verify failed" |
| Fail-open during network outage | Sigstore: verification raises (fail-closed); policy: no network | unchanged | code review; live outage not tested |
| Container image substitution | mutable base tags | digest-pinned | Dockerfiles |
| Action substitution by tag move | mutable tags | commit SHA pins | workflows |

Distinction used in tests:
- **Cryptographic integrity:** the digest and the signature cover the bytes. Tampering tests check this.
- **Authenticity:** the signing key belongs to the claimed issuer. Trust-store tests check this, using test-only keys.
- **Provenance:** the artifact was produced by a specific build or workflow. Not implemented, because no producer exists (section 7).
- **Authorization:** whether the signer may approve a verdict. Not covered by the signature format.

## 5. Changes in this PR

- **Export signatures v2** (`rust/src/audit_export_signing.rs`, `python/aigov_py/audit_export_signing.py`): the record binds issuer, signer, creation time, expiry, and the whole document (without the `signatures` array). Expiry is enforced. Legacy v1 records keep verifying, and cannot carry an expiry. Floating-point numbers are refused. Cross-language vectors are pinned in both test suites.
- **Policy file gate** (`rust/src/govai_api.rs::enforce_policy_file_trust`): staging and production refuse an unsigned policy file that controls verdicts, unless `AIGOV_ALLOW_UNSIGNED_POLICY_FILE=1` is set, which prints a warning.
- **Staging test fixtures** that load the repository's policy file now set the opt-in explicitly, with a comment.
- **Workflows** (non-CLA): top-level `permissions: contents: read` added to nine workflows that had none. Third-party actions pinned to commit SHAs with the tag as a comment (checkout, setup-python, upload-artifact, download-artifact, setup-node, rust-cache, rust-toolchain, trivy-action).
- **Dockerfiles:** `rust:1-bookworm` and `debian:bookworm-slim` pinned by digest, in both `Dockerfile` and `rust/Dockerfile`.
- **Documents:** `docs/operations/audit-export-signing.md` (format and migration), `docs/operations/policy-signing.md` (trust and migration).

## 6. Residual gaps (not closed here)

- **Replay and freshness.** A valid, unexpired export can be replayed. Closing this needs a verifier-side freshness policy or a nonce, which is a design change.
- **Verdict policy is not signed.** Signed policy bundles exist, but verdicts still read the unsigned policy file. Until the verdict configuration is part of a signed bundle, the opt-in flag is a risk acceptance, not a fix.
- **Key custody.** Seeds are supplied by file or stdin. Hardware-backed or KMS-backed signing is not implemented (see the KMS architecture report).
- **Sigstore live verification** has not been run. No live bundle or identity exists in this environment. The Sigstore code path is not invoked by any workflow.
- **Dependabot** has no Docker ecosystem entry, so the digest pins need manual refresh.

## 7. Not implemented, and why

- **SBOM generation, build provenance attestations, image signing, and Sigstore signing of releases.** The repository has no publish or distribution step (no registry push, no package upload, no release that consumers install). Adding attestations without a consumer would be a checklist item. They would benefit a release workflow that publishes the audit binary or the Python package. That workflow does not exist yet.
- **A Sigstore verifier in the runtime.** The runtime does not consume Sigstore data. The verifier stays in the operator tooling.

## Evaluation gate

Passes when the Rust suite (with PostgreSQL opted in), the Python suite (with and without PostgreSQL), the tamper and signature negative tests, the workflow and Dockerfile validation, and the make gates pass on the PR head. Results are in section 8.

## Human approval gate

Not approved for production by this report.

- Requires your decision: whether to make verdict configuration part of a signed bundle (closes the largest residual gap), and whether a release pipeline should be added to justify SBOM and attestation work.
- Requires your action: set `AIGOV_ALLOW_UNSIGNED_POLICY_FILE=1` only if you accept the risk in staging or production until the verdict configuration is signed; re-sign existing exports with v2 if you need expiry or full binding.
- Requires credentials or infrastructure: a live Sigstore bundle and identity for verification, and a production key custody decision.

## 8. Test results

Final runs on the final code, before the PR was opened:

| Suite | Result |
|-------|--------|
| Rust `cargo test --locked`, PostgreSQL auth test opted in | 214 passed, 0 failed, 0 ignored |
| Rust export binding (`export_signature_binding`) | 10 passed (includes tamper, expiry, legacy, floats, cross-language vector) |
| Rust policy gate (`policy_unsigned_file`, `policy_unsigned_optin`) | 2 passed |
| Python full suite, no database | 1026 passed, 41 skipped |
| Python full suite, PostgreSQL opted in | 1063 passed, 4 skipped |
| Python export binding and Sigstore fail-closed | 14 passed (offline) |
| Skipped with PostgreSQL | live OAuth and tenant provisioning (BLOCKED), Sigstore real bundle (BLOCKED), `mcnemar_F_vs_G` report artifact |
| `make` gates (8 targets) | all exit 0 |
| CLA workflow guard, report gate | PASS |
| Workflow YAML parse (15 files) | all parse |
| `docker buildx build --check` (both Dockerfiles) | no warnings |

The skips are not counted as passing. Sigstore verification has not been run against a live bundle.
