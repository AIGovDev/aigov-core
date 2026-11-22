# jsonwebtoken 12.0.0 dependency compatibility — 2026-11-22

## Scope

This change upgrades the Rust audit runtime's `jsonwebtoken` dependency from 11.1.0 to 12.0.0 and updates its associated dependency graph.

## Compatibility and reproducibility

- The main Rust manifest and lockfile are updated for `jsonwebtoken` 12.
- Independent Cargo lockfiles for the downstream consumer smoke test, minimal example, and immutable S3 adapter are regenerated with Cargo to maintain `--locked` reproducibility.
- A previously truncated immutable S3 lockfile was repaired before re-resolution.
- No intended change is made to JWT policy, trust boundaries, authorization decisions, audit event formats, or production deployment configuration.

## Risks and verification

- **JWT compatibility:** Version 12 changes cryptographic dependency versions and rejects empty HMAC keys. Validate encoding/decoding and JWT authentication regressions without weakening cryptographic checks.
- **Cargo reproducibility:** Require `cargo build --locked` and downstream `cargo test --locked` to succeed.
- **Security:** Retain security-scan and supply-chain checks; review parsing of JWT header extensions and claim types.
- **Integration:** Ensure independent downstream consumers still compile with the updated dependency tree.

## Evaluation gate

Status: **PENDING final CI completion.** The changed lockfiles were generated through GitHub Actions using Cargo and committed to the PR branch. Do not infer test success from resolver completion alone. Require the `aigov-ci`, `compliance`, `security-scan`, `supply-chain-audit`, and branch-policy jobs to pass on the final commit.

## Human approval gate

**PENDING.** Merge and deployment require maintainer approval. No production readiness or deployment authorization is asserted.
