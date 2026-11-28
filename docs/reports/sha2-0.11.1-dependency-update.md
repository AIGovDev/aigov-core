# sha2 0.11.1 dependency update

## Summary

Upgrades the Rust runtime's `sha2` dependency to 0.11.1. The release changes the digest output type so it no longer implements `LowerHex`; three digest-to-hex conversions now use the repository's existing `hex::encode` dependency.

## Scope and impact

- Preserve the existing lowercase 64-character SHA-256 representation used by artifact validation and replay determinism.
- Update the artifact-validation regression fixture to use the same encoder.
- Refresh the downstream Rust consumer lockfile to resolve the upgraded runtime dependency graph.
- No evidence schema, digest algorithm, API contract, or database migration is changed.

## Validation

The initial Rust build and unit/integration tests passed after replacing the three `{:x}` formatting sites. The downstream Rust consumer then exposed its stale lockfile; that lockfile is refreshed to match the runtime dependency graph. CI is running again on the updated commit.

- Local Rust validation could not run because `cargo` is not installed in this environment.
- Final Rust build and test results remain pending from GitHub Actions.

## Evaluation gate

**PENDING** until the relevant CI checks pass on the final commit, including the locked Rust build and tests, downstream Rust consumers, and compliance checks.

## Human approval gate

**PENDING** maintainer review before merge.
