# sha2 0.11.1 dependency update

## Summary

Upgrades the Rust runtime's `sha2` dependency to 0.11.1. The release changes the digest output type so it no longer implements `LowerHex`; three digest-to-hex conversions now use the repository's existing `hex::encode` dependency.

## Scope and impact

- Preserve the existing lowercase 64-character SHA-256 representation used by artifact validation and replay determinism.
- Update the artifact-validation regression fixture to use the same encoder.
- No evidence schema, digest algorithm, API contract, or database migration is changed.

## Validation

The original CI failures were Rust compile errors at the three `{:x}` formatting sites. The fix is committed and the full pull-request CI has been restarted.

- Local Rust validation could not run because `cargo` is not installed in this environment.
- Final Rust build and test results remain pending from GitHub Actions.

## Evaluation gate

**PENDING** until the relevant CI checks pass on the final commit, including the locked Rust build and tests, downstream Rust consumers, and compliance checks.

## Human approval gate

**PENDING** maintainer review before merge.
