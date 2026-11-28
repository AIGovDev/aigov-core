# tower-http 0.7.1 dependency update

## Summary

PR #540 upgrades the direct Rust runtime dependency `tower-http` from 0.6.11 to 0.7.1.

## Scope

The change is limited to dependency metadata, generated lockfiles, and this validation report. Application source and public API contracts are unchanged.

## Evaluation gate

- The initial CI run built the runtime and passed the Rust unit and integration suite.
- The initial downstream Rust consumer smoke failed because its committed lockfile did not include the newly direct `tower-http 0.7.1` dependency.
- The downstream consumer lockfile now records 0.7.1 for `aigov_audit` and retains 0.6.11 for the separate transitive dependency.
- CI is running again after this correction; final status is pending.
- The initial container scan reported five HIGH Debian OS package findings, unrelated to this dependency update.

## Human approval gate

Status: pending maintainer review after the dependency and downstream lockfile correction.

## Validation

GitHub Actions on PR #540 are the validation source. No local cargo executable was available in this workspace.
