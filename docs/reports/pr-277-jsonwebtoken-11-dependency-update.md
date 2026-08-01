# PR #277 — jsonwebtoken 11.0.0 dependency update

## Summary

This pull request updates the Rust `jsonwebtoken` dependency from version 10.4.0 to 11.0.0 and refreshes the downstream Rust consumer lockfile.

## Scope

- update of `jsonwebtoken` from 10.4.0 to 11.0.0
- resulting transitive dependency changes
- refresh of `tests/downstream-consumption/rust-consumer/Cargo.lock`
- validation of downstream consumer compilation and tests with `--locked`

## Risk assessment

The main risks are API incompatibility, changed token validation behavior, changed cryptographic dependency behavior, incompatible transitive dependencies, and divergence between manifests and lockfiles.

## Mitigations

- the downstream consumer lockfile is generated from the current dependency manifest
- downstream validation runs with `cargo test --locked`
- the full Rust test suite and dependency checks remain required
- the change can be rolled back by restoring the previous dependency version and lockfiles

## Evaluation gate

The update is acceptable only if the downstream consumer test, Rust test suite, dependency audit, Cursor plugin smoke test, repository gate, and all required CI checks pass against `staging`.

## Human approval gate

Pending. This report does not claim human approval. Merge requires approval by an authorized repository maintainer.

## Rollback plan

Revert this pull request and restore `jsonwebtoken` 10.4.0 and the corresponding lockfiles.

## Result

The dependency update is suitable for merge only after all required automated checks pass and an authorized maintainer approves the pull request.
