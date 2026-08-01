# Dependabot update: base64 0.23.0

## Scope

This change updates the direct Rust dependency `base64` to version 0.23.0.

## Downstream compatibility

The downstream Rust consumer lockfile was regenerated.

The resulting dependency graph intentionally contains:

- base64 0.23.0 for aigov_audit
- base64 0.22.1 for jsonwebtoken and other transitive dependencies

This is expected and allows both dependency requirements to coexist.

## Validation

Executed:

- cargo generate-lockfile
- cargo check --locked

Result: successful.

## Risk assessment

Only dependency resolution changed.
No application logic, public API, database schema or security policy changed.

## Rollback

Revert this commit.

## Evaluation gate

The dependency update was evaluated through the downstream Rust consumer.

Validation performed:

- regenerated `tests/downstream-consumption/rust-consumer/Cargo.lock`;
- confirmed that `aigov_audit` resolves `base64 0.23.0`;
- confirmed that `jsonwebtoken` and other transitive consumers retain `base64 0.22.1`;
- executed `cargo check --locked` successfully.

Evaluation result: PASS.

## Human approval gate

Human review is required before merge.

Approval scope:

- review the dependency graph change;
- confirm that the dual `base64` versions are intentional;
- confirm that no application logic or public API changed;
- confirm that the downstream lockfile is committed.

Human approval status: pending pull request review.
