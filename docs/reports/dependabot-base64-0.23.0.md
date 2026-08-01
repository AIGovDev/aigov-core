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
