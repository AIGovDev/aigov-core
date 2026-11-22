# SQLx 0.9.1 dependency compatibility — 2026-11-22

## Scope and motivation

This pull request upgrades the Rust audit runtime's SQLx dependency from 0.8.6 to 0.9.1. The initial Dependabot update left direct `sqlx-core` and `sqlx-postgres` dependencies at 0.8.6, leading to incompatible SQLx trait implementations and a failed Rust build.

## Changes and impact

- Align `sqlx`, `sqlx-core`, and `sqlx-postgres` to 0.9.1 in `rust/Cargo.toml`.
- Keep migration execution on SQLx's current migration API.
- Reconcile `rust/Cargo.lock`: remove obsolete 0.8-only packages and normalize dependency references. Preserve the reproducibility requirement enforced by `cargo --locked`.
- No authorization, security gate, audit event format, database schema, or production configuration is intentionally changed.

## Risks and mitigations

- **Dependency upgrades:** SQLx 0.9.1 may contain breaking API or runtime changes. Require the full Rust compilation, tests, and integration checks.
- **Lockfile integrity:** The lockfile must match Cargo's solver and build successfully using `--locked`; do not bypass this flag.
- **Database functionality:** Migration and Postgres-backed query paths require regression coverage. Successful compilation alone is insufficient to establish database compatibility.
- **Supply chain:** Retain existing dependency and audit checks.

## Evaluation gate

**PENDING.** The following checks must pass on the final commit before considering merge:

- `aigov-ci` Rust build with `--locked` and relevant tests.
- `compliance` report and artifact gates.
- `security-scan` and `supply-chain-audit` checks.
- Rust migrations and PostgreSQL regression verification wherever CI fixtures are available.

A check is not marked verified based on an uncompleted workflow.

## Human approval gate

**PENDING.** This is a dependency update with compatibility and reproducibility risks. A human maintainer must approve merging after required checks and review. No production deployment is authorized.
