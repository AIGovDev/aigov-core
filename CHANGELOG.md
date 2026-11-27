# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to the [versioning policy](docs/releases/versioning-policy.md).

## [Unreleased]

### Security

- Staging refuses to start without authenticated principals, as production does.
- Protected event types belong to one role each (approvals and risk reviews to the approver, receipts to the executor). Other event types are pipeline or agent evidence, posted by the agent role. Before this, the role table refused most SDK event types in principal-configured environments.
- Ledger routes have a request time limit, a concurrency limit, and a body size limit (`AIGOV_REQUEST_TIMEOUT_SECS`, `AIGOV_MAX_CONCURRENT_REQUESTS`, `AIGOV_MAX_BODY_BYTES`). Invalid values stop startup. The main PostgreSQL pool waits at most 5 s for a connection.
- Execution receipts are accepted only from an authenticated executor principal, and only for an authorization Core issued in the same run. Previously any key could record a receipt for an authorization that was never issued.
- Production refuses to start without authenticated principals (`GOVAI_PRINCIPALS_JSON` or OIDC).
- Crash-point instrumentation moved behind the non-default `fault-injection` Cargo feature; a normal build refuses to start if the fault-injection variables are set.

### Fixed

- The container listens on all interfaces inside its own namespace (`AIGOV_BIND=0.0.0.0:8088`). Before this, a published port returned nothing.
- The SDK wheel includes the PostgreSQL executor schema (`migrations/pg/0001_executor_pg.sql`).
- `ai_discovery_reported` is allowed for the agent role when principals are configured.

### Changed

- Repository slug and documentation branding: **`govai-core` → `aigov-core`** (GitHub rename prepared in-tree). Runtime package names unchanged (`aigov_audit`, `aigov-py`, `govai` CLI compat). Helm chart, Kubernetes manifests, Docker tags, and CI job `aigov-core-portable` use the new slug.

### Added

- An opt-in release-mode benchmark now measures the Rust file-backed ledger verifier on valid and tampered long ledgers; machine-readable results record workload and environment metadata.
- MCP report-template writes now use the existing signed trusted-execution flow, with a separate human approval request tool and pre-migrated executor store.

## [0.2.1] - 2026-06-10

### Added

- Release packaging metadata for Rust (`rust/Cargo.toml`) and Python (`python/pyproject.toml`).
- Release validation scripts: `scripts/validate_changelog.py`, `scripts/generate_release_notes.py`, and `scripts/release_readiness_report.py` with Makefile targets and CI artifact build steps.
- Production-readiness fixes: non-mutating `GET /ready`, mounted `GET /metrics`, standards registry entries, and supply-chain CI (Dependabot, `supply-chain-audit` workflow).

### Changed

- PostgreSQL-only SQLx dependency graph (removed `sqlx-mysql` / `rsa` transitives); runtime migrations use `sqlx_core::migrate::Migrator`.
- Release documentation and examples aligned with scripts and Makefile targets shipped in AIGov Core (removed references to platform-only release validators).

### Fixed

- Runtime observability contract tests for `/metrics` and read-only readiness probes.
