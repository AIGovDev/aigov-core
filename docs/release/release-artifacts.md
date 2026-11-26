# Release artifacts: release candidate (not published)

These artifacts are prepared for review. Nothing is tagged, published, or deployed. The release decision is in
`docs/release/pilot-readiness.md`, and the evidence is in `docs/reports/release-candidate-2026-11-26.md`.

## Release notes (draft)

**AIGov Core, release candidate (controlled pilot).**

Security fixes:

- Execution receipts are accepted only from an authenticated executor principal, and only for an authorization Core issued in the same run.
  Previously any key could record a receipt for an authorization that was never issued.
- Production refuses to start without authenticated principals (`GOVAI_PRINCIPALS_JSON` or OIDC). Previously it started without them, so any key
  could post approvals and receipts.
- Crash-point instrumentation is a non-default `fault-injection` Cargo feature. A normal build contains no crash code and refuses to start if the
  fault-injection variables are set.

Fixes:

- The SDK wheel now includes the PostgreSQL executor schema (`migrations/pg/0001_executor_pg.sql`). Downstream installs could not apply it before.
- `ai_discovery_reported` is allowed for the agent role. Before this, no role could post it when principals were configured.

Behaviour changes that affect integrations:

- A client that posts `execution_receipt` without an executor key is refused with `RECEIPT_REQUIRES_EXECUTOR` (403).
- A receipt that names an authorization Core did not issue for the run is refused with `RECEIPT_FOR_UNISSUED_AUTHORIZATION` (422).
- Production without principals is refused at start.

Verification added: crash consistency at three issuance boundaries, two-process single use of an approval, receipt provenance, production
principal refusal, the wheel contents, and a two-instance ledger test.

Known limitations: see the residual risks R-1 to R-11 in the report.

## Changelog entry

The entry is in `CHANGELOG.md` under `[Unreleased]`.

## Versioning recommendation

- Cargo (`rust/Cargo.toml`) and the Python package (`python/pyproject.toml`) are both `0.2.1`. The repository has the tag
  `v0.3.0-core-replay-operations`, so the version files are behind the tag history.
- Recommendation: **`0.4.0-rc.1`** for this candidate. The receipt and production changes alter behaviour that integrations depend on, so this is a
  pre-1.0 minor bump, not a patch.
- Bump both version files together, and reconcile the tag history before tagging. Do not tag from this branch. Tagging is a separate decision.

## Compatibility matrix

| Component | Version or setting | Tested here | Notes |
|---|---|---|---|
| Core HTTP API, `POST /evidence` | unchanged request shape | full suites | new error codes listed in the release notes |
| Core HTTP API, `GET /ready`, `/health`, `/metrics` | unchanged | container runtime (3 env-sensitive tests on this host) | |
| Ledger format | JSONL hash chain, unchanged | chain verified in all tests | |
| PostgreSQL migrations (Core) | `0001`–`0004` | Rust suite with PostgreSQL | `EXPECTED_SQLX_MIGRATION_COUNT` 4 |
| PostgreSQL (executor store) | schema version 1 (`pg/0001_executor_pg.sql`) | integration suite | PostgreSQL 16 locally (`postgres:16-alpine` in the container tests); 18 in the Compose example |
| SDK (`aigov_py`) | 0.2.1 metadata, PostgreSQL schema included | wheel build, offline downstream check | live downstream check runs in CI |
| Python | 3.12 locally; CI jobs observed on 3.11 | 3.12 full suite locally | the CI downstream job's Python version was not checked |
| Rust | toolchain used locally; `rust/Cargo.lock` pins crates | `cargo test --locked` | `--locked` in every build |
| Container image | `rust/Dockerfile`, UID 1000, default `prod` | built and run locally | no fault-injection feature |
| Key registry | v2 format from PR #514 | registry PostgreSQL suites | unchanged here |

## Software bill of materials

Method: the inventory is the lockfile content, not a signed or generated CycloneDX document.

- `docs/evidence/release-candidate/cargo-lock-inventory.txt`: 328 packages from `rust/Cargo.lock`, with the lockfile's SHA-256. 327 come from
  a registry; the rest are workspace crates.
- `docs/evidence/release-candidate/python-dependencies.txt`: the six declared Python runtime dependencies with their version floors. There is no
  Python lockfile, so transitive Python dependencies are not pinned by this repository.

Not done: a vulnerability scan of this inventory (the CI `cargo-audit` and `pip-audit` jobs run on the PR), a signed SBOM, and a reproducible-build
comparison (R-10).

## Security evidence package (index)

| Item | Location |
|---|---|
| Findings, severity, status | `docs/reports/release-candidate-2026-11-26.md` (Findings) |
| Negative controls, including inconclusive ones | `docs/evidence/release-candidate/negative-controls.md` |
| Crash-consistency tests | `python/tests/test_crash_consistency_core.py` |
| Receipt provenance tests | `python/tests/test_receipt_provenance_core.py` |
| Two-instance approval test | `python/tests/test_approval_single_use_two_instances.py` |
| Production principal refusal | `rust/tests/prod_requires_principals.rs` |
| Dependency inventories | `docs/evidence/release-candidate/` |
| Threat model | `docs/threat-model.md` |
| Architecture, runbooks | `docs/architecture/distributed-execution.md`, `docs/operations/distributed-execution-runbook.md` |

## Customer pilot checklist

- [ ] Decision in `docs/release/pilot-readiness.md` accepted by the named owners, with the residual risks R-1 to R-11 recorded.
- [ ] Pilot environment in production mode, with `GOVAI_PRINCIPALS_JSON` configured (or OIDC).
- [ ] One ledger host for the tenant, and no shared ledger directory across hosts.
- [ ] Signed policy bundle and trust file in place; anchors in PostgreSQL; migrations applied (`/ready` is 200).
- [ ] Executor store migrated with `migrate-pg`; `status-pg` returns exit 0.
- [ ] Downstream deduplication key chosen, or the duplicate-effect risk accepted in writing.
- [ ] Crash-consistency gate run on the release commit (command in the readiness document).
- [ ] `make gate`, `make enterprise-readiness-check`, and the customer pilot pass on the deployed commit.
- [ ] Hosted CI on the release commit is green for every required check.
- [ ] Backup taken, and the ledger head hash recorded off host.
- [ ] First-incident drill completed: Core restart, PostgreSQL restart, and an executor recovery.
- [ ] Issue #501 owner decisions D1–D4 recorded (or the pilot's risk acceptance references them).
