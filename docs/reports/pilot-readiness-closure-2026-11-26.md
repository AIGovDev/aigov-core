# Pilot readiness closure: consolidated audit, 2026-11-26

Branch `feat/pilot-readiness-closure`, from `origin/staging` at `b39accc` (PR #516 merged). Issue #501 stays open for owner review.
This report consolidates the residual-risk review (R-1 to R-11 from the release-candidate audit), the new findings of this round, the
final validation, and the recommendation. Pilot package and decision: `docs/release/pilot-readiness.md` and `docs/release/pilot-package.md`.

## Status, in one paragraph

Four blockers from the release-candidate audit are closed in code and tested: staging now refuses to start without principals (R-1);
Core bounds request time, concurrency, and body size, and the database wait (R-3); the crash-consistency gate and the fault-absence check
run in CI (R-5); and the container failures had a confirmed cause, a loopback bind inside the container, which is fixed (R-8). Two more
defects were found and fixed during this work: the principal role table refused most event types the SDK sends (F-10, a pilot blocker), and
staging accepted approvals and evidence without principals (F-9). The two-volume rollback test on real filesystems is complete (#501 A2).
The recommendation is still a **controlled pilot, conditional GO**, with the conditions in the decision document. Unrestricted production remains NO-GO.

## Findings in this round

| ID | Severity | Finding | Status |
|---|---|---|---|
| F-9 | High | Staging started without principals, so any key could post approvals and execution evidence. | **Fixed.** Staging refuses to start without principals, as production does. `staging_requires_principals.rs`, `prod_requires_principals.rs`. |
| F-10 | High | The principal role table listed only the tool and approval events. The SDK sends others (`run_started`, `trace_started`, `policy_eval`, `evidence_genesis`, `model_invocation_recorded`, `completed`, and more), so Core refused them in every principal-configured environment, which is now staging and production. | **Fixed.** Protected types belong to one role each: approvals and revocations and risk reviews to the approver, receipts to the executor. All other types are pipeline or agent evidence, and only the agent role may post them. The gates still check each event. Unit test `role_may_post`. Owner should confirm the assignment. |
| F-11 | Medium | Core had no request time limit, concurrency limit, or body limit on the ledger routes. | **Fixed.** Time, concurrency, and body limits (defaults 30 s, 256, 2 MiB). Health and readiness are outside them. Invalid settings stop startup. `request_limits_http.rs` over a real socket; the negative control with the time limit removed fails. |
| F-12 | Medium | The main PostgreSQL pool waited up to sqlx's default (30 s) for a connection. | **Fixed.** Five-second acquire timeout. |
| F-13 | Medium | The container listened on 127.0.0.1 inside its namespace, so the published port returned nothing. This was the cause of the three workstation container failures. | **Fixed** in the image (`AIGOV_BIND=0.0.0.0:8088`). Measured: default bind HTTP 000 through the port, with the bind set HTTP 200. All 16 container tests pass on the rebuilt image. |
| F-14 | Low | The benchmark's `receipts_recorded` was cumulative across levels (60, 120, 180, 240), which read as per-level. | **Fixed.** Per level, with the store total kept separately. Benchmark rerun. |
| F-15 | Low | A tracked root-level `aigov_py/__init__.py` shim shadows the package when Python runs from the repository root. Its behaviour is deliberate, but a benchmark run from the root imported an old installed copy and failed. | **Documented; not changed.** Run from `python/` or set `PYTHONPATH`. |
| F-16 | Low | The two-volume test and the approval-opt-in test were not in the right state for the full run (a skip filter that matched the file, not the test; a missing principal). | **Fixed** in the test and the script. |

Earlier-round findings F-1 to F-8 are in `docs/reports/release-candidate-2026-11-26.md`, all fixed.

## Residual risks R-1 to R-11: status

| ID | Was | Now | Evidence and note |
|---|---|---|---|
| R-1 | Medium: untrusted approvals and evidence in staging without principals | **Closed in code.** Owner must configure principals in every deployed staging environment. | Staging refusal tests; simulation 66/66 with per-role keys. A deployed staging now needs `GOVAI_PRINCIPALS_JSON` before its next start. No remote change was made. |
| R-2 | Medium: policy anti-rollback record authenticated only by the row | **Open, owner decision D2.** | `docs/decisions/issue-501-owner-decisions.md`. Two-volume test shows the row refusing rollback on two real filesystems. |
| R-3 | Medium: no timeout, concurrency, or resource bound | **Mitigated; not load-tested.** | F-11, F-12. Bounds and the socket test. No throughput or load test of Core was run; the limits are defaults to tune per pilot. |
| R-4 | Medium: several Core instances on different hosts sharing one ledger | **Unchanged.** Unsupported, documented. | `docs/operations/distributed-execution-runbook.md`. |
| R-5 | Medium: crash gate not in CI | **Closed.** New CI job `crash-consistency-gate`. | `make crash-consistency-gate` (9 tests), `make fault-absence-check`. The job has not yet run on the hosted runner for this head (see Validation). |
| R-6 | Medium: concurrent issuance across processes during key or policy change | **Open, NOT VERIFIED.** | Single-process unit tests only. Not in this round. Recorded as a pilot risk. |
| R-7 | Low: benchmark not re-run | **Closed.** Rerun on the final code: 4 levels, zero unauthorized, zero duplicate, zero false denial. | `docs/evidence/release-candidate/benchmark-pg-final.json`. Figures below. |
| R-8 | Low: container tests environment-sensitive | **Closed** with a confirmed cause and fix (F-13). | 16 of 16 pass locally on the rebuilt image. |
| R-9 | Medium: exactly-once external effects | **Unchanged, by design.** The pilot must choose a deduplication key downstream. | `docs/release/pilot-package.md`. |
| R-10 | Low: SBOM not signed; reproducibility not compared | **Partly closed.** CycloneDX 1.5 SBOMs generated; reproducibility check is for the crate only. | SBOMs and provenance in `docs/evidence/release-candidate/`. Not validated against the official schema; no full from-scratch build comparison (disk). |
| R-11 | Low: versions and tags disagree | **Recommendation given; not applied.** | `docs/release/release-artifacts.md`. Bumping the version touches pinned tests and CI; the owner decides. |

## Production defaults fail closed

Verified by tests and by the staging simulation (66 checks), with the refusals reported by the binary itself:

- production without a signed bundle: refused (existing tests);
- production or staging without principals: refused before the database connection opens (the policy step first checks that a database URL is present);
- production with `AIGOV_POLICY_FILE`, `AIGOV_ALLOW_UNSIGNED_POLICY_FILE`, or `AIGOV_APPROVER_ALLOWLIST`: refused;
- production without a database URL for the policy anchor: refused;
- a limit variable that does not parse or is out of range: startup refused;
- the fault-injection variables in a normal build: startup refused, and the normal binary contains no crash-point names.

## Fault-injection absence from release artifacts

`make fault-absence-check` reads the normal release binary and finds no crash-point names (`after_sign_before_response`, `after_append_before_sign`).
The fault-injection build contains them. The check is a strings check. It catches the feature being enabled by mistake; it does not prove that no
crash code exists. The Dockerfile builds without the feature.

## #501

- **A2 (two volumes):** complete. `make two-volume-rollback` creates two disk images, attaches them as separate filesystems (different devices, checked),
  runs the six-step sequence with separate Core processes, and removes its images. Refusal text: "rollback refused: revision 1 is older than the anchored revision 2".
  Evidence: `docs/evidence/release-candidate/two-volume-rollback.txt`.
- **D1–D4:** recommendations only, in `docs/decisions/issue-501-owner-decisions.md`. No owner decision was made. #501 is not closed.
- **Traceability:** rows for R-1 to R-11 above and A2 are updated here, not in the merged PR #515 appendix.

## Crash consistency as a release gate

`make crash-consistency-gate` builds the fault-injection binary and the normal release binary, and runs the crash-point tests (4), receipt
provenance (4), and two-instance approval single use (1). The CI job runs the same target. A release must pass it.

## Benchmark (final code)

PostgreSQL executor store, 60 valid and 10 forged authorizations per level, measured from outside the workers. Host: 12 CPUs, load about 6–8 at the end.

| Workers | Executed | Throughput (executed/s) | Executed latency p50 / p95 / p99 (ms) | Unauthorized | Duplicate | False denials | Receipts (this level) |
|---|---|---|---|---|---|---|---|
| 1 | 60/60 | 24.9 | 35.8 / 47.9 / 59.2 | 0 | 0 | 0 | 60 |
| 2 | 60/60 | 70.8 | 0.6 / 23.6 / 67.9 (all attempts p50 0.6) | 0 | 0 | 0 | 60 |
| 4 | 60/60 | 113.2 | 0.6 / 21.4 / 36.2 | 0 | 0 | 0 | 60 |
| 8 | 60/60 | 137.6 | 0.6 / 27.1 / 33.4 | 0 | 0 | 0 | 60 |

Reading the table: at 1 worker every attempt is executed, so its latency is the full store round-trip (about 36 ms). At 2 or more workers the
all-attempts median is dominated by fast refusals. The executed-only percentiles are the fair figure, and they are of the same order at every level.
Recovery after a killed executor: 211 ms median over three runs, with a 1-second lease. These are local figures on a shared workstation, not
production capacity. The benchmark measures the store and the executor against stand-ins, not a real Core or a real downstream system.

## Validation (final code HEAD of this change)

| Step | Result |
|---|---|
| Release build; fault-injection build; fault-absence check | pass |
| Rust, all tests with PostgreSQL (`--no-fail-fast --include-ignored`, two-volume test run separately) | **419 passed, 0 failed** |
| Two-volume rollback (`make two-volume-rollback`) | pass |
| Crash-consistency gate | pass |
| Python, full suite with PostgreSQL and release Core (container file run separately) | **1318 passed, 0 failed, 34 skipped** |
| Container runtime, rebuilt image | **16 passed** |
| Staging simulation (`scripts/staging_policy_verify.py --skip-live`) | **66 passed, 0 failed** |
| Acme Finance (binary mode, PostgreSQL) | pass |
| Customer pilot (fresh output directory) | pass, all checks passed, no FAIL rows |
| `make gate`; `make enterprise-readiness-check` | pass; OK |
| SDK wheel: build, offline downstream check from an isolated target | pass; contains the PostgreSQL migration |
| `cargo audit` (328 crates) | no vulnerabilities; one allowed warning: `chrono` unmaintained (RUSTSEC-2026-0543) |
| `pip-audit` on the 37-package aigov-py closure (from the SBOM) | no known vulnerabilities |

Not run in this round: the SDK downstream check against a live Core (CI does this); the distributed benchmark's SQLite mode; a from-scratch rebuild
of all dependencies for reproducibility.

## Supply chain

- SBOMs: `docs/evidence/release-candidate/sbom/aigov-core-rust.cdx.json` (327 crates, with lockfile SHA-256) and `aigov-py-python.cdx.json` (37 packages,
  no hashes in installed metadata). CycloneDX 1.5 shape checked; not validated against the official schema.
- Provenance: `docs/evidence/release-candidate/provenance.json`, generated by `scripts/release_provenance.py` on the final commit. Not signed.
- Reproducibility: the Core crate, rebuilt twice in the same target directory with `cargo clean -p aigov_audit`, gives the same binary hash
  (`1dea2793…`). Dependencies were not rebuilt.
- Base images are pinned by digest in `rust/Dockerfile`. The container runs as UID 1000 and does not enable the fault-injection feature.

## Not verified, and why

- R-6: cross-process issuance during a key or policy change (not in this round).
- Load and soak behaviour of Core under realistic traffic (only the functional socket test).
- A live staging deployment with principals (no remote change was made, by request).
- The hosted CI result for this head (see the pull request for the result on the final commit).

## Evaluation gate

Passes when, on the final code: the Rust and Python suites pass with PostgreSQL; the crash-consistency gate, fault-absence check, and two-volume rollback
pass; the staging simulation, the container tests, Acme Finance, the customer pilot, the SDK wheel downstream check, `make gate`, and
`make enterprise-readiness-check` pass; the benchmark shows zero unauthorized, zero duplicate, and zero false denials at 1, 2, 4, and 8 workers; and
`cargo audit` and `pip-audit` report no vulnerabilities in the shipped dependencies. Status: all of these pass locally on the final code. The hosted
checks are recorded on the pull request.

## Human approval gate

Not approved for production by this report. Before any pilot use, the owners must decide and record: the assignment of `ai_discovery_reported` and the other
pipeline event types to the agent role (F-10, the new role rule); the D1–D4 decisions in `docs/decisions/issue-501-owner-decisions.md`; that every deployed
staging and production environment has principals configured (R-1); the pilot's request limits (R-3 defaults) and volume; the acceptance of R-6 and R-9; and
the release version (R-11). Issue #501 remains open. Merging into `staging` and any tag or release are separate decisions, and this report does not make them.
