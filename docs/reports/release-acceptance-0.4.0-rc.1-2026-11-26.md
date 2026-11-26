# Release acceptance report: AIGov Core 0.4.0-rc.1 (candidate)

Branch `release/0.4.0-rc.1-preparation`, from `origin/staging` at `f6b4d71` (PR #517 merged). This report consolidates the release-freeze work:
R-6 verification, release integrity, the owner acceptance package, the deployment preflight, the independent audit handoff, and the final validation.

**Status: release candidate, ready for owner review. Not approved. Nothing is tagged, published, or deployed. Issue #501 stays open.** The owner's
decisions are in `docs/decisions/release-0.4.0-rc.1-owner-acceptance.md`, and every one of them is open.

## Recommendation

- **Controlled pilot: conditional GO**, for one tenant on one ledger host, in production mode, with principals in every environment, within the measured
  write ceiling of the chosen hardware (about 37 to 49 accepted evidence writes per second on the test workstation), and with the owner decisions recorded.
- **Unrestricted production: NO-GO.** Several hosts sharing a ledger are unsupported (R-4). Issue #501 decisions D1 to D4 are open. The overload behaviour is
  measured on one host only.
- **Version: `0.4.0-rc.1`** (recommended, not applied to the tree as a tag; the owner approves it).

## Findings in this round

| ID | Severity | Finding | Status |
|---|---|---|---|
| F-17 | High | A process that started on policy revision 1 kept accepting evidence (HTTP 200, `policy_version` 1) after another process anchored revision 2. The revision was superseded in the database but still enforced by the old process. Measured before the fix. | **Fixed** (`0e7a29e`). Each evidence write checks the anchored revision and refuses with `POLICY_REVISION_SUPERSEDED` (409), or `POLICY_ANCHOR_UNAVAILABLE` (503) when the anchor cannot be confirmed. Test: `test_policy_revision_across_processes.py`. |
| F-18 | High | Under sustained overload Core accepted every request into an unbounded queue. The append blocked on disk inside the request task, so the time limit did not see the queue (my earlier claim that it did was wrong). 161 clients timed out at 256 concurrent, and 129 writes were recorded that the client never saw succeed. | **Fixed** (`a18f295`). The append runs on the blocking pool; an in-flight limit refuses excess requests at once with 503 `OVERLOADED`, before any handler runs, so nothing is recorded for them. Measured after the fix: 701 accepted and 81,715 refused at 256 clients, no client timeouts, and every accepted write accounted for in the ledger. |
| F-19 | Medium | The time limit's description claimed it bounded the permit wait. It did not. | **Corrected** in code comments, the invariant document, and the changelog (`c649ec4`). |
| F-20 | Medium | Keep-alive clients saw broken-pipe errors when a refused request's body was not read. | **Fixed** (`Connection: close` and `Retry-After: 1` on the refusal). |
| F-21 | Low | The verdict test skipped the anchor commit that startup performs. The correct refusal failed the test. | **Fixed** in the test (`b29e953`). Behaviour unchanged. |
| F-22 | Low | A test database name and a placeholder tenant were wrong in the new cross-process test. | **Fixed** in the test before the first pass. |

Earlier findings F-1 to F-16 remain fixed, as recorded in `docs/reports/pilot-readiness-closure-2026-11-26.md`.

## R-6: concurrent issuance during rotation, revocation, and policy change

Tested in `python/tests/test_issuance_cross_process.py` and `test_policy_revision_across_processes.py`:

- **Three independent Core processes** on one ledger and one registry anchor, issuing while the signing key is rotated (exe-a to exe-b) and then revoked
  (exe-a). Result: 58 authorized, 2 refused after retirement. Every authorization verifies against the registry key for its key id. No exe-a authorization
  at or after the revocation time. Each approval authorizes at most once. A duplicate through another process is refused with `approval_already_consumed`.
  The ledger chain verifies, and holds one consequential record for every call that reached signing.
- **A call whose key is retired after its record is committed** is refused, and its approval is consumed. The human must approve again. This is the fail-closed
  behaviour, and it is recorded as R-6a.
- **Two processes on revisions 1 and 2**: the superseded process refuses writes; the current one accepts them. A missing anchor row refuses writes, and
  they resume once the row is restored.

Not tested: several hosts, a database restart during issuance, a policy change during a rotation.

## Overload and fail-closed behaviour (measured)

From `scripts/core_load_test.py`; evidence in `docs/evidence/release-candidate/load/`. One Core process, Python client on the same host.

| Configuration | Clients | Accepted (200) | Refused (503 OVERLOADED) | Client timeouts | Unaccounted records | Accepted p50 / p99 (ms) |
|---|---|---|---|---|---|---|
| Default limit (256) | 1 | 640 | 0 | 0 | 0 | 23 / 35 |
| Default limit (256) | 16 | 641 | 0 | 0 | 0 | 379 / 456 |
| Default limit (256) | 64 | 664 | 0 | 0 | 0 | 1592 / 1624 |
| Default limit (256) | 256 | 821 | 0 | 0 | 0 | 6687 / 7101 |
| Limit 16, 3 s limit | 64 | 755 | 85,850 | 0 | 0 | 328 / 355 |
| Limit 16, 3 s limit | 256 | 701 | 81,715 | 0 | 0 | 381 / 676 |

Recovery after the peak: a single client's median is back to 27 to 35 ms, with no refusals. The chain verifies in every run.

Reading the table: throughput of accepted writes stays between about 37 and 49 per second at every level. That is the single-writer ceiling on this host. Above the limit, Core refuses rather than queues.

## Release integrity

| Check | Result |
|---|---|
| CycloneDX 1.5 schema, Rust SBOM (327 components) | valid |
| CycloneDX 1.5 schema, Python SBOM (37 components) | valid |
| Dependency completeness (Cargo.lock to SBOM; pyproject to SBOM) | complete |
| Clean container build (`docker build --no-cache`) | built; its binary contains no crash-point names |
| Repository release build vs clean build (same commit) | not byte-identical: 48 bytes of crate identifiers differ (`docs/evidence/release-candidate/reproducibility.md`). Code identical. |
| Fault-injection code absent from the release binary and the clean image's binary | pass |
| Recorded checksums | regenerated for the final commit (see provenance record) |
| `cargo audit` | no vulnerabilities; one allowed unmaintained-crate warning (`chrono`) |
| `pip-audit` on the aigov-py closure | no known vulnerabilities |
| Artifact signing | procedure written, no key or identity created (`docs/release/artifact-signing.md`) |

## Validation (final code)

| Step | Result |
|---|---|
| Release build; fault-injection build; fault-absence check | pass |
| Rust, all tests with PostgreSQL, two-volume test excluded | **420 passed, 0 failed** |
| Rust, no database (the CI command) | **398 passed, 0 failed, 23 ignored** (PostgreSQL tests) |
| Two-volume rollback (two real filesystems, separate processes) | pass |
| Crash-consistency gate (fault-injection build) | pass (9 tests) |
| Python, full suite with PostgreSQL and release Core (container file separate) | **1327 passed, 0 failed, 27 skipped** |
| Container runtime (clean image) | **16 passed** |
| Staging simulation (`--skip-live`) | **66 passed, 0 failed** |
| Acme Finance (binary mode, PostgreSQL) | pass |
| Customer pilot (fresh output directory) | pass, all checks passed |
| SDK wheel: build, offline downstream from an isolated target, PostgreSQL migration included | pass |
| `make gate` | pass |
| `make enterprise-readiness-check` | OK |
| `make validate-changelog` | OK |
| Benchmark, final code (1, 2, 4, 8 workers) | zero unauthorized, zero duplicate, zero false denial (`docs/evidence/release-candidate/benchmark-pg-final.json`) |

Hosted CI on the final head is the separate gate and is recorded on the pull request.

## Deployment preflight

`scripts/deploy_preflight.py` checks names only (never values) against a supplied environment file. The new requirement is `GOVAI_PRINCIPALS_JSON` in
staging and production. The incompatibilities with an existing staging configuration, and the migration, backup, rollback, and smoke-test steps, are in
`docs/release/deployment-preflight.md`. No remote environment was contacted, and Railway was not changed.

## Owner acceptance

Prepared, not approved: `docs/decisions/release-0.4.0-rc.1-owner-acceptance.md`. It covers issue #501 D1 to D4, the event-role assignment (F-10),
residual risks R-2, R-6, R-9, and R-11, the proposed version, the pilot topology, and the remaining limitations. Each decision has a recommended option,
alternatives, consequences, and acceptance criteria, and each owner record is open.

## Independent audit handoff

`docs/audit-handoff/`: architecture, trust boundaries, security invariants (I-1 to I-17, each with its enforcement point and tests), known limitations,
source locations, and reproduction instructions. It is prepared for an independent security review. **No independent audit has been performed.** The
internal verification in this report is the project's own.

## Residual risks at release

| ID | Status |
|---|---|
| R-1 | Closed in code; deployed staging needs principals (deployment prerequisite) |
| R-2 | Open: database authority over the policy anchor (owner decisions D1, D2, D4) |
| R-3 | Measured: overload fails closed; capacity per host is the limit |
| R-4 | Unsupported by design: several hosts sharing one ledger |
| R-5 | Crash gate in CI; two-volume test on a workstation |
| R-6 | Tested in the stated configuration; untested cases stated (owner acceptance) |
| R-6a | Designed fail-closed behaviour: a retired key's call consumes its approval |
| R-7 | Superseded by the sustained measurements above |
| R-8 | Closed (image binds all interfaces inside its namespace) |
| R-9 | Open: exactly-once external effects are not claimed (owner acceptance) |
| R-10 | Partly closed: SBOMs schema-valid; rebuild differs in 48 bytes of identifiers; no independent builder |
| R-11 | Open: version is recommended, not applied (owner decision) |
| L-1 to L-5 | Listed in `docs/audit-handoff/known-limitations.md` |

## Evaluation gate

Passes when, on the final code: the Rust suites (with PostgreSQL and without), the Python suite, the crash-consistency gate, the fault-absence check, the
two-volume rollback, the container runtime on a clean image, the staging simulation, Acme Finance, the customer pilot, the SDK wheel downstream check,
`make gate`, `make enterprise-readiness-check`, and `make validate-changelog` pass; the load evidence shows overload refusals with every accepted write
accounted for; the SBOMs validate against the official schema and match the lockfile; and the release binary contains no fault-injection code. Status:
all of these pass locally on the final code. The hosted checks are recorded on the pull request.

## Human approval gate

Not approved. The owner must record each decision in `docs/decisions/release-0.4.0-rc.1-owner-acceptance.md`: D1 to D4, F-10, R-2, R-6, R-9, R-11, the version,
the pilot topology, and the limitations. Issue #501 remains open until the owner reviews it. Merging into `staging`, tagging, publishing, and deploying are
separate decisions, and this report does not make them.
