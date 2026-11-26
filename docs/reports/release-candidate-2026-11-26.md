# Release candidate: final security hardening and audit, 2026-11-26

Branch `feat/release-candidate-hardening`, from `origin/staging` at `af4efc9` (PR #515 merged). Issue #501 stays open for human review.
Commits on this branch are listed in the delivery section. Everything below was run locally on this workstation unless a row says CI.

## Status, in one paragraph

Four confirmed defects were found and fixed on this branch, none of them Critical: forged execution receipts were accepted; production could
start without authenticated principals; the SDK wheel omitted the PostgreSQL executor schema; and one event type (`ai_discovery_reported`) had
no role that could post it. Fault-injection crash points were compiled into the normal binary and are now behind a non-default Cargo feature.
Crash consistency of authorization issuance is now verified at three boundaries, and two-instance single use of an approval is verified.
The full local validation passes on the code at `302c6dc`, with one later test-only commit (`bb03393`). The recommendation is a **controlled pilot,
conditional on the conditions in the Human approval gate**, and **not** unrestricted production. The decision and its evidence are in
`docs/release/pilot-readiness.md`.

## Findings

Severity: Critical = breaks the authorization guarantee with no preconditions; High = breaks an evidence or authentication guarantee in a
supported configuration; Medium = breaks a guarantee only under a stated configuration or limit; Low = operational or defence-in-depth.

| ID | Severity | Finding | Evidence | Status |
|---|---|---|---|---|
| F-1 | High | An execution receipt was accepted from any key, and for an authorization Core never issued. Receipts are evidence that an authorized call ran. | N1 in `docs/evidence/release-candidate/negative-controls.md`: HTTP 200 for `auth_never_issued` on `af4efc9`. | **Fixed** (`989cefa`). Receipts require an authenticated executor and an authorization issued in the same run. Tests `test_receipt_provenance_core.py`: 4 pass. |
| F-2 | High | Production started without authenticated principals, so any key could post approvals and receipts. | N7. | **Fixed** (`989cefa`, moved earlier in `5ec7cf7`). Production refuses to start before any database access. `production_refuses_to_start_without_principals`: pass. |
| F-3 | High | The SDK wheel omitted `migrations/pg/0001_executor_pg.sql`. A downstream install could not create the PostgreSQL executor schema. | N10: the wheel listed the two SQLite-era migrations only. | **Fixed** (`a8e151a`). The wheel includes the PostgreSQL schema. The offline downstream check passes from an isolated target directory. |
| F-4 | Medium | No role could post `ai_discovery_reported`, so any principal-configured deployment refused it. | N9: `ROLE_NOT_PERMITTED` for the agent key. | **Fixed** (`a8e151a`): allowed for the agent role. Owner should confirm this role assignment. |
| F-5 | Medium | Crash points were compiled into the normal release binary, active when two environment variables were set. | N8. | **Fixed** (`989cefa`). Non-default `fault-injection` feature. The Dockerfile does not enable it. A normal binary refuses to start with either variable set. |
| F-6 | Low | An oversized request is closed without an HTTP 413. | N12: `Broken pipe` on a 5 MB body. | **Open.** The limit is enforced. The response is not a 413 (see R-3). |
| F-7 | Low | The approval-consumption race across two instances was not directly tested. | #501 item "Approval consumption across instances" was NOT VERIFIED. | **Verified** (`a8e151a`): five rounds, exactly one authorization, the other refused with `approval_already_consumed`, chain verifies. |
| F-8 | Low | The principals-required check and the OIDC and key initialisation were reordered, and a text move dropped two startup calls. | The OIDC gate and approval tests failed on `5ec7cf7`. | **Fixed** (`302c6dc`) before the final run. Found by the test suite, not by review. |

No finding was rated Critical. Every High finding has a fix and a test. Negative controls are in `docs/evidence/release-candidate/negative-controls.md`,
which also records what was NOT shown (N6 is inconclusive and is not claimed as a bypass).

## Adversarial review: what was inspected

The review read the implementation for each area named in the request, and checked the claims by running Core:

- **Authentication and tenant isolation.** Authorization status requires an executor principal of the same tenant (`get_execution_authorization_status`).
  Principals are required in production. In dev and staging without principals, any key can post any event type (accepted limit, R-1).
- **Human approval authenticity and single use.** With principals configured, an agent key cannot post `human_approved` (N5). Single use is verified
  across two processes (F-7) and across restarts (crash tests). Without principals, approvals are unauthenticated (R-1).
- **Policy evaluation and authorization issuance.** Consequential calls are refused for unknown or reused approvals (`approval_not_found`,
  `approval_already_consumed`). The approval is checked under the ledger lock.
- **Cryptographic signing and registry trust.** Not changed in this branch. Covered by the existing key-registry suites, which pass.
- **Key rotation and revocation.** Not changed. Covered by the registry PostgreSQL suites (passing). Concurrent issuance during key change across
  processes is NOT VERIFIED (R-6).
- **Authorization replay and substitution.** The receipt and status checks bind to the authorization id, the run, and the call fingerprint.
  Re-use of an authorization after a receipt is refused by the existing gate.
- **Executor claims, leases, fencing, recovery.** Unchanged in this branch; covered by the distributed suites from PR #515 (passing).
- **Receipt authenticity.** Fixed (F-1).
- **Evidence integrity and historical verification.** The ledger chain verifies after every crash, two-instance and receipt test.
- **Fail-open under dependency failure.** Core refuses consequential calls when the anchors are unavailable (`AUTHORIZATION_KEY_UNAVAILABLE`), and
  `/ready` reports 503. No fail-open path was found in the tested configurations.

## Crash consistency

Termination was injected with the release binary built with `--features fault-injection`, at three boundaries of the issuance path:
`before_append`, `after_append_before_sign`, and `after_sign_before_response`.

- No authorization reaches the client from a crashed call (asserted by the client's view; exit code 137 asserted).
- After restart, the committed consequential record exists once, the same event id is refused (409), a new call naming the same approval is
  refused (`approval_already_consumed`), and the chain verifies.
- Test file: `python/tests/test_crash_consistency_core.py`: 4 tests pass (three crash points plus the normal-build control).

Not verified: a crash during the PostgreSQL anchor write during issuance, a crash during key rotation, and a network cut mid-issuance (R-5).

## #501 traceability

The matrix from PR #515 is the appendix of `docs/reports/distributed-execution-2026-11-26.md`. This branch changes these rows:

| Item | Before | Now |
|---|---|---|
| Approval consumption across instances | NOT VERIFIED (direct test) | **PASS** (two processes, five rounds) |
| Receipt authenticity (new row) | not listed | **PASS** for the tested configurations; **PARTIAL**: approvals without principals are still unauthenticated (R-1) |
| Production requires principals (new row) | not listed | **PASS** |
| Wheel includes PostgreSQL schema (new row) | not listed | **PASS** |
| Anti-rollback and same-revision replay (R5, D1–D4, A2) | as in PR #515 | **Unchanged.** Owner decisions still required. Two-volume rollback NOT VERIFIED. |

Issue #501 is **not** closed by this report. The owner decisions D1–D4 and the two-volume test remain open.

## Validation (final HEAD `302c6dc`, plus one test-only commit `bb03393`)

| Suite | Result | Notes |
|---|---|---|
| Rust, all tests with PostgreSQL (`cargo test --no-fail-fast -- --include-ignored`) | **414 passed, 0 failed** | includes `prod_requires_principals` |
| Release and fault-injection builds | pass | `--features fault-injection` build is separate, in `target-fault/` |
| Python, full suite with PostgreSQL and release Core | **1334 passed, 0 failed, 34 skipped** | skips are for external identity providers, Sigstore, and live trust-state Core |
| PostgreSQL integration (destructive, opt-in) | 33 passed | includes nonce, revocation, and audit store |
| Crash consistency (fault build) | 4 passed | normal-build refusal control included |
| Receipt provenance | 4 passed | forged, unissued, agent, and legitimate receipt |
| Two-instance approval | 1 passed (5 rounds) | |
| Container runtime (local, Docker Desktop) | 12 of 16 passed on the final image; see note | |
| Acme Finance validation (binary mode, PostgreSQL) | pass, exit 0 | |
| Customer pilot end to end (release Core, PostgreSQL) | pass, "all checks passed" | |
| `make gate` | pass | |
| `make enterprise-readiness-check` | OK | |
| SDK wheel: build, contents, offline downstream | pass | wheel contains the PostgreSQL migration |
| Security harness, reference-agent suites | included in the Python suite | pass |
| Distributed execution benchmark | not re-run on this branch | the executor code is unchanged from PR #515 (see R-7) |

Container note: 3 of the 16 container tests fail on this workstation with `/health` or `/ready` never answering. The same 3 fail on an image built
from `origin/staging`, with no change from this branch. The CI runner passed 16 of 16 on PR #515's head. The hosted CI run on the final head is
the authority for these tests, and the report does not claim a local pass for them.

## Delivery

Commits on this branch, in order: `c9ca72d` (crash-point tests), `989cefa` (fault gating, receipts, prod principals), `a8e151a` (two-instance
approval test, wheel migration, discovery role), `5ec7cf7` (principal check before policy load), `302c6dc` (restores two dropped startup calls),
`bb03393` (container assertion accepts either production refusal). The release documents are in `docs/release/`, and the negative controls
are in `docs/evidence/release-candidate/`.

## Evaluation gate

Passes when, on the exact final HEAD: the Rust and Python suites pass locally with PostgreSQL; every High finding has a fix and a test; the
negative controls are recorded, including the inconclusive ones; the wheel contains the PostgreSQL schema and passes the offline downstream
check; Acme Finance, the customer pilot, `make gate`, and `make enterprise-readiness-check` pass. Status: these pass locally on `302c6dc` and
`bb03393`, with the container caveat above. The hosted checks on the PR's head are a separate gate, recorded on the PR.

## Human approval gate

Not approved for production by this report. Before any pilot use, the owners must decide and record: that every pilot environment is production
mode or configures principals (staging does not refuse without them, R-1); the ledger topology (one ledger host per tenant; several hosts sharing one
ledger directory are unsupported); the owner decisions D1–D4 in #501; whether `ai_discovery_reported` belongs to the agent role (F-4); and whether the
crash tests, which run only with the `fault-injection` build and are not in CI, must be run as a manual gate before the pilot (R-5). Issue #501 remains
open. Merging into `staging` is a separate decision, and this report does not make it.

## Residual risks

- **R-1 (Medium).** Without principals (dev and staging), any key can post approvals. Receipts are now refused, but approvals are not. Production refuses
  this configuration. The pilot must not run staging without principals.
- **R-2 (Medium).** The policy anti-rollback record is authenticated by the PostgreSQL row, not by its own signature. Lowering the record is detected
  through the row (#501 D2 remains an owner decision).
- **R-3 (Medium).** Core has no server-side request timeout and no concurrency limit. An oversized body is closed without a 413. Load and slowloris
  behaviour were not measured.
- **R-4 (Medium).** Ledger serialization is per host. Several Core instances on different hosts sharing one ledger directory are unsupported.
- **R-5 (Medium).** The crash tests need a `fault-injection` build and are not run by CI. Crashes during the PostgreSQL anchor write, during key rotation,
  and during a network cut mid-issuance are not verified.
- **R-6 (Medium).** Concurrent authorization issuance across processes during a key or policy change is NOT VERIFIED beyond single-process unit tests.
- **R-7 (Low).** The distributed benchmark was not re-run for this branch. Its numbers in PR #515 were taken under heavy unrelated machine load.
- **R-8 (Low).** Container tests are sensitive to the local Docker networking on this workstation.
- **R-9 (Medium).** Exactly-once external effects are not claimed. A downstream system without a deduplication key can apply a retried side effect twice.
- **R-10 (Low).** The SBOM is a lockfile inventory, not a signed CycloneDX document. Reproducible build output was not compared across machines.
- **R-11 (Low).** The Cargo and Python version is `0.2.1`, while the tag `v0.3.0-core-replay-operations` exists. See the release notes for the versioning recommendation.
