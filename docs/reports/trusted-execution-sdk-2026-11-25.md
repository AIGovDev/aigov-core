# Trusted execution in the AIGov SDK — 2026-11-25

## Scope

Moves the reusable trusted-execution layer from `examples/agent-reference` and the customer examples into the official
Python SDK, `aigov-py`, as `aigov_py.trusted`. Starts from `origin/staging` at `c91c906`, which includes PR #510 (merged;
verified before any work). Refs #501, which stays open. No Railway change, no external infrastructure, no paid API, no
deployment, and no merge. The Rust service and Core are unchanged.

## Audit of the existing SDK before implementation

| Surface | Finding |
|---|---|
| `aigov_py.runtime.client.RuntimeGovernanceClient` | Evidence submission and a compliance summary. Used by the new client, not duplicated |
| `aigov_py.canonical_json`, `aigov_py.policy_bundle_signing` | Canonical bytes and policy signing. Used as they are |
| `python/pyproject.toml` | Packages `aigov_py*` and `govai*`. A new subpackage ships automatically; `examples/` never ships |
| Reference trusted layer (`core_trusted.py`, `core_gate.py`, `core_policy.py`, `trust_setup.py`) | Imported three example-only modules (`sandboxed_tools`, `execution_token`, `tool_gateway`). The argument digest came from `sandboxed_tools`, a security contract; the capability map and the sandbox are benchmark data |
| Customer integration (`aigov_integration.py`, `pilot_launch.py`) | Customer applications imported the interface from `examples/`; the launcher had fixed resource names |

Decision: the digest is reimplemented in the SDK byte-for-byte; the benchmark sandbox and capability map stay in the
example. Nothing security-relevant is duplicated: the reference now delegates to the SDK.

## What moved

`python/aigov_py/trusted/`, 12 modules:

- `core.py`: `Decision`, `CoreDecision`, `CoreClient`, `new_event`. The decision mapping is the reference's, unchanged.
- `tools.py`: `ToolSpec`, `tool_registry`, `args_binding_hash`, `resource_id`. The digest is the reference's formula.
- `authorization.py`: the domain, the schema check, the signature check, `Refused`. Unchanged.
- `store.py`: `ExecutionStore`. The reservation is atomic and unchanged. It no longer creates its table (see Decision 1).
- `executor.py`: `Executor`, `ExecutionOutcome`, `result_digest`. The same order of checks, with one addition (below).
- `actors.py`: `AgentActor`, `ApproverActor`. Take an explicit tool registry.
- `evidence.py`: `offline_evidence_checks`. Moved verbatim from the reference's source.
- `policy.py`: `build_policy_document` (the reference's document, with every constant a parameter), signing helpers.
- `provision.py`: `provision`, `load_state`. The per-run keys and Core environment.
- `launch.py`: `start_docker`, `start_binary`, `stop`, `prepare_state_dir`. Resources carry a caller-chosen prefix.
- `integration.py`: `IntegrationConfig`, `Integration`, `start_core`, `stop_core`.
- `migrations/0001_executor_store.sql`: the executor store schema, as package data (see Decision 1).

Public names are listed in `aigov_py/trusted/__init__.py` (`__all__`, 32 names). `docs/trusted-execution-sdk.md` documents
them.

## Preservation of trust boundaries and enforcement semantics

Each item was checked by a test or a run, not by inspection alone.

- **Argument digest.** Five golden values recorded from the reference before the move; the SDK reproduces each one
  (`test_trusted_sdk.py`). A changed field changes the digest.
- **Authorization domain and signature.** A signature without the domain is refused; a signature from another key is
  refused; a tampered payload is refused; a wrong schema is refused.
- **Executor refusals before any side effect.** Audience, run, tool, argument digest, and expiry each refuse with the
  reference's reason; a forged authorization is refused before anything else. Verified with a Core stand-in that fails the
  test if it is contacted.
- **Single use.** Eight concurrent reservations of one authorization: exactly one succeeds.
- **Credential separation.** Each principal gets its own key and role. The authorization seed is not in any state
  handed to an actor.
- **One addition.** An unregistered tool is refused (`tool_not_registered`) before the digest is computed. The reference
  previously raised a `KeyError` in that case.
- **Reference behaviour.** The reference's 20 in-process tests, its 27 service-backed tests against a live Core, and the
  small trusted demonstration all pass through the new adapters, with no change to their expectations.

## Decision 1 (needs your review): the executor store's schema

The repository's schema policy (`docs/operations/runtime-schema-ownership.md`) says shipped packages must not create
database tables at runtime. The test `python/tests/test_runtime_ddl_boundary.py` enforces it. My first version created
the executor's table in the package, and the full suite failed on that test. I did not weaken the test or move the module
out of the shipped set.

The change that follows the policy:

- The store checks that its table exists and refuses to start otherwise (`ExecutionStoreSchemaError`).
- The schema is a versioned migration, `0001_executor_store.sql`. An operator applies it once, before first use, using
  `executor_store_migration()`. Re-running it is safe.
- The migration ships as package data. Nothing in the package executes it.

The policy names `rust/migrations/` as the owner of production schema, applied out of band. A SQLite executor store is
customer-operated local state, not the Rust service's database, so this placement is my judgement. Please decide whether
the migration belongs under `rust/migrations/`, or under a separate versioned location, or whether the executor store
should stay out of the shipped SDK until the repository owners review it.

## Packaging and downstream consumption

- The wheel (`aigov_py-0.2.1-py3-none-any.whl`) contains the 12 trusted modules and the migration. It contains no code from
  `examples/` or the reference (checked by name in the build step and in CI).
- The wheel was built from this tree and installed into a clean Python 3.12.3 environment created with `uv`, outside the
  repository. `aigov_py` loads from site-packages.
- `scripts/trusted_sdk_downstream_check.py` is a customer-style consumer. It imports only `aigov_py.trusted`, refuses to
  run if the repository is on the path, and runs two checks: offline (signature, tampering, refusal before any Core call)
  and live (a Core that the run starts and removes, with its own prefix and database).
- The version is unchanged at 0.2.1. A version bump is a release decision and is not made here.

## Customer examples migrated

- `examples/customer-pilot/`: the configuration, the launcher, and the workflow use the SDK. The launcher is a wrapper that
  keeps the pilot's prefix and builds Core's image from the checkout when it is missing. The pilot's policy now has its
  own issuer name, and its outsider approver is a real unlisted approver (a credential the policy does not allow).
- `examples/customer-integration/`: `aigov_integration.py` is removed. `acme/app.py`, `acme/validate.py`, and
  `quickstart.py` import `aigov_py.trusted`. Customer code imports nothing from `examples/`.
- `examples/agent-reference/`: `core_gate.py`, `core_policy.py`, `core_trusted.py`, `gate.py`, and `service/trust_setup.py`
  are thin adapters over the SDK. They keep the reference's names, its default labels, and its benchmark sandbox.

## Defects found and fixed during the work

1. The executor store created its table at runtime, which the boundary test rejected (Decision 1).
2. The quickstart created its state directory before the launcher, so the launcher's safety check (which refuses to remove
   a directory it did not create) rejected it. The launcher now creates the directory with its marker.
3. The downstream check used a temporary directory, which Docker Desktop cannot mount. It uses the home cache, as the
   other examples do.
4. The shared virtual environment's editable install pointed at a different checkout, so the reference's Core launcher
   imported a package without `aigov_py.trusted`. I created a dedicated Python 3.12.3 environment for this work and did not
   change the shared one.
5. Two CI-facing counts changed with the work: the pilot's unit tests are now 6, and the SDK adds 27. Both are set in
   the workflow.

## Validation

Final tree. Each result below was produced by the command named, on this tree.

| Check | Result |
|---|---|
| No-Core suites: reference in-process (20), pilot (6), integration (10), SDK (27) | 63 passed |
| Full Python suite (`pytest python/tests`) | 1142 passed, 61 skipped, exit 0 (the one earlier failure, Decision 1, is resolved) |
| Reference service-backed tests, live Core, through the adapters | 27 passed |
| Reference small trusted demonstration | completed |
| Acme Finance validation, Docker Core | 8 of 8 cases, 38 of 38 checks |
| Quickstart, Docker Core | evidence checks pass; cleaned up |
| Customer pilot end to end, Docker Core | 45 pass rows, 0 failing |
| Downstream check, offline, from the installed wheel | passed |
| Downstream check, live, Docker Core, from the installed wheel | refund executed once; 10 evidence checks pass |
| Binary-mode rehearsal of CI, three separate databases on a throwaway PostgreSQL 18 | Acme, quickstart, and downstream all pass |
| Two Cores at once (quickstart and Acme), separate prefixes | both pass; each cleaned up only its own resources; none left behind |
| Staging policy harness, `--skip-live`, throwaway PostgreSQL 18 | 66 passed, 0 failed |
| `make gate` | passed |
| Lint and format of changed Python (ruff) | clean |

The throwaway PostgreSQL containers were created for this run and removed afterwards. Each run's Core resources were
removed by its own `stop`, using its own prefix.

## Limitations

These hold for the SDK as shipped. The same list is in `docs/trusted-execution-sdk.md`.

- Identities are configuration, with no identity provider. API keys are bearer secrets. Signing keys are generated per
  run for evaluation; production keys must come from a managed store and be rotated, with the pinned authorization public key.
- The executor's store is local SQLite on one host, and the operator must apply the migration before first use.
- Revocation does not stop a side effect that has begun, and does not undo one that has completed.
- No exactly-once execution across an external system. A crash between a side effect and its receipt needs reconciliation.
- The approval window in the examples is 30 seconds, a demonstration value.
- Timings come from one machine and a few runs.
- Not a certification and not a statement of regulatory compliance.

## Evaluation gate

Passes when the SDK exposes stable public interfaces for agent, approver, and executor integrations; customer applications
and the reference import nothing from `examples/` (the reference's adapters import the SDK, and the SDK imports nothing from
`examples/`, checked by a subprocess test); the trust boundaries and enforcement semantics are preserved (golden digests,
refusal reasons, single use, credential separation, and the reference's 27 live-Core tests); a wheel built from the tree
installs into a clean Python 3.12 environment and passes the downstream checks offline and live; two Cores with separate
databases run without touching each other; the full suite, the affected suites, the harness, and `make gate` pass; and CI
runs the same checks on the final HEAD. These hold for the tree recorded above, subject to CI on the final HEAD.

## Human approval gate

Not approved for production by this report. The SDK is ready for customer evaluation on synthetic data. Before a customer
depends on it in production, the items in the Limitations section must be addressed, and the repository owners must decide
Decision 1 (where the executor store's migration lives, and whether the store ships). Merging into `staging` is a separate
decision, and this report does not make it.
