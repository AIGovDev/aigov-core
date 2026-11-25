# Customer pilot quickstart for AIGov Core — 2026-11-25

## Scope

Makes AIGov Core evaluable by a prospective enterprise customer without our help or external infrastructure. The
deliverable is a single command, `python examples/customer-pilot/pilot.py run`, that runs a synthetic enterprise workflow
on a local Core, verifies the evidence, writes a customer-facing report, and cleans up. Starts from `origin/staging` at
`db03118` (PR #508 merged). Refs #501, which stays open. No Railway, production, or external infrastructure was
changed. No paid API was used, and no model was run. All identities, keys, and policies are generated per run, and all
data is synthetic.

## Onboarding audit

The existing material was audited before anything was built. The findings are below, and each one was checked against
the repository.

| Finding | Where | What was done |
|---|---|---|
| Six quickstart documents overlap and disagree on the first commands | `docs/quickstart-5min.md`, `docs/customer-onboarding-10min.md`, `docs/customer-quickstart.md`, `docs/pilot-onboarding.md`, `docs/hosted-pilot-runbook.md`, `docs/quickstart-runtime.md` | Not consolidated here, since they serve different audiences. The new pilot guide is linked from the root README's front section |
| No documented way to see the agent authorization path (approval, consequential call, authorization, receipt) from a clean checkout | README, `docs/pilot-onboarding.md`, `docs/quickstart-5min.md` cover the CI compliance gate and verdicts only | Added `docs/customer-pilot.md` and the pilot |
| The trusted reference needs Docker or a release binary, a state-file path, and several separate commands | `examples/agent-reference/README.md` | The pilot runs the whole sequence in one command, with generated state and cleanup |
| Hard-wired to the reference's tools, identities, and policy | `core_trusted.py` (argument digest, sandbox calls), `core_policy.py`, `trust_setup.py` | Generalized with optional parameters; defaults reproduce the reference exactly (see Reuse) |
| Root `docker-compose.yml` uses the fixed key `test-key` | `docker-compose.yml` | Not changed here. It is a local developer convenience, not part of the pilot path, and the pilot generates its own keys. Flagged for a later cleanup |
| The CLI verification and export tools are not connected to the agent workflow | `python/aigov_py/cli.py` | Not connected. The pilot verifies the export offline with the pinned key, which is the check a reviewer needs |

## What was built

- `examples/customer-pilot/pilot.py`: `run` (start, workflow, verify, report, clean up), `run --keep`, `run --binary`, and
  `down`. It writes a report and returns status 1 if any check fails.
- `pilot_config.py`: the synthetic tenant, the three approvers (two on the allowlist, one not), the agent and executor
  identities, the tools, and the pilot's signed-policy document.
- `pilot_launch.py`: Docker mode (private network, PostgreSQL 18, Core from this checkout) and binary mode (a release
  `aigov_audit` and a database URL). Cleanup removes only the pilot's own containers, network, volume, and a state
  directory that carries a marker file.
- `pilot_workflow.py`: the nine steps, the synthetic records, and the executor's side effects.
- `pilot_report.py`: the customer report. Authorization and execution are kept in separate sections, and the limitations
  are printed next to the results.
- `python/tests/test_customer_pilot.py`: five unit tests that need no Core.
- `docs/customer-pilot.md`: the customer guide.
- CI: `.github/workflows/agent-reference.yml` runs the five unit tests with an exact count in the in-process job, and a new
  `customer-pilot` job runs the pilot against a release Core with a PostgreSQL 18 service. That job fails on any failing
  check.

## Reuse, and what changed in the reference

The pilot reuses the trusted-execution code. The reference was generalized, not forked, so the pilot and the reference
share one implementation of each control:

- `core_policy.policy_document` and `write_signed_policy` take optional tools, approvers, policy identifier, and approval
  TTL. The default output is byte-equivalent to the committed `policies/core_policy.unsigned.json`, which a test checks.
- `service/trust_setup.build` takes approver identities, a policy document, a tenant, and principal names. The defaults
  generate the reference's identities.
- `core_trusted`: a tool registry (`register_tool`, `TOOL_ACTIONS`, `resource_of`) replaces the hard-coded
  `TOOL_CAPABILITY_MAP` lookups, and `Executor` takes an optional `performer`. Without a performer, the executor uses
  the sandboxed tools exactly as before.

Verification that the reference behaviour did not change: the 20 in-process tests, the 27 service-backed tests against a
live Core built from the same tree, and the small trusted demonstration all passed (see Regression results).

## Acceptance criteria (measured in the runs)

Each criterion is checked by the pilot on every run. The results below are from the final validation run on this
machine. The pilot's own report is the record for each run.

| Criterion | Result | Evidence |
|---|---|---|
| Unauthorized actions prevented | pass | step 3: delete refused (`tool_not_permitted`); the record is unchanged |
| Human oversight enforced | pass | step 2: export held (`approval_not_found`); step 6: export runs only after the steward's approval |
| Approval impersonation prevented | pass | step 4: self-approval (`role_not_permitted`), outsider (`approver_not_allowlisted`), identity claim (`approver_identity_mismatch`) each refused |
| Execution replay prevented | pass | step 7: the same authorization is refused by the executor; the export is not repeated |
| Evidence independently verifiable | pass | Core's chain check passes; offline checks on the export and the pinned public key pass for every authorization; each receipt matches an issued authorization, one receipt each |
| Core unavailability handled safely | pass | step 9: the agent fails closed (`INDETERMINATE`), the executor refuses (`core_unavailable`), the record is unchanged, and the same authorization runs once after recovery |
| Latency measured and reported | pass | each step records Core and executor timings; see Timings |

## Timings

Core ready (including any image build), and the workflow total, from the saved reports of three consecutive runs on the
validation machine:

| Measure | Run 1 (builds the image) | Run 2 (image present) | Run 3 (image present) |
|---|---|---|---|
| Core ready (seconds) | 7.71 | 6.03 | 5.96 |
| Workflow total (ms) | 104.8 | 112.9 | 113.6 |

Run 1 built the image, but Docker reused cached layers from earlier builds of this checkout. A build from an empty cache
was not timed, so no cold-start build time is claimed. The per-step Core and executor timings are in each run's report.
These are one machine and three runs. They are not a capacity claim.

## Clean-checkout validation

The committed branch was cloned into an empty directory. A fresh virtual environment was created and the package was
installed from that clone. The pilot's Core image was removed first, so the run built it from the clone's files. Then
the pilot unit tests and the full pilot were run.

Environment: a clone of commit `02d9a4b`, a fresh virtual environment (Python 3.13; CI uses 3.12), and the package installed
with `pip install -e "./python[dev,agent-reference]"` from the clone. The first attempt used a Homebrew interpreter whose
`ensurepip` is broken on this machine; that attempt created no pilot result and was repeated with a working interpreter.

Results: the five pilot unit tests passed. The full pilot ran from the clone with `pilot.py run`, built `aigov-core:pilot`
from the clone's files (the image had been removed first), and passed every check. Core was ready in 4.18 seconds, and the
report has 45 passing check rows and no failing rows. The workflow total was 149.8 ms. Cleanup removed the containers,
network, volume, and state directory. No credential, configuration, or prepared state from this machine was used: the
run generated its own.

## Regression results

| Check | Result |
|---|---|
| In-process reference tests (`test_agent_reference_integration.py`) | 20 passed |
| Service-backed reference tests against a live Core built from this tree (`test_agent_reference_core.py`, `AIGOV_REF_REQUIRE_CORE=1`) | 27 passed |
| Pilot unit tests (`test_customer_pilot.py`) | 5 passed |
| Small trusted demonstration, as CI runs it (`run_core_demo.py --cases 2`) | completed |
| Staging policy harness, local simulation (`scripts/staging_policy_verify.py --skip-live`, against a throwaway PostgreSQL 18) | 66 passed, 0 failed |
| `make gate` (report gate) | passed |
| Rust code | not changed in this set; the Rust suite is unchanged |

The harness was run against a throwaway PostgreSQL 18 container on a free local port. It was not run against any shared
database. A first attempt used a port already taken by another server; the harness only failed password authentication
there, and nothing was executed against it.

## Limitations

These are the same limitations printed in every pilot report. Each is also stated in `docs/customer-pilot.md`.

- Synthetic data only. The pilot does not connect to any system of the customer's.
- Identities and approver names are static configuration, with no identity provider.
- API keys are bearer secrets. They are generated per run and removed at the end.
- Core's policy-signing and authorization keys are environment secrets in the pilot. A deployment must hold them in a
  managed key store and rotate the pinned authorization key.
- The executor is a local process with a local SQLite store. Several executors need a shared store with the same atomic
  reservation.
- Revocation stops an authorization that the executor has not yet checked. It does not stop a side effect that has begun,
  and it does not undo a completed one.
- Exactly-once execution across external systems is not claimed. A crash between a side effect and its receipt leaves a
  reservation with no receipt, which an operator must reconcile.
- The approval window is 30 seconds, a demonstration value.
- The pilot is not a certification and does not establish compliance with any regulation, including the EU AI Act.

## Evaluation gate

Passes when: the pilot runs end to end from a clean checkout in a clean environment without undocumented credentials or
prepared state; every acceptance criterion passes in the run; the reference's tests still pass and execute with none
skipped, with the reference behaviour unchanged; the harness and `make gate` pass; and the CI jobs pass on the final
HEAD. Every item in this report is true of the committed tree, as recorded above.

## Human approval gate

Not approved for production by this report. The pilot is an evaluation aid. Before any production use, a deployment
needs the items listed under Limitations: an identity provider for approvers and the executor, a managed key store with
rotation for the authorization key, a shared executor store with the same atomic reservation, reconciliation of
reservations without receipts, and a reviewed approval window. The open decisions in issue #501 still apply. Merging this
branch into `staging` is a separate decision.
