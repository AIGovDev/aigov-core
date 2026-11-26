# Enterprise pilot integration for AIGov Core — 2026-11-25

## Scope

Makes it possible for a prospective enterprise customer to integrate their own agent and tools with AIGov Core. Starts
from `origin/staging` at `e114e7a`, which includes PR #509 (the customer pilot quickstart, merged; verified before any
work). Refs #501, which stays open. No Railway change, no external infrastructure, no paid API, no deployment, and no
merge. All data is synthetic, and all identities, keys, and policies are generated per run.

## What was inspected before anything was built

| Surface | What it provides | Finding |
|---|---|---|
| SDK, `python/aigov_py/runtime/client.py` | `RuntimeGovernanceClient`: submit evidence, compliance summary | Evidence submission only. It has no approval, authorization, status, export, or verification calls |
| Reference Core client, `examples/agent-reference/.../core_gate.py` | `CoreClient`: decisions from Core's answers, status, verify, export | Holds the trusted-execution HTTP calls. Not in the SDK |
| Trusted executor, `.../core_trusted.py` | Actors (`AgentActor`, `ApproverActor`), `Executor`, `ExecutionStore`, offline checks | Holds the verification, reservation, and receipt logic |
| Policy builder, `.../core_policy.py` | Signed policy from tools, approvers, and TTL | Already parametrized for the pilot |
| Launcher, `examples/customer-pilot/pilot_launch.py` | Docker and binary Core startup with generated state | Fixed resource names. Not safe to run beside another Core |
| HTTP API, `rust/src/govai_api.rs` | `POST /evidence`, `GET /verify`, export, authorization status | Used through `CoreClient`; not changed |
| Customer pilot | Nine-step workflow, report, one command | The reference for the new interface |
| Integration docs | `examples/agent-reference/INTEGRATION.md`, `docs/customer-pilot.md` | Covered the design, not how a customer adapts it |

Conclusion: the trusted-execution capabilities already exist, in the reference package and not in the SDK. Building a
second implementation would duplicate them, so the new interface composes them. Moving them into `aigov_py` is a real
option for later (see Blockers, item 5). It is not done here, because it would be a larger change to a shared package.

## What was built

- `examples/customer-integration/aigov_integration.py`: the interface. `IntegrationConfig` describes tools, approvers, and
  identities, rejects unsafe settings at definition time, and generates the signed policy and per-run keys. `Integration`
  exposes `call`, `request_approval`, `approve`, `revoke`, `execute`, `export`, and `verify`. `start_core` and
  `stop_core` manage a Core whose resource names are unique to that call. About 300 lines, none of which is
  security logic.
- `examples/customer-integration/acme/app.py`: a separate example customer application (Acme Finance accounts payable). It
  defines its tools, a synthetic ledger as the performer, and the payment flow. 123 lines.
- `examples/customer-integration/acme/validate.py`: runs the required validation against a real Core, prints the reason for
  each check, and writes `validation.json` and `validation.md`. Exits 1 on any failure.
- `examples/customer-integration/quickstart.py`: a minimal, adaptable integration. The customer-owned parts are marked.
  Supports Docker and binary modes.
- `docs/customer-integration.md`: the integration guide (credential separation, policy configuration, flow, trust
  boundaries, failure handling, evidence export, measured effort).
- `docs/customer-pilot-acceptance.md`: the acceptance checklist, with supported capabilities in one table and production
  limitations in another, and a command for each item.
- `python/tests/test_customer_integration.py`: 10 tests that need no Core.
- CI: the in-process job runs the 10 integration unit tests with an exact count. The `customer-pilot` job runs the Acme
  validation and the quickstart against a release Core, each on its own database. Both fail the job on failure.

## Changes to existing code

All changes keep existing behaviour. Each is checked by the regression suites below.

- `examples/customer-pilot/pilot_launch.py`: the name prefix and the state generator are parameters. The defaults are the
  pilot's names and generator, so the pilot is unchanged. `stop` removes only resources with the given prefix.
- `examples/agent-reference/aigov_agent_reference/core_trusted.py`: `offline_evidence_checks` moved here from the pilot,
  so the pilot and the integration share one copy. The pilot now imports it.
- `examples/customer-pilot/pilot_workflow.py`: calls the moved function. No other change.

Core, the Rust code, the SDK, and the HTTP API are unchanged.

## Requirements and where each is met

1. **Reusable integration interface for customer tools, using existing SDK components.** `aigov_integration.py`, built on
   the reference's actors, executor, and policy builder. No new security logic.
2. **Policy enforcement, authenticated approval, authorization verification, receipts.** Core enforces the policy. Each
   approver authenticates with its own key. The executor verifies the authorization before it acts, and records a
   receipt. Shown by `validate.py` and the quickstart.
3. **Separate example customer application, without changing Core internals.** `acme/` uses only `Integration`.
4. **Documentation of credentials, policy, trust boundaries, failure handling, evidence export.**
   `docs/customer-integration.md`, sections 2 to 7.
5. **Minimal integration example.** `quickstart.py`.
6. **Measured integration complexity and onboarding blockers.** Section "Measured effort" and "Blockers" below.
7. **Customer pilot acceptance checklist; supported versus production limitations.**
   `docs/customer-pilot-acceptance.md`.

## Validation

The validation runs eight cases, each on a fresh run with its own ledger and executor store, against a Docker Core built
from this tree. Result from the final run: **8 of 8 cases passed, 38 of 38 checks passed**, Core ready in 2.61 s, whole run
2.79 s, cleaned up with its own prefixed resources.

| Case | What it tests | Result and reason |
|---|---|---|
| authorization | a read runs; an approved payment runs once | `executed`; payment recorded once |
| rejection | a rejected request does not run | `approval_not_approved`; no payment |
| approval | a claimed identity is refused; an agent credential cannot approve; an authenticated approval is recorded | `approver_identity_mismatch`; `role_not_permitted`; `accepted` |
| revocation | only the approver can revoke; a revoked approval cannot authorize; revocation after issue stops execution | `revocation_not_by_approver`; `approval_revoked`; `authorization_revoked` |
| replay | a second use of the authorization, and of the approval, is refused | `authorization_receipt_recorded`; `approval_already_consumed`; one payment |
| modified arguments | Core refuses a changed call; the executor refuses a changed authorization; the approved arguments still run | `approval_linkage_mismatch`; `authorization_arguments_mismatch`; `executed` |
| core unavailable | the agent fails closed; the executor refuses; nothing runs; the same authorization runs once after recovery | `INDETERMINATE`; `core_unavailable`; one payment |
| independent verification | Core's chain check; offline signature, binding, scope, and receipt checks; a changed authorization is detected | all pass; tampering detected |

Each check asserts the reason it expects, and the report prints the actual reason Core or the executor returned, so a mismatch shows up in both places.

Regression, all on the final tree:

| Check | Result |
|---|---|
| Reference in-process tests | 20 passed |
| Reference service-backed tests, live Core from this tree | 27 passed |
| Customer pilot unit tests | 5 passed |
| Customer integration unit tests | 10 passed |
| Customer pilot end to end, after the launcher change | 45 rows pass, 0 fail |
| Small trusted demonstration (CI form) | completed |
| Staging policy harness, `--skip-live`, throwaway PostgreSQL 18 | 66 passed, 0 failed |
| `make gate` | passed |

## Measured effort

Measured on the validation machine, for the quickstart, counting non-blank, non-comment lines:

- Configuration (section 1): 11 lines.
- Performer (section 2): 11 lines.
- Flow: 40 lines. About 10 of them are Core start and stop plumbing, and the rest is the flow. The flow makes 7
  integration calls.
- The Acme application: 123 lines, including its ledger and approval flow.

These measure one example. The remaining effort is in the customer's performer, identity and key management, and approval
process. They are not an estimate for a customer's system.

## Blockers found

These are the obstacles a customer would hit. Each one was found by running the material, and each has an owner below.

1. **Docker Desktop does not share the system temporary directory.** The first quickstart run used Python's temporary
   directory. Core's policy mount came up empty, and Core exited. The quickstart now uses the home cache, as the validator
   does, and the docs say why. Owner: this change. Customers on Docker Desktop must not place state under a temporary
   directory.
2. **A failed Core start left resources behind.** The caller never received the resource prefix, so nothing removed the
   containers. `start_core` now removes its own partial resources on any failure. Owner: this change.
3. **Fixed resource names collide.** Two Cores on one machine share container names, and `stop` could remove the other's
   resources. Names are now unique per call, and `stop` takes the prefix. Owner: this change.
4. **Shared database state.** Core keeps policy history in its database. We did not test two policies on one database. The
   CI jobs use a fresh database for each integration run, which removes that question for the runs. A customer should do the
   same until it is tested. Owner: open for a test.
5. **The trusted layer lives in an example package, not the SDK.** Customers installing `aigov_py` get evidence submission
   but not approval, authorization, or the executor. They must depend on `examples/agent-reference`. This is the largest
   onboarding blocker. Moving the code into the SDK is a planned change to a shared package, not done here. Owner: open.
6. **Approval and authorization calls are not in any published client.** A customer's developers must learn the
   trusted-execution flow from the examples. The guide and the quickstart address this. Owner: open for a stable client API.
7. **Local interpreter issue (environment, not product).** On this machine, Homebrew's Python could not create a virtual
   environment, because `ensurepip` failed. A working interpreter was used. Recorded here because a customer's machine may
   hit the same problem. Owner: the customer's environment.

## Limitations

These are the production limitations that the acceptance checklist states, section 2. In short: static identities with
no identity provider; bearer API keys; keys held as environment secrets; a local SQLite executor store, on one host; a
revocation window between the executor's status check and the side effect; no exactly-once claim across external systems;
a 30-second approval window; timings from one machine. The pilot is not a certification and does not establish compliance
with any regulation, including the EU AI Act.

## Evaluation gate

Passes when: the interface lets a customer integrate their own tools without Core internals, shown by a separate example
application; each required behaviour (authorization, rejection, approval, revocation, replay, modified arguments, Core
unavailability, independent verification) is tested against a real Core and its result is recorded with Core's reason; the
reference and pilot regression suites pass with no behaviour change; the staging harness and `make gate` pass; the
integration's effort is measured, not estimated; the blockers are stated with owners; and CI runs the integration tests
with none skipped. These hold for the committed tree as recorded above, subject to CI on the final HEAD.

## Human approval gate

Not approved for production by this report. The integration is ready for a customer pilot on synthetic data. Before a
customer uses it with real systems, the production items in `docs/customer-pilot-acceptance.md` section 2 must be
addressed, and a reviewer must sign off the executor's store, key management, and approval window. Blocker 5 (the trusted
layer in an example package) must be resolved before a customer depends on it as a library. Merging this branch into
`staging` is a separate decision, and this report does not make it.
