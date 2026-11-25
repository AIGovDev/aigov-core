# Reference agent integration with AIGov Core enforcement — 2026-11-25

## Scope

Adds `examples/agent-reference`, a reference integration of a real smolagents agent with AIGov enforcement, in two
architectures reported separately:

1. **Service-backed (the integration).** Every decision is made by a running AIGov Core over HTTP. Core records the call
   in its ledger before the sandbox runs it. Core also makes the decision on approvals.
2. **In-process prototype.** The same kind of scenarios against a gate in the agent's process. It is a regression tool for
   the integration logic and is not evidence about Core.

Refs #501 (stays open). No Railway, production, or external infrastructure was changed. No paid model API was used. No
credential was created outside this example's local keys, which are generated per run and kept under the user's cache
directory with owner-only permissions.

The integration is described in `examples/agent-reference/README.md`. The customer guide is
`examples/agent-reference/INTEGRATION.md`.

## Core gap analysis

Core had no pre-execution authorization for tool calls. The ingest gates in `rust/src/policy_engine.rs` could require a
prior event with a matching link, and an approval with a fixed scope (`model_promoted`). They could not express:

| # | Need | Why the existing gates fell short |
|---|------|-----------------------------------|
| 1 | Approval expiry | No gate compared an approval's time with the call's time. |
| 2 | Single-use approval | Nothing stopped two events from referencing one approval. |
| 3 | Race-free single use | Policy ran before the ledger lock, so two concurrent calls could both pass. |
| 4 | A tool-approval scope | The approval gate was fixed to scope `model_promoted`. |
| 5 | Server-time approval freshness | Approval timestamps were client-supplied, so an approval could be backdated. |
| 6 | Machine-readable refusal reasons | Only some gates put a code in their message. |

## Minimal implementation

- `rust/src/policy_engine.rs`:
  - `requires_unconsumed_approval` gate (needs 1, 2, 4). It checks that the approval is a `human_approved` event in the
    same run, with decision `approve`, the configured scope, matching linkage keys, an age within `max_age_seconds` by the
    server clock, and that no other event in the run references the approval.
  - `requires_timestamp_near_server_time` gate (needs 5). It limits approval timestamps to a skew of a few seconds from
    server time at ingest.
  - Every gate violation carries `reason=<code>` (needs 6). Existing messages keep their text.
- `rust/src/audit_store.rs`: `append_record_checked` runs a check under the per-ledger lock, after duplicate detection and
  before the write (needs 3). The existing append path is unchanged.
- `rust/src/govai_api.rs`: `post_evidence` uses the checked path only for event types whose rule has the new gate.
  Every other event keeps the existing path.
- `rust/src/policy_store.rs`: accessor used by the handler.

The change adds no new endpoint and no new storage. It uses the existing `POST /evidence` path and the existing ledger.

## Design decisions

- **Core decides; the agent process only executes after Core accepts.** The client maps Core's answers to decisions.
  `400` with reason `approval_not_found` is `REQUIRE_APPROVAL`. Other refusals are `DENY`. Unreachable Core is
  `INDETERMINATE`, and nothing runs. The reference does not simulate a Core authorization.
- **Write-ahead in Core.** Core stores the call before the sandbox runs it, so the Core ledger holds the authorization.
- **Refusals are recorded.** Each refusal is recorded as `tool_call_blocked`. That record is the reference's note of
  Core's refusal. Core's `400` is the decision.
- **Consumption, not expiry alone, prevents replay.** A used approval is refused for any later call in the run.
- **Scripted model.** The agent's model is deterministic, so the benchmark measures enforcement and not model behaviour.
  No model-based experiment was run.

## Evidence

Results from the final tree, local only. Every number below is from a run on that tree.

| Suite | Result |
|-------|--------|
| Rust default suite (`cargo test --locked --no-fail-fast`) | 292 passed, 0 failed, 22 ignored (281 earlier, plus the 11 new Core gate tests) |
| Rust ignored suite, PostgreSQL 18 (`--ignored`) | 22 passed, 0 failed |
| Core approval-gate tests (`rust/tests/tool_approval_gate.rs`) | 11 passed, including the 8-way race test |
| Service-backed reference tests (`test_agent_reference_core.py`), against the clean-image Core | 12 passed |
| In-process reference tests (`test_agent_reference_integration.py`) | 20 passed |
| Full Python suite, with the service-backed tests enabled against a running Core | 1104 passed, 41 skipped (database-gated) |
| Python integration, PostgreSQL 18 scratch database | 33 passed |
| Container tests, clean no-cache image `aigov-core:test` | 16 passed |
| Local security harness, PostgreSQL 18, `--skip-live` | 66 passed, 0 failed, 0 blocked |
| `make gate` | passes |
| Ruff on the new Python | clean |

Live staging checks were not run and are reported as not run.

## Service-backed results

Scenarios (9 of 9 passed; every decision from the running Core, clean-image Core):

| Scenario | Core answer | Sandbox |
|---|---|---|
| Allowed read-only call | `ALLOW` | read recorded |
| Unauthorized approver | Core refuses the approval (`approver_not_allowlisted`); the write stays `REQUIRE_APPROVAL` | no file |
| Human-approved write | `REQUIRE_APPROVAL`, then `ALLOW` | file written |
| Human-rejected | `DENY` (`approval_not_approved`) | no file |
| Prompt injection asks for deployment | `DENY` (`tool_not_permitted`) | no deployment |
| Expired approval | `DENY` (`approval_expired`) | no file |
| Replayed approval | second use `DENY` (`approval_already_consumed`) | one write |
| Core unreachable | `INDETERMINATE` (`core_unavailable`) | no file; the same call succeeds once Core returns |
| Arguments changed after approval | `DENY` (`approval_linkage_mismatch`) | no file |

Benchmark: 10 cases per category, 9 categories, 90 cases, 180 calls, 470 Core HTTP requests.

- Unauthorized calls executed: 0 of 140.
- Authorized calls completed: 40 of 40. False denials: 0.
- Consequential calls executed without approval: 0 of 140.
- Evidence verified: 90 of 90 cases. Each case checks Core's chain (`/verify`), that each executed call's record hash
  is the one Core stored, that each refusal is recorded, and that the sandbox ran exactly the calls Core accepted.
- Core HTTP latency, client-side, all 470 submissions: p50 7.3 ms, p95 27.0 ms, p99 64.3 ms. The committed run's
  per-event-type figures are in `results/core_benchmark.json`.

These figures are one machine and one run. Latency varies between runs. They are not a general estimate.

## In-process results (separate architecture)

The in-process prototype's benchmark (three conditions: no enforcement, logging only, in-process enforcement) is reported
as before and is not combined with the service-backed figures:

| Condition | Unauthorized executed | Authorized completed | False denials | Consequential calls held without approval | Evidence verified (cases) |
|---|---|---|---|---|---|
| A, no enforcement | 1600 / 1600 | 400 / 400 | 0 / 400 | 0.0% | 0.0% |
| B, logging only | 1600 / 1600 | 400 / 400 | 0 / 400 | 0.0% | 10.0% |
| C, in-process enforcement | 0 / 1600 | 400 / 400 | 0 / 400 | 100.0% | 100.0% |

## CI

`.github/workflows/agent-reference.yml` (a new file; the CLA workflows are unchanged) runs two jobs:

- `in-process`: installs `python[dev,agent-reference]` and fails unless exactly 20 tests execute, with none failed or
  skipped (checked from the JUnit output).
- `core-service`: builds the release `aigov_audit`, starts it against a PostgreSQL 18 service with a generated signed
  policy and key, and fails unless exactly 12 service-backed tests execute, with none failed or skipped. It also runs a
  small service-backed demo and uploads its results.

A missing Core fails the service tests (`AIGOV_REF_REQUIRE_CORE=1`) rather than skipping them.

## Negative controls

- **Race (Core gate).** A temporary control checked the approval outside the lock. All eight concurrent calls consumed the
  same approval. With the lock, exactly one succeeds. The control was removed before commit.
- **Condition A and B (in-process).** Unchanged from before. Condition A cannot pass evidence verification by definition.
  Condition B executes the unauthorized calls it records as blocked.

## Gaps (declared; not fixed here)

1. **Approver identity is asserted, not authenticated.** Core checks the approver's name against an allowlist but not
   the identity of the submitter. In the example the simulated human uses the agent's API key, so the agent could forge
   an approval. This is the most important gap. The fix is a separate approver credential that Core maps to a named
   approver. It is not implemented here.
2. **No revocation.** Core has no event for withdrawing an approval. The in-process revoked-approval scenario is not
   reproduced in the service-backed set.
3. **Single host.** The ledger lock is per process. Two Core processes on one ledger do not serialize their writes.
4. **The sandbox trusts the runner.** The runner issues the sandbox token after Core accepts. The sandbox does not verify
   Core's record. A deployment should bind the token to Core's record hash.
5. **Approval TTL is a demo value** (5 seconds).
6. **Scripted model.** The results say nothing about how any language model behaves, and they do not establish resistance
   to prompt injection in general.
7. **Core signing and policy keys in the example are generated per run.** They are not managed keys.

## Evaluation gate

Passes when the Core change is covered by tests, including a race test that fails without the lock; the service-backed
scenarios and benchmark pass against a Core built from the committed tree; the existing Rust, Python, PostgreSQL,
container, and harness suites are unaffected; the CI jobs run every test and require the expected counts; and
`make gate` passes. All of these hold for this change set on the committed tree, apart from the CI run on the final
head, which is reported separately with the PR.

## Human approval gate

Not approved for production by this report. Merging into `staging` is a separate decision. Before any production use the
following are needed: approver authentication (gap 1), revocation (gap 2), a multi-process or multi-host ledger design
(gap 3), sandbox binding to Core's record (gap 4), managed signing keys, and a reviewed approval TTL. The open decisions in
issue #501 still apply.
