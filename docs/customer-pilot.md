# AIGov Core customer pilot

A self-contained evaluation of AIGov Core on **synthetic data**. You run one command on your own machine. It starts a
local AIGov Core, runs an enterprise workflow that reads and changes customer records under policy, shows that
unauthorized and unapproved actions are refused, exports the evidence, verifies it, writes a report, and removes what it
created.

It does not contact any external system, does not use a model API, and does not need an account, a hosted service, or
any credential you supply. Every identity, key, and policy is generated for that run.

This pilot is not a certification and does not establish compliance with any regulation, including the EU AI Act.

## What you need

- Python 3.10 or newer (tested on 3.12)
- Docker, running
- This repository, checked out
- The first run also builds the Core image from this checkout, which takes several minutes (the Rust release build).
  Later runs reuse the image.

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e "python[agent-reference]"
```

## Run it

```bash
python examples/customer-pilot/pilot.py run
```

That is the whole evaluation. When it finishes you get a report at
`pilot-output/<timestamp>/pilot-report.md`, the evidence in `pilot-output/<timestamp>/evidence/`, and a clear exit code:
`0` when every check passes, `1` when any check fails.

Options:

| Command | What it does |
|---|---|
| `pilot.py run` | Start Core, run the workflow, verify, report, clean up |
| `pilot.py run --keep` | Same, but leave Core running so you can query it. Remove it with `pilot.py down` |
| `pilot.py run --out <dir>` | Write the report and evidence to a directory you choose |
| `pilot.py run --binary <aigov_audit> --database-url <postgres url>` | Use a release Core binary and a PostgreSQL database you provide, with no Docker |
| `pilot.py down` | Remove a kept run |

Cleanup removes only what the pilot created: its containers, its private network, its ledger volume, and its state
directory, which carries a marker file. It never touches other containers or volumes.

## What the workflow does

The agent is a synthetic support assistant. It works on three synthetic customer records. Each step asks Core for a
decision, and the executor performs a side effect only after it has verified Core's signed authorization.

| Step | What happens | Expected result |
|---|---|---|
| 1 | Read a customer record | Core allows. The executor runs it and records a receipt |
| 2 | Request a sensitive data export before any approval | Core holds it for approval. Nothing is exported |
| 3 | Try to delete a customer record | Core refuses (`tool_not_permitted`). Nothing is deleted |
| 4 | Impersonation: the agent approves its own request, an approver outside the allowlist approves, and an approver claims another identity | Each attempt is refused by Core, for its own reason |
| 5 | The data steward approves the export under its own identity | Core records the approval |
| 6 | The approved export runs | Core allows. The executor verifies, runs the export once, and records a receipt |
| 7 | Replay the same authorization | The executor refuses it (`authorization_receipt_recorded`) |
| 8 | The records owner approves a customer update, and the executor applies it | The record changes. A receipt is recorded |
| 9 | Core is unreachable, then recovers | The agent and the executor fail closed while Core is down. Nothing runs. After recovery the authorization runs once |

Three identities approve. Two are on the allowlist (`steward@acme-retail.example`, `owner@acme-retail.example`). One is
not (`outsider@contractor.example`). The agent is `agent:support-assistant`. The executor is `executor:records-service`.
Each has its own key, and no key is shared.

## Read the report

The report has these sections, in this order:

1. **Summary**: the run ID, the policy revision Core stamped, and how many checks and acceptance criteria passed.
2. **Startup and timing**: how long Core took to become ready, and the workflow's total time.
3. **Acceptance criteria**: one row per criterion, with the evidence from this run.
4. **Workflow**: for each step, the requested action, Core's decision and reason, the approval, the execution
   authorization, the executor's outcome, and the receipt, followed by the checks for that step.
5. **Authorization and execution, kept apart**: a Core decision of ALLOW gives an authorization. It does not show that
   anything ran. Only an executor receipt shows that, and each receipt names the authorization it used.
6. **Evidence verification**: Core's own chain check, and offline checks that need only the exported file and the pinned
   authorization public key.
7. **Limitations**: the limits of this pilot, stated next to the results.

## Acceptance criteria and where each is shown

| Criterion | How the pilot shows it |
|---|---|
| Unauthorized actions are prevented | Step 3: the delete is refused, and the record is still there |
| Human oversight is enforced | Step 2: the export is held. Step 6: it runs only after the steward's approval |
| Approval impersonation is prevented | Step 4: self-approval, an outsider approval, and an identity claim are each refused |
| Execution replay is prevented | Step 7: the same authorization is refused the second time |
| Evidence is independently verifiable | Evidence section: Core's chain check, and offline signature, binding, and scope checks |
| Core unavailability is handled safely | Step 9: nothing runs while Core is down, and the same authorization runs once after recovery |
| Latency is measured and reported | Each step records Core and executor timings. The report gives them |

The pilot checks these criteria on every run. A run with any failing criterion exits with status `1`.

## Timing

Two numbers matter for a first evaluation. They are measured separately:

- **Cold start** is the first run on a machine, when the Core image must be built from this checkout. The build
  dominates it, and it takes several minutes. It is a one-time cost.
- **Warm start** is any later run, with the image already built. It is what you will repeat.

Measured on the validation machine (macOS, local Docker), from the saved reports of three consecutive runs:

| Measure | Run 1 (builds the image) | Run 2 (image present) | Run 3 (image present) |
|---|---|---|---|
| Core ready, including any image build (seconds) | 7.71 | 6.03 | 5.96 |
| Workflow total (ms) | 104.8 | 112.9 | 113.6 |

Run 1 built `aigov-core:pilot`, but Docker reused cached layers from earlier builds of this checkout, so a build from an
empty cache is not represented here. The first-run cost on a machine with no cached layers is several minutes and is not
claimed by these figures. Each run writes its own timings into its report.

## Limitations

- **Synthetic data only.** The records, identities, and tools are invented. The pilot does not connect to your systems.
- **Static identities.** Approver and agent identities are configuration. There is no identity provider. An approver
  identity is only as strong as the credential issued for it.
- **Bearer API keys** for this pilot. They are generated per run and removed at the end.
- **Key handling.** Core's policy-signing key and its execution-authorization key are environment secrets in the pilot.
  A deployment must hold them in a managed key store and rotate the pinned authorization key.
- **Single host.** The executor is a local process with a local SQLite store. Several executors need a shared store with
  the same atomic reservation.
- **Revocation** stops an authorization the executor has not yet checked. It does not stop a side effect that has begun,
  and it does not undo one that has completed.
- **No exactly-once claim across external systems.** A crash between a side effect and its receipt leaves a reservation
  with no receipt, which an operator must reconcile.
- **Approval window** is 30 seconds in this pilot, as a demonstration value. A production policy would set minutes.
- **Not a certification.** The pilot shows how a policy decision, a human approval, and an execution receipt are recorded
  and checked. It does not establish that a system complies with any regulation.
- **One machine, one run** of each measurement. Timings are not a capacity claim.

## Moving from the pilot to your own workflow

The pilot's tools, approvers, policy, and records are defined in `examples/customer-pilot/pilot_config.py`, and the
executor's side effects in `examples/customer-pilot/pilot_workflow.py`. To evaluate your own tools, replace those and
keep the same trust boundary: the agent requests and submits, humans approve under their own credentials, Core decides
and signs, and the executor verifies the authorization itself before it acts. The reference's integration guide,
`examples/agent-reference/INTEGRATION.md`, describes that boundary in full.
