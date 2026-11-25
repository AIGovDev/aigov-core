# Trusted execution in the AIGov SDK (`aigov_py.trusted`)

The trusted-execution layer lets a customer's agent perform consequential actions only when AIGov Core has decided
the call under policy, a named human has approved it under their own credential, and an executor that the customer
runs has verified Core's signed authorization before acting. It ships in the `aigov-py` package. A customer installs the
wheel and imports the public names below. Nothing needs to be copied from `examples/`.

```bash
pip install aigov-py            # or the wheel built from this repository
```

```python
from aigov_py.trusted import Integration, IntegrationConfig, Tool, start_core, stop_core
```

## Public API

Everything a customer application imports is listed in `aigov_py/trusted/__init__.py` (`__all__`). Each name has one
role. The types are plain dataclasses, so they can be checked with a type checker.

| Name | Role |
|---|---|
| `ToolSpec` (alias `Tool`) | A tool: `name`, `action` (the capability recorded in the binding), `kind` (`"read"` or `"write"`), `resource_key` (the argument that names the resource). Validated on creation |
| `tool_registry(tools)` | Validates a sequence of tools into a name-to-tool mapping. Rejects duplicates |
| `args_binding_hash(spec, args)` | The argument digest that binds an approval and an authorization to one exact call |
| `IntegrationConfig` | Tools, approvers, identities, and the approval window. Validated on creation |
| `Integration` | One run: `call`, `request_approval`, `approve`, `revoke`, `execute`, `execute_with`, `export`, `verify` |
| `start_core`, `stop_core` | Start a Core for one configuration, and stop it. Each start has its own name prefix |
| `AgentActor` | The agent's credential: requests approvals, submits reads and writes, records blocked calls |
| `ApproverActor` | A human's credential: approves, rejects, and revokes in its own identity |
| `Executor` | Verifies Core's authorization, reserves it once, performs the side effect, records a receipt |
| `ExecutionStore` | The executor's single-use record (local SQLite) |
| `ExecutionOutcome` | What `Executor.execute` returns: `executed`, `reason`, `authorization_id`, `receipt_recorded`, timings |
| `Refused` | The executor's refusal, with a stable `reason` code |
| `Decision`, `CoreDecision`, `CoreClient` | Core's answer, mapped to `ALLOW`, `DENY`, `REQUIRE_APPROVAL`, or `INDETERMINATE` |
| `verify_authorization_signature` | Checks an authorization against a pinned public key, with the domain separator |
| `offline_evidence_checks` | Checks an export and its authorizations without Core's database or keys |
| `build_policy_document`, `write_signed_policy`, `generate_signing_keys`, `trust_store_json` | The signed policy |
| `provision`, `load_state` | Per-run keys, principals, and Core's environment |
| `Performer` | The type of the side-effect function you supply |

### The performer

The executor never performs an action itself. You supply a performer, which is your side effect:

```python
def perform(tool: str, arguments: dict, execution_id: str) -> dict:
    # call your system here; make the call idempotent on execution_id where your system supports it
    return {"success": True, "data": {...}, "blocked_reason": None}
```

A performer is required. The SDK has no default side effect.

The performer receives an idempotency key as its third argument: `execution_key(authorization_id)`, a value that is the
same for every attempt at one authorization, including a resume after a crash. Pass it to your external system wherever
that system deduplicates on a key. Without such a system, the key does nothing, and nothing is guaranteed (section
"Idempotency and single use").

### One call, end to end

```python
integ = Integration(config, core_url, state, out_dir, perform)

read = integ.call("read_order", {"order_id": "ORD-1"}, "call-1")        # reads need no approval
integ.execute("read_order", {"order_id": "ORD-1"}, read)

request = integ.request_approval("refund_order", args, "call-2")       # the agent asks
approval = integ.approve("lead", request, "refund_order", args, "call-2")  # a human decides
call = integ.call("refund_order", args, "call-2", approval.event_id)    # the agent submits
outcome = integ.execute("refund_order", args, call)                    # the executor performs it once
```

## Trust boundaries (unchanged from the reference)

| Party | Holds | Can | Cannot |
|---|---|---|---|
| Agent | its own API key | request approvals, submit calls | approve, revoke, sign, record receipts |
| Approver | its own API key, bound to one identity | approve or reject in that identity, revoke its own approvals | approve in another identity, approve its own request, submit calls |
| Executor | its own API key and the pinned authorization public key | verify, reserve, perform, record receipts | approve, submit calls, sign |
| Core | the policy-signing key and the authorization signing seed | decide, record, sign | (not an actor) |

The SDK moved the reference's code. It did not change what is checked, in what order, or with what result. The
argument digest is byte-identical to the reference's (golden values are tested). The authorization domain is the same.
The executor's order of checks is the same, with one addition: an unregistered tool is refused first (`tool_not_registered`).

## Tools, and why the registry is explicit

A tool's `action` and `resource_key` are part of the binding. They are not inferred. `tool_registry` rejects duplicate
names, and `Executor`, `AgentActor`, and `ApproverActor` take the registry explicitly. A call to a tool that is not in
the registry is refused before any request is sent.

The reference keeps a process-wide registry (`register_tool`) for its own tests. New code should pass registries
explicitly. The process-wide form is not part of the SDK.

## Policy

`build_policy_document` produces a `govai.policy.v1` bundle with the same rules the reference uses:

- `tool_call` (reads) is allowed only for tools in `read_tools`.
- `consequential_tool_call` (writes) is allowed only for tools in `write_tools`, and needs a recorded, approved,
  in-scope, unrevoked, unconsumed, in-date approval bound to the same run, tool, argument digest, and policy revision.
- `human_approved` is accepted only from an approver on the allowlist, in its own authenticated identity, and not for its
  own request.
- `human_approval_revoked` is accepted only from the approver who gave the approval.
- Any event type not listed is rejected.

Every tool not named in `read_tools` or `write_tools` is refused by Core with `tool_not_permitted`, even if the agent asks.

`IntegrationConfig` builds the allowlists from its tools. `unlisted_approvers` exists to test refusal: such an approver
holds a credential, and Core refuses its approvals by policy. A customer normally leaves it empty.

## The executor store

The executor records each execution durably in a local SQLite file. The file is one host's state; it is not a shared
store. Schema management is out of band: an operator applies the versioned migrations with
`python -m aigov_py.trusted.store_admin migrate --db <file> --backup-dir <dir>`. The executor never creates or upgrades a
table, and it refuses to open a file whose schema version is not exactly `SCHEMA_VERSION` (currently 2). The operator
procedure is in `docs/operations/executor-store-runbook.md`.

## The execution lifecycle

Each authorization has one execution, which moves through these states:

```
reserved -> started -> succeeded | failed | outcome_unknown -> reconciliation_required -> reconciled
reserved -> failed        (refused before any side effect: revoked, expired, not authorized, arguments unavailable)
```

- `reserved`: the authorization was received, verified, checked against Core, and reserved. Its arguments are stored, so
  it can be resumed after a crash.
- `started`: written before the performer is called, with a lease. A crash after this point has an unknown outcome.
- `succeeded` / `failed`: the performer returned a definite result. The outcome and a pending receipt are written in one
  transaction.
- `outcome_unknown` -> `reconciliation_required`: the performer raised, or a worker died with its lease expired. These two
  states are recorded together. **They are never retried automatically.**
- `reconciled`: signed evidence from an authorized reconciler was applied.

Every transition is checked against a fixed table (`lifecycle.ALLOWED`) inside the transaction that records it. An illegal
transition is refused and writes nothing. Each row stores the authorization id, the executor identity, the tool, the
argument digest, and the policy revision.

Concurrency: a reservation is atomic, so of several workers racing for one authorization only one reserves it. Core
also refuses an authorization once it has a receipt, so a worker that arrives later is refused by Core's status check.

## History

Every transition appends one entry to `execution_events`. The table cannot be updated or deleted (triggers). Each entry
carries a hash of its content and of the previous entry. `verify_history()` recomputes the chain, and detects an altered,
reordered, or removed entry. The rows in `executions` are a projection of the history: `verify_projection()` checks that
each row agrees with the last transition recorded for it. Migrated v1 entries are marked as such and are not part of
the chain.

## Recovery after a restart

```python
actions = executor.recover()        # call at startup; safe to call any number of times
```

`recover` brings each unresolved execution to the state its evidence supports:

- `reserved`, never started: the authorization is checked again (signature, expiry, Core's status), and then performed
  once. If Core cannot be asked, nothing is performed and the action is `deferred`.
- `started`, lease expired: recorded as `outcome_unknown`, then `reconciliation_required`. Not retried.
- `started`, lease live: skipped. A live worker holds it.
- finished with a pending receipt, or a missing one: the receipt is delivered. The action is not repeated.
- `reconciliation_required`: reported, not touched.

The arguments are checked against the stored digest before anything is performed. If they do not match, the execution is
closed without action.

Failure points are tested with real process termination at each boundary (`python/tests/test_executor_lifecycle.py`
and `scripts/executor_recovery_live.py`): before reservation, after reservation, immediately before the side effect, during
the side effect, after the side effect before the outcome, after the outcome before the receipt, after Core stored the
receipt before the acknowledgement, and during recovery itself.

## Receipts

A receipt is written locally with its outcome, in the same transaction (`pending`). Delivery submits the stored event to
Core, and marks it `recorded` when Core acknowledges it. Core rejects a duplicate event id (409). A timeout may mean Core
stored it. Both cases are settled by looking the event up in the run's export; the event is resubmitted only if the export
does not contain it. Receipt delivery is evidence delivery: it never runs the action, and its content is derived only from
the stored row. Core requires a non-empty result digest, so every receipt carries one, derived from the recorded outcome
where no result data exists.

## Reconciliation of an unknown outcome

An execution in `reconciliation_required` is never run again by the executor. Someone checks the external system and
records what they find, signed with their own Ed25519 key, under a domain separator:

```python
from aigov_py.trusted import ReconcilerRegistry, apply_reconciliation, make_payload, sign_evidence

envelope = sign_evidence(make_payload(row, outcome="succeeded", external_reference="order-7781",
                                      external_evidence=proof_bytes, reconciler=identity,
                                      observed_at_utc=now_iso), reconciler_seed_b64)
apply_reconciliation(store, envelope, ReconcilerRegistry(keys={identity: reconciler_pub_b64}),
                     receipt_event_id="execution_receipt-...")
```

The evidence is applied only if the signer is in the registry, the signature verifies under that key, every binding field
matches the stored execution, the execution is awaiting reconciliation, the outcome is `succeeded`, `failed`, or
`not_executed`, and the observation time is after the reservation and not in the future. The evidence is appended to the
history. The earlier unknown-outcome entries remain.

`not_executed` closes the authorization without repeating the action. Running the action again needs a new authorization,
and so a new human approval. There is no force-execute and no force-success. Refusals are reported with a stable reason
(`reconciliation_signature_invalid`, `reconciler_not_authorized`, `reconciliation_binding_mismatch`,
`reconciliation_not_required`, `reconciliation_timestamp_invalid`, `reconciliation_outcome_invalid`).

`apply_escalation` records a signed request for manual investigation, changes no state, and is kept in the history.

## Visibility

`report(store)` returns a structured document: counts by state, pending executions, unknown outcomes, the reconciliation
backlog, missing and pending receipts, recovery failures (refusals caused by local state), the unresolved list, latency
(`reserve_to_start`, `execution`, `receipt_delivery`, each with count, p50, p95, max, measured from the history's
timestamps), and the history and projection checks. The executor also logs one structured line per transition through
`aigov_py.trusted.executor` and `aigov_py.trusted.receipts`.

## Identities used for each step

| Step | Credential | Checked by |
|---|---|---|
| Authorization | Core's signing key (never given to an actor) | the executor's pinned public key, with the domain |
| Execution and receipt | the executor's API key | Core's role check (`executor`) |
| Reconciliation | the reconciler's Ed25519 key | the operator's registry, pinned out of band |
| Schema changes | the operator's shell | the store refuses a file that is not at the expected version |

## Idempotency and single use: what each mechanism guarantees

These are five separate things. Only the first two are guaranteed by this SDK.

| Mechanism | Guarantees | Does not guarantee |
|---|---|---|
| Authorization single use (Core) | Core issues at most one authorization for one approval, and refuses a second use | Anything about the external system |
| Executor reservation (store) | On one host, one reservation per authorization, even under concurrent workers | Anything across hosts (one store per host) |
| Receipt delivery retry | A receipt reaches Core at most once (duplicates are settled by Core's export), without repeating the action | That the receipt is delivered without a Core outage |
| Downstream idempotency | Only what your external system guarantees for the key it receives (`execution_key`). Verified by you, not assumed | Anything if the external system ignores the key |
| Exactly-once external execution | Not claimed. An unknown outcome is held for reconciliation, never retried. Exactly-once needs a verified idempotent external system | Anything the executor cannot observe |

The executor never assumes downstream idempotency. Whether your system deduplicates on `execution_key` is a property you
must test against that system before you rely on it.

## Failure handling

| Situation | Result |
|---|---|
| Core unreachable when the agent submits | `INDETERMINATE`; no authorization; nothing runs |
| Core unreachable when the executor checks | refused (`core_unavailable`); nothing runs |
| Core back, same authorization | runs once; the store prevents a second run |
| Authorization presented twice | refused (`authorization_receipt_recorded`) |
| Arguments changed after approval | Core refuses (`approval_linkage_mismatch`); the executor refuses (`authorization_arguments_mismatch`) |
| Approval revoked before the call | Core refuses (`approval_revoked`) |
| Approval revoked after issue, before the executor checks | refused (`authorization_revoked`) |
| Approver claims another identity | refused (`approver_identity_mismatch`) |
| Agent credential tries to approve | refused (`role_not_permitted`) |
| Unregistered tool | refused (`tool_not_registered`) |
| Performer raises mid-call | recorded as `outcome_unknown`, then `reconciliation_required`; not retried |
| Process killed mid-call | on restart, held until the lease expires, then `outcome_unknown`; not retried |
| Process killed after the outcome | the receipt is re-sent on restart; the action is not repeated |
| Reconciliation evidence forged or altered | refused; nothing changes |

## Launching Core

`start_core(config, state_dir, port=..., mode="docker" | "binary", image=..., binary=..., database_url=...)` starts
Core with this configuration's policy and identities, and returns the running Core and its name prefix.

- **Docker** needs an image that already contains Core. Build it from the repository's `rust/Dockerfile`, or pull it from
  your registry. The SDK does not build images.
- **Binary** needs a release `aigov_audit` and a PostgreSQL database that you provide.

Every resource has the prefix that `start_core` returned. `stop_core(state_dir, prefix)` removes only those resources. A
state directory is removed only if it carries the marker the SDK wrote when it created it. Two Cores with different
prefixes and different databases can run on one machine without touching each other.

## Packaging and compatibility

- The wheel contains `aigov_py/trusted/` and nothing from `examples/`.
- Python 3.10 or newer is declared. The wheel was installed and exercised on Python 3.12.3 in a clean environment.
- The package version is unchanged (0.2.1). A version bump is a release decision.
- The reference's names keep working through thin adapters (`aigov_agent_reference.core_trusted`, `core_gate`,
  `core_policy`, `service/trust_setup`). They delegate to the SDK. They add the reference's registry and benchmark sandbox
  and nothing else.

## Production limitations

These hold for the SDK as shipped. They are the same limitations the reference and the pilot state.

- **Identities are configuration.** No identity provider. An approver's identity is only as strong as the credential issued for it.
- **API keys are bearer secrets.** The SDK generates keys for runs and tests. Production keys come from your secret manager.
- **Signing keys.** Core holds the policy-signing key and the authorization seed. The SDK's `generate_signing_keys` and
  `provision` are for development and evaluation. Production keys must be managed and rotated, and the authorization
  public key pinned by each executor must be rotated with them.
- **The executor's store is local SQLite on one host.** Several executors need a shared store with the same atomic reservation.
- **Revocation window.** Revocation stops an authorization the executor has not yet checked. It does not stop a side
  effect that has begun, and it does not undo a completed one.
- **The lease.** A started execution is treated as dead only after its lease expires. A worker that runs longer than its lease
  can be mistaken for dead while still acting. Set `lease_seconds` above your longest external call.
- **No exactly-once across external systems.** A crash between a side effect and its receipt leaves a reservation with no
  receipt. An operator must reconcile it against your system.
- **Approval window** is 30 seconds in the examples, a demonstration value.
- **One Core process per ledger.**
- **Not a certification** and not a statement of regulatory compliance.
