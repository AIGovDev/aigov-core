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

The executor records each reservation in a local SQLite file. The SDK does not create that file's table. A store
without the table refuses to start (`ExecutionStoreSchemaError`), and the message names the step that fixes it.

The schema is a versioned migration, `0001_executor_store.sql`, shipped as package data. An operator applies it once,
before first use, with their own tooling. Re-running it is safe:

```python
import sqlite3
from aigov_py.trusted import executor_store_migration

with sqlite3.connect("executor.sqlite") as conn:
    conn.executescript(executor_store_migration())   # once, out of band, before first use
```

This follows the repository's rule that shipped packages do not create database tables at runtime
(`docs/operations/runtime-schema-ownership.md`). Where the migration file should live under that rule is a decision for
the repository owners; it is flagged in the audit report.

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
- **No exactly-once across external systems.** A crash between a side effect and its receipt leaves a reservation with no
  receipt. An operator must reconcile it against your system.
- **Approval window** is 30 seconds in the examples, a demonstration value.
- **One Core process per ledger.**
- **Not a certification** and not a statement of regulatory compliance.
