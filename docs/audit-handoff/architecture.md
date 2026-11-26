# Architecture (for the external reviewer)

## Components

| Component | Where | What it does | What it stores |
|---|---|---|---|
| Core (HTTP service) | `rust/` (binary `aigov_audit`) | Accepts evidence over HTTP, applies the policy, appends to the ledger, issues execution authorizations, serves verdicts and exports | Ledger: hash-chained JSON Lines per tenant, with sidecar state and run indexes |
| Policy bundle | file, verified at start | The rules Core applies. Signed (Ed25519) and checked against a trust file | Nothing at runtime |
| Policy anchor | PostgreSQL table `policy_revision_anchor` (migration 0003) | The accepted revision and digest per policy. The authority for rollback | One row per policy |
| Key registry | file (`registry.json` plus an event log), trust file, PostgreSQL anchor `key_registry_anchor` (migration 0004) | Signed lifecycle events for the authorization signing keys: register, activate, rotate, revoke | Hash-chained events; anchor row with the head |
| Executor SDK | `python/aigov_py/trusted/` | Runs a downstream action only with a verified authorization; records receipts; recovers after crashes | PostgreSQL executor store (`executions`, `execution_events`, append-only) or SQLite (one host only) |
| Reconciliation | `python/aigov_py/trusted/reconcile.py` | Applies signed evidence from a downstream system to an execution that is in doubt | Through the executor store |

## Data flow for one consequential call

1. An approver posts `human_approved` (approver principal). Core records it in the ledger.
2. An agent posts `consequential_tool_call` naming the approval (agent principal).
3. Core checks the policy and the approval, under the ledger lock. It prepares an authorization id and times, appends the record, then signs an
   authorization over the record hash, using a key the registry holds as active.
4. The response carries the signed authorization. The executor verifies its signature against the registry key for its key id, the audience, the tool, the argument digest, and the expiry (with a fixed clock-skew allowance), and runs the action only then.
5. The executor posts an `execution_receipt` (executor principal). Core accepts it only for an authorization it issued in the same run.

## Topology

Supported for the pilot: one Core per tenant on one host, with a local ledger volume; PostgreSQL for the policy anchor, the key registry anchor, and
the executor store; executors as library code in customer workers.

Not supported: several Core instances on different hosts sharing one ledger directory (the ledger lock is a host-local `flock`), SQLite executor stores on
more than one host.

## Storage and integrity

- The ledger is append-only in practice: each record carries the hash of the previous record. `audit_store::verify_chain` checks the whole chain, and the verification endpoint (`/verify`, `govai_api.rs`) calls it. Core validates its sidecar state on load (`load_state_if_valid`) and does not re-verify the whole chain at each start.
- The PostgreSQL executor history is append-only at the database level (triggers refuse UPDATE, DELETE, and TRUNCATE on the event table), and each
  event carries a chain hash.
- Backups must restore the database and the ledger together. The distributed runbook, section 8, gives the rules and the off-host head hashes.
