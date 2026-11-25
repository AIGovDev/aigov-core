# Integrating your agent and tools with AIGov Core

This guide is for a developer who wants AIGov Core to govern the consequential actions of their own agent: which tools
the agent may call, which of them need a named human to approve, and what evidence is kept.

It is built on the trusted-execution code in `examples/agent-reference` and the launcher in `examples/customer-pilot`.
Your application needs no Core internals. It calls one small interface, in `examples/customer-integration/aigov_integration.py`.

You can run the working examples before reading further:

```bash
python examples/customer-integration/quickstart.py                       # ~60 lines; Docker
python examples/customer-integration/acme/validate.py run                 # 8 cases; Docker
```

## 1. The model in one paragraph

Your **agent** proposes calls. Core decides each call against a signed **policy**, and records every decision in an
append-only ledger. A consequential call needs an **approval** from a named human, given under that human's own
credential. When Core allows a call, it signs an **execution authorization** for that exact call. Your **executor** (the
code that actually performs the side effect) verifies the authorization itself, reserves it once, performs the call, and
records a **receipt**. The agent never holds a signing key, and no single credential can both request and approve.

## 2. Credential separation

Each actor gets its own API key, and Core maps each key to one principal and one role:

| Actor | Role | Can | Cannot |
|---|---|---|---|
| Agent | `agent` | request approvals, submit calls, record blocked calls | approve, revoke, record receipts |
| Approver (one per person) | `approver`, bound to one identity | approve or reject requests in its own identity, revoke its own approvals | approve in another identity, approve its own request, submit calls |
| Executor | `executor` | record receipts for issued authorizations, check status | approve, submit calls |
| Core | (holds the keys) | decide, record, sign | (never given to an actor) |

`IntegrationConfig.generate` creates one key per actor, and no key is shared. Keys are generated per run. Your
production deployment must issue and store them in your own secret manager. Section 7 lists this as a limitation.

## 3. Policy configuration

You describe your tools in one place:

```python
CONFIG = IntegrationConfig(
    tenant="your-tenant",
    policy_id="your-policy",
    tools=(
        Tool("read_order", "order:read", "read", resource_key="order_id"),
        Tool("refund_order", "order:refund", "write", resource_key="order_id"),
    ),
    approvers={"support_lead": "lead@your-company.example"},   # name -> identity; the allowlist
    agent_identity="agent:support-bot",
    executor_identity="executor:orders-service",
)
```

- A **read** tool runs without approval, but is still authorized by Core and receipted by the executor.
- A **write** tool needs an approval from one of the listed approvers before Core will authorize it.
- A tool that is **not listed is refused** by Core (`tool_not_permitted`). It cannot run, even if the agent asks.
- `resource_key` names the argument that identifies the resource. Core binds the approval to the tool, the arguments, and
  the policy revision.

`IntegrationConfig` checks its own rules when it is created. It rejects duplicate tool names, an unknown tool kind, no
write tool, no approver, an agent and executor with the same identity, and an approver whose identity is the agent's.
The tests in `python/tests/test_customer_integration.py` cover each rule.

Approval freshness is `approval_max_age_seconds` (30 in the examples). This is a demonstration value. Set it to what your
approval process needs, typically minutes.

## 4. The flow your application runs

```python
integ = Integration(CONFIG, core_url, state, out_dir, performer)

read = integ.call("read_order", {"order_id": "ORD-1"}, "call-1")          # no approval
integ.execute("read_order", {"order_id": "ORD-1"}, read)

request = integ.request_approval("refund_order", args, "call-2")         # the agent asks
approval = integ.approve("support_lead", request, "refund_order", args, "call-2")   # a human decides
call = integ.call("refund_order", args, "call-2", approval.event_id)      # the agent submits
outcome = integ.execute("refund_order", args, call)                       # the executor performs it once
```

`performer(tool, arguments, execution_id)` is your side effect. It returns
`{"success": bool, "data": ..., "blocked_reason": str | None}`. The executor calls it only after it has verified the
authorization. Put your real API call there, and make it idempotent on `execution_id` where your system supports that.

## 5. Trust boundaries and what is not claimed

Inside the boundary: Core's policy key and authorization key, the executor's pinned public key, the executor's store,
and Core's ledger lock.

Outside it, the design does not stop these, so your deployment must:

- **Bypass.** A process that performs your side effect without going through the executor. Your external system must
  accept those calls only from the executor's own credential.
- **Executor state.** A process that can reach the executor's store or key. Run the executor where the agent cannot reach it.
- **Wrong Core.** An executor that trusts a different Core. The pinned key and status URL must point at the right one.
- **Clock.** A clock more than about five seconds off.

Not claimed:

- **Exactly-once across your external system.** The executor reserves before it acts. A crash between your side effect and
  the receipt leaves a reservation with no receipt, which an operator must reconcile against your system.
- **Revocation of an execution that has begun.** Revocation stops an authorization that the executor has not yet
  checked. It does not stop a side effect in progress, and it does not undo a completed one.
- **Resistance to prompt injection in general.** Core refuses calls outside the policy. It does not judge the content of
  an approved call.

## 6. Failure handling

| Situation | What happens |
|---|---|
| Core unreachable when the agent submits | The agent gets `INDETERMINATE`. It gets no authorization, so nothing runs |
| Core unreachable when the executor checks | The executor refuses (`core_unavailable`). The side effect does not run |
| Core back after an outage | The same authorization can run once. The executor's reservation prevents a second run |
| Authorization presented twice | The second is refused (`authorization_receipt_recorded`) |
| Arguments changed after approval | Core refuses the call (`approval_linkage_mismatch`). The executor refuses a changed authorization (`authorization_arguments_mismatch`) |
| Approval revoked before the call | Core refuses (`approval_revoked`) |
| Approval revoked after issue, before the executor checks | The executor refuses (`authorization_revoked`) |
| Approver tries to approve a different identity | Refused (`approver_identity_mismatch`) |
| Agent tries to approve | Refused (`role_not_permitted`) |

The validation in `examples/customer-integration/acme/validate.py` checks each of these against a real Core, and prints the
reason Core returned.

## 7. Evidence export and independent verification

After a run, `integ.export()` returns Core's export for the run: the ledger events, the hash chain, and the execution
receipts. `integ.verify(authorizations)` runs two kinds of check:

1. **Core's chain check**, which asks Core to verify its own ledger.
2. **Offline checks** that need only the export, the authorizations, and the pinned authorization public key. They confirm
   each authorization's signature and domain, that it is bound to a record in the ledger, that its run and audience match,
   that each receipt matches an issued authorization, and that no authorization has two receipts.

A reviewer can rerun the offline checks without access to Core's database or keys. The validation's tampering case shows
that a changed authorization fails the signature check.

## 8. Measured integration effort

Measured on the validation machine, for the quickstart:

- Your configuration: 11 lines.
- Your performer: 11 lines.
- Your flow: 40 lines, of which about 10 are Core start and stop plumbing. The integration makes 7 calls: `call`,
  `execute`, `request_approval`, `approve`, `verify`, and a second `call` and `execute`.
- The Acme example application (`examples/customer-integration/acme/app.py`) is 123 lines, including its ledger and
  its approval flow.

These numbers are for an example of this shape, not a measure of your system. The remaining effort is in your performer,
your identity and key management, and your approval process. See `docs/customer-pilot-acceptance.md`.

## 9. Moving to production

Section 7 of the acceptance checklist lists what a production deployment still needs. In short: an identity provider for
approvers and the executor, a managed key store with rotation for the authorization key, a shared executor store with the
same atomic reservation, reconciliation of reservations without receipts, and a reviewed approval window.
