# Integrating AIGov enforcement with your agent

This guide is for wiring your own tools and approval process to the gate in
`aigov_agent_reference`. Read the README first, which covers the decision order, the
trust boundary, and the limits. The steps below assume your agent framework lets you pass
custom tools. The example uses smolagents. The same approach works with other frameworks
if you can route each tool call through one function.

## 1. Decide what needs a human

Write down which actions are consequential: writes, admin changes, deployments, payments,
anything that is hard to undo. Put their action types in
`approval_required_action_types`. Everything else is decided by policy alone.

## 2. Write the policy

Start from `policies/example_policy.json`:

- `agent.principal`: the identity your agent acts as.
- `agent.allowed_tools`: the only tools the gate will run for that agent. Anything else is
  refused, even if your framework exposes it.
- `grants`: who may approve or read, and for which action types. The policy is signed when
  it is loaded. Grants are the only way a human approver is authorized.

Keep the policy in version control, and review changes like code.

## 3. Route every tool through the gate

Each tool your agent can call should look like `build_governed_tools` in `agent.py`: it
takes the agent's arguments, builds a `ToolCall`, calls `gate.request`, and returns a string
the model can read. Do not give the agent any other handle to the sandbox, the token
authority, or the approval store.

Do not expose a code-executing tool unless it runs in its own sandbox with no access to
your tool objects. See "Controlled execution and bypass paths" in the README.

## 4. Provide a real approval channel

`ApprovalStore.decide` records the decision and the approver's identity. Your deployment
must call it only from an authenticated human channel (for example a reviewer's web UI
behind your identity provider), and the agent must have no path to that channel. Then:

- Show the reviewer the exact call: tool, arguments, and repository. The approval is
  bound to the argument hash, so a changed call needs a new approval.
- Set the approval lifetime (`ttl_seconds`) for your risk tolerance. Expired approvals are
  denied.
- Revoke an approval through `RevocationList` when a reviewer withdraws it. The gate checks
  revocation again immediately before execution.

## 5. Replace the in-process keys before production

The reference generates its execution-token key and its policy key in the process. Both
must be managed keys in production, held where the agent cannot read them. The benchmark's
`kms_key_provider.py` and `sql_key_provider.py` show the interfaces. Also replace the
SQLite replay store with the PostgreSQL store (`SqlNonceStore("postgresql", dsn=...)`) if
more than one host runs the agent.

## 6. Keep the decision log and approval store protected

The decision log detects edits and deletions. It is not signed. The approval store is a
SQLite file. Both need file permissions that the agent process cannot write, and the log
should be copied to storage you control. Verify it with `verify_evidence` after each run,
and alert on any failure.

## 7. Test your wiring before you rely on it

Copy the regression tests in `python/tests/test_agent_reference_integration.py` and point
them at your tools. At minimum, check:

- A call with no approval is held (`REQUIRE_APPROVAL`) and does not run.
- A call that the policy does not allow is denied and does not run.
- A replayed, expired, revoked, or altered-argument approval is denied.
- Making the approval store unavailable stops execution (`INDETERMINATE`).
- The sandbox or your system of record has no change after a denied call.

## 8. Operate it

- Watch the denial reasons. A spike in `tool_not_permitted_for_agent` can mean a
  prompt-injection attempt or a misconfigured agent.
- Treat `INDETERMINATE` as an outage, not a refusal. Fix the dependency first.
- Review policy changes and approver grants on the same cadence as other access reviews.

## What this does not cover

- It does not make the model resist prompt injection. It limits what an injected
  instruction can do.
- It does not authenticate your approvers. That is your identity provider's job.
- It does not replace the AIGov Core service. The example keeps its evidence locally.
  Connecting a deployment to the service is separate work.
- It does not restrict the agent's network access or other process-level access. Do that
  in your deployment.
