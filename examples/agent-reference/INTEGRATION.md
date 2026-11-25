# Integrating AIGov Core with your agent

This guide is for connecting your own tools and approval process to AIGov Core. The integration this
guide describes is the service-backed path: Core makes every authorization decision, and your agent
process only submits evidence and runs a call once Core accepts it. Read the README first, for the
decision table, the policy, and the open gaps. Read section 4 before you deploy anything.

The reference code is in `aigov_agent_reference/core_gate.py` and `core_runner.py`. Copy those two
modules and adapt the tool wrappers. The example uses smolagents, but any framework works if each tool
call can be routed through one function.

## 1. Decide what needs a human

List the consequential actions: writes, admin changes, deployments, payments, anything hard to
undo. In your policy, put their tools on the write allowlist. Those are the only tools that need an
approval. Everything else is a read, and Core decides it from the read allowlist alone.

## 2. Write the policy

Start from `policies/core_policy.unsigned.json`. Then change, in one reviewed file:

- `tool_call.gates` (`requires_decision_enum`): the read tools.
- `consequential_tool_call.gates`: the write tools (`requires_decision_enum`), and the approval gate
  (`requires_unconsumed_approval`). Set `max_age_seconds` to your approval window. Minutes is typical;
  the reference uses 5 seconds for the demo.
- `human_approved.gates`: the approver allowlist (`requires_approver_allowlist`), and the freshness
  check (`requires_timestamp_near_server_time`).

Sign the bundle with your own managed key, not the reference's generated key. Core verifies the
signature at startup. Keep the unsigned policy in version control and review changes like code. A test
in the reference shows the pattern: the committed file must equal what the code produces.

## 3. Route every tool call through Core

Each tool wrapper should:

1. Submit the call to Core as an evidence event: `tool_call` for reads, `consequential_tool_call` for
   writes (with the approval event id and an argument binding hash). `CoreRunner` does this.
2. Read Core's answer. Only `ALLOW` (a `200` with a `record_hash`) allows the call.
3. Run the operation only after `ALLOW`. Record the Core `record_hash` next to your operation's result.
4. On a refusal, let the model see the reason, and do not run anything.

Do not expose any other handle to your systems to the agent: no raw API client, no credentials, no
direct database access. Those are the paths around the gate.

For writes with no approval yet, the reference records an approval request in Core and reports
`REQUIRE_APPROVAL`. Show that request to the approver, along with the exact arguments, because the
approval is bound to them.

## 4. Fix the approver identity before you deploy (open gap)

This is the most important item. Core checks that the approver's name is on the allowlist. It does not
check who submitted the approval. Today, anything that can post `human_approved` with your tenant's API
key can approve on a person's behalf. In the reference, the simulated human uses the agent's key, so
the agent could approve its own writes.

Before production:

- Give approvals their own credential, separate from the agent's. Only the approval interface holds it.
- Have Core map that credential to a named approver, and check the approver field against the
  authenticated identity. This is a small Core change. It is not implemented in this example.
- Keep the approval interface on an authenticated human channel (for example, your identity provider
  behind a reviewer UI). The agent must have no path to it.

Until this is done, treat a Core approval as the approver's name as typed, and do not rely on it for
consequential actions.

## 5. Keep the sandbox and the record connected

The reference runner issues the sandbox token after Core accepts the call, in the same process. The
sandbox checks the token, not Core's record. For production, bind the token to Core's `record_hash`, or
put the sandbox behind a service that verifies the record. Otherwise a process that holds the sandbox
can run calls Core never saw.

## 6. Operate on the evidence

- Verify each run with `GET /verify/{run_id}` (Core's chain check) and read the export with
  `GET /api/export/{run_id}`. The export's `evidence_hashes.log_chain` gives each event's record hash.
- Check that every executed call's `record_hash` matches the export. The reference's benchmark does this
  for every case.
- Alert on `INDETERMINATE` (Core unreachable). Fix the dependency first; do not retry blindly.
- Watch the refusal reasons. A spike in `tool_not_permitted` can mean prompt injection or a
  misconfigured agent.

## 7. Limits to plan around

- **Single host.** The ledger lock serializes writes within one Core process. Do not run two Core
  processes on one ledger.
- **No revocation.** Core has no event for withdrawing an approval. Until one exists, an approval is
  good until it expires or is used.
- **Expiry is server-clock based.** An approval's age is measured from its (freshness-checked)
  timestamp. Clock skew between the approval interface and Core is bounded by the freshness check.
- **The agent cannot be trusted with approvals.** See section 4.
- **Not prompt-injection immunity.** Core limits what an injected instruction can do. It does not stop
  a model from being manipulated.

## 8. Test your wiring

Copy `python/tests/test_agent_reference_core.py` and point it at your tools and policy. At minimum:

- A write with no approval is held and does not run.
- A read-only call for an allowed tool runs.
- A tool not on the allowlist is refused.
- A replayed, expired, or changed-argument approval is refused.
- Core unreachable means nothing runs, and the same call succeeds once Core returns.
- Core's chain verifies, and every executed call's record hash matches Core's export.
