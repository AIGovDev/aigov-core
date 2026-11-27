# MCP tool execution through trusted Core authorization

Core already implements signed execution authorizations, approval binding, status checks, a trusted executor, and durable single-use execution stores. This integration connects the existing local MCP report-template writer to that path; it adds no second authorization protocol.

## Governed sequence

1. Call `govai_request_audit_template_approval`. The bridge submits a `tool_approval_requested` event as the agent and returns the run ID, call ID, request event ID, policy revision and argument binding hash.
2. A separately authenticated human approver reviews the exact request and submits a `human_approved` event through an approved integration. The MCP agent key cannot approve its own request.
3. Call `govai_generate_audit_report_template` with the returned `run_id` and `tool_call_id`, the approver's `approval_event_id`, and the unchanged `stem` and `force` values.
4. The bridge submits `consequential_tool_call` with its agent credential. Core checks policy and single-use approval state and returns a signed authorization only when allowed.
5. The bridge passes that authorization to the existing `aigov_py.trusted.Executor`. The executor verifies the signature, audience, run, tool, expiry and argument binding; checks current authorization status; reserves the authorization in its durable local store; then writes the file and submits a receipt.

`dry_run=true` remains local and does not contact Core or write a file. A real write fails closed on missing configuration, denied or pending approval, invalid signature, expired/revoked authorization, unavailable Core, missing executor store, or a replayed authorization.

## Configuration

Supply these variables through the MCP host or process supervisor. Do not put credentials in checked-in MCP JSON:

```text
GOVAI_RUNTIME_AUTH_URL=https://core.example
GOVAI_AGENT_API_KEY=<agent-principal key>
GOVAI_EXECUTOR_API_KEY=<separate executor-principal key>
GOVAI_EXECUTION_AUTH_PUBLIC_KEY_B64=<pinned Core authorization public key>
GOVAI_EXECUTOR_AUDIENCE=<the configured executor audience>
GOVAI_EXECUTOR_STORE_PATH=/var/lib/aigov/mcp-executor.sqlite
```

The agent and executor keys must be distinct and map to their respective Core roles and tenant. The bridge accepts HTTPS; plain HTTP is accepted only for loopback development. Provision and pin the public key through the trusted-execution runbook. Create and migrate the SQLite executor store out of band with `python -m aigov_py.trusted.store_admin migrate --db <path>`; the bridge refuses to initialize or upgrade its schema. One SQLite store is for one host. Use the existing PostgreSQL executor store when multiple executor processes or hosts share the same tenant state.

The built-in tool binding is `docs:write` with the report stem as its resource identifier. The signed governance policy must allow the exact `govai_generate_audit_report_template` name as a write tool. Approval must bind the generated `tool_call_id`, run, argument digest and policy revision. Review the action/tool mapping and policy together before deployment.

## Trust boundary and limitations

- Core's signed authorization is a cryptographically verifiable decision under the configured trust key. It is not proof that the arguments describe truthful facts.
- An authorization with no receipt means execution is unconfirmed. A receipt is evidence submitted by the executor; independently inspect and verify the ledger/export.
- The executor store prevents local replay. It cannot guarantee exactly-once effects in the filesystem or any external system across a crash between effect and receipt.
- The executor store persists the bound arguments so it can recover a reserved call. Protect the store file with the same tenant and host controls as the MCP process; this tool's arguments contain only a normalized report stem and a Boolean overwrite flag.
- This adapter controls only calls routed through this MCP server. Shell access, another MCP server, or another process can bypass it unless the surrounding environment restricts those paths.
- The current local report writer runs on the same host as the agent. Production deployment should isolate the executor and its filesystem credentials from the agent; this integration is a reproducible adapter, not a sandbox boundary.
- Core ledger coordination is host-local. Do not infer cross-host Core ledger safety from the PostgreSQL executor store.

## Reproducible integration example

Use the existing [trusted agent reference](../../examples/agent-reference/INTEGRATION.md) to provision distinct agent, approver and executor identities, sign a policy allowing the report-template tool, start Core, and migrate an executor store. Then:

1. Start `python3 mcp/aigov_mcp_server.py mcp-stdio` with the variables above.
2. Call `govai_request_audit_template_approval` with `{"stem":"sample-audit","force":false}` and retain its returned `run_id`, `tool_call_id`, `request_event_id`, `policy_revision`, and `args_binding_hash`.
3. Review the target and binding fields, then run the approval helper with those exact values and `GOVAI_APPROVER_API_KEY` plus `GOVAI_APPROVER_IDENTITY` for an allowlisted, distinct human approver. The helper checks the digest, requires an interactive `APPROVE` confirmation, and returns the `human_approved` event ID:

```bash
python3 examples/mcp-trusted-execution/approve_template_request.py \
  --run-id '<run_id>' \
  --tool-call-id '<tool_call_id>' \
  --request-event-id '<request_event_id>' \
  --policy-revision '<policy_revision>' \
  --args-binding-hash '<args_binding_hash>' \
  --stem sample-audit
```
4. Call `govai_generate_audit_report_template` with `dry_run:false`, the exact original `stem` and `force`, plus the retained `run_id`, `tool_call_id` and approval event ID.
5. Verify that `docs/reports/sample-audit.md` exists, the MCP response names an authorization ID and receipt status, and the corresponding run export contains the call and executor receipt.
6. Repeat with a changed stem, changed force value, missing approval, or the same authorization. Each must refuse before a new file write.

This example uses local Core and local SQLite for reproducibility. It is not a multi-host deployment example.
