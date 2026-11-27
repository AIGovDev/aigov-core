# smolagents trusted execution

The AIGov adapter exposes registered tools to `smolagents.ToolCallingAgent` while sending authorization decisions and side effects through the existing AIGov Core trusted-execution protocol. The adapter is a connector, not a new policy engine or a sandbox.

## Write approval flow

1. Create one `AgentActor` and `Executor` from a trusted `Integration` and register only the tools the agent may call.
2. Wrap each tool with `make_smolagents_tool`. The model receives only the business arguments declared in the host-owned input schema.
3. A write tool records `tool_approval_requested` and returns only `REQUIRE_APPROVAL` and `executed: false`. The call ID, request event ID, policy revision, original arguments, and exact Core response stay in adapter host memory.
4. Trusted host code calls `take_pending_approval(tool)` to consume the oldest pending request for that tool once. A distinct human approver uses that host-only handle to see and approve or reject the exact original tool name, call ID, arguments, and Core request.
5. The host calls `invoke_registered_tool` with the original call ID and the human approval event ID. Core reevaluates policy and issues signed authorization. The executor verifies the signature, audience, expiry, exact argument binding, and replay state before invoking the registered performer and recording its receipt.

Never place approver credentials, approval event IDs, executor credentials, or the performer in model-controlled arguments. The adapter rejects schemas that expose host-only approval fields and bounds pending approval state to 128 requests per tool instance.

## Reproducible Core-backed example

The CI workflow runs `examples/integrations/huggingface/smolagents_live.py` with the release Rust binary and an isolated PostgreSQL database. It requires no model API key, downloaded model, or remote code. The example exercises an actual `smolagents.Tool`, a read, a pending write, human approval of that exact request, modified-argument refusal, one authorized execution, and replay refusal. The performer is an in-process test callback; this validates the AIGov authorization boundary, not an external payment or business system.

The example uses the repository's pinned `smolagents` version from `python/pyproject.toml` (`1.26.0`). The CI workflow is the canonical invocation and installs PostgreSQL and Python test dependencies.

## Security boundary and limitations

- The adapter only governs calls routed through these registered wrappers. Shell, arbitrary Python, `CodeAgent`, or another MCP tool can bypass the adapter unless the host separately restricts those capabilities.
- The pending request handle is in memory on the host-owned tool object. A process restart loses that convenience handle; the host must reconcile the request from trusted Core state or start a new call. It must not invent approval IDs or silently repeat an approval request.
- A signed authorization and execution receipt provide integrity and attribution under the configured trust roots. They do not prove that the request was factually justified or that an external real-world effect occurred.
- This adapter does not establish multi-host consistency for Core's local ledger. Use the deployment's supported single-host Core topology until a shared durable ledger protocol is available.

Run the unit and adapter tests from the repository root with:

```sh
python -m pytest python/tests/test_smolagents_adapter.py -q
```
