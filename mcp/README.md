# AIGov local MCP bridge

Real writes to `govai_generate_audit_report_template` require the existing trusted Core execution protocol and a distinct human approval. Use `govai_request_audit_template_approval` to record a request, obtain approval through a separately authenticated approver, then submit the original binding fields to the write tool. The local preview path (`dry_run=true`) remains side-effect-free. Configure separate agent and executor credentials, a pinned authorization public key, audience, and pre-migrated executor store through the process environment; see [`docs/runtime/mcp-preexecution-authorization.md`](../docs/runtime/mcp-preexecution-authorization.md).

## Direct stdio (recommended)

From the repository root:

```bash
python3 mcp/govai_mcp_server.py mcp-stdio
```

Cursor `mcp.json` example:

```json
{
  "mcpServers": {
    "govai-local": {
      "command": "python3",
      "args": ["mcp/govai_mcp_server.py", "mcp-stdio"]
    }
  }
}
```

## Optional shell wrapper

`mcp/run_govai_mcp_stdio.sh` resolves the repo root and `exec`s the Python server with **no stdout capture**:

```json
{
  "mcpServers": {
    "govai-local": {
      "command": "bash",
      "args": ["mcp/run_govai_mcp_stdio.sh"]
    }
  }
}
```

### Wrapper rules

- **Never** `tee`, redirect, or log MCP **stdout** (including to `/tmp`). Cursor reads JSON-RPC only from stdout.
- **Never** print banners or debug lines to stdout in `mcp-stdio` mode.
- Diagnostics may go to **stderr** only (`govai_mcp_server.py` already does this).
- Do not commit user-specific `~/.cursor/mcp.json` files; copy patterns from `.cursor/mcp.json.example` or `.cursor-plugin/examples/local-config.json`.

## Silent MCP notifications

The stdio server accepts these notifications with **no JSON-RPC response**:

- `notifications/initialized`
- `initialized`
- `notifications/cancelled`
