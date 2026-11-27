# MCP integration

## Purpose

Explain how the Model Context Protocol (MCP) bridges local agents to GovAI documentation and validation scripts, aligned with the checked-in Cursor plugin pack and **no** silent changes to hosted enforcement.

## Integration overview

The repository ships MCP configuration examples under `.cursor-plugin/` and `mcp/`. Read-only tools remain local. The report-template writer now integrates with the existing trusted execution SDK: a separately authenticated approver must approve the exact tool call, Core issues a signed authorization, and the executor verifies and reserves it before the local write. This does not constrain shell or other MCP-server bypass paths; isolate the executor and its filesystem credentials for production. Developer integrations automation packs can list MCP-related commands as **documentation** of argv shape—validators do not execute them.

## Implementation steps

1. Read `.cursor-plugin/quickstart.md` for installation and security boundaries.
2. Merge `mcp.json` examples without committing secrets or absolute user paths.
3. Configure separate agent and executor keys, a pinned Core authorization public key, executor audience, and pre-migrated store through environment injection. Never put credentials in checked-in MCP JSON.
4. Use `govai_request_audit_template_approval`, obtain a distinct human approval, then call the report-template writer with the returned run/call IDs and approval event ID. Preview with `dry_run=true` without contacting Core.
5. Point agents at `make developer-integrations-platform-check` or individual Python validators for deterministic JSON.

## Validation

- `make cursor-plugin-check`
- `python3 scripts/developer_integrations_check.py --json`
- `python3 -m pytest python/tests/test_mcp_preexecution_authorization.py -q`
- `docs/integrations/cursor-plugin.md` for overlap with IDE packaging

## Failure modes

- **Over-trusting local tools** — MCP success does not imply `VALID` verdict on hosted runs. Mitigation: treat MCP output as pre-flight only.
- **Stale plugin paths** — moving scripts without updating automation pack metadata breaks artifact checks. Mitigation: run `make automation-pack` after edits.
