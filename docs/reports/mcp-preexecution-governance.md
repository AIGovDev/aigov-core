# MCP pre-execution governance change report

run_id=mcp-preexecution-governance
bundle_sha256=
policy_version=existing Core policy revision, bound at runtime

## Scope

This change routes the supported local MCP and CLI report-template write through the existing AIGov trusted execution SDK. It does not add a Core endpoint, policy schema, general MCP proxy, or host sandbox.

## Evaluation gate

**Status: local checks passed; hosted CI is authoritative and must complete before review.**

- `make gate`: passed.
- Cursor plugin validation and MCP handshake: passed.
- Python compile check: passed.
- Eleven MCP regression/adversarial test functions passed through the local direct fixture harness. The harness is not pytest; pytest and ruff are unavailable in the local environment.
- Route check passed with the existing mounted-route warning.
- Rust code was not changed. Rust formatting, tests, and cargo audit could not be run locally because the Rust toolchain is unavailable.

The tested cases cover denial without dispatch, exact argument binding, malformed configuration, replay refusal, path normalization, exclusive create, explicit overwrite, and symlink escape refusal.

## Human approval gate

Real writes require a separate approver identity and an explicit interactive approval before the agent receives a signed authorization. No production approval or real Core-backed write was performed as part of this change validation. Dry-run remains local and side-effect free.

## Security properties

The adapter reuses Core-issued authorization, exact tool and argument binding, audience and expiry checks, Core status validation, durable replay reservation, and execution receipts. File creation avoids concurrent clobbering; overwrite is atomic and only available when explicitly approved. Report paths resolving outside the repository are refused.

A valid signature and receipt support integrity and attribution under the configured trust assumptions. They do not establish the factual truth of report content or prove that an external effect occurred.

## Risk and limitations

The MCP adapter and executor share a local process, so this is not a hardened credential or filesystem isolation boundary. Arbitrary shell or Python entry points outside the supported adapter can bypass it. The executor store must be migrated before use. Core's authoritative JSONL ledger remains single-host. A live Core/MCP integration test and hosted security, supply-chain, and Rust CI results remain required before acceptance.
