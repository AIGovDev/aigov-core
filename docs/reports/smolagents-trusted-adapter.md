# smolagents trusted execution bridge

## Evaluation gate

The adapter connects the smolagents `Tool` interface to the existing Core-backed `AgentActor` and replay-resistant `Executor`. New tests verify refusal without dispatch, signed authorization forwarding, host-only approval references, one-time host retrieval of the exact original request, and rejection of model schemas that expose approval fields.

Local validation on the PR head plus this follow-up:

- Rust `cargo test --locked`: passed; full unit and non-database integration suite passed. Database-backed tests requiring `AIGOV_TEST_PG_ADMIN_URL` and multi-volume tests remained ignored by their existing guards.
- Python adapter tests: **16 passed** with `smolagents==1.26.0` and PyNaCl. They cover denial, replay handoff, host-only IDs, missing request events, bounded pending state, concurrent calls, and dispatch through a real `ToolCallingAgent` with a deterministic local model.
- Python smoke workflow suite (standards, MCP authorization, Hugging Face adapters, and smolagents): **68 passed**.
- Ruff lint and format checks: passed for the adapter, tests, and live example after correcting the initial lint findings.
- Python compile check: passed.
- `make gate`, `make core-runtime-examples-check`, and `make reference-integrations-check`: passed. The runtime example checker emitted its existing warning that `/metrics` is mounted but absent from its expected route list.
- `cargo audit`: no vulnerable Rust dependencies; it reports the existing no-fix unmaintained `chrono` advisory `RUSTSEC-2026-0543` as an allowed warning. `pip-audit python --skip-editable`: no known vulnerabilities.
- Gitleaks 8.30.1: verified the release SHA-256 and scanned the changed adapter, test, example, and guide files; no leaks found.
- `cargo clippy --locked --all-targets -- -D warnings`: blocked by 25 existing lint errors in untouched Rust files. `cargo fmt --all -- --check` also reports formatting differences across untouched Rust files; this change does not modify Rust source.
- Full Core-backed example: not run locally; no PostgreSQL server/client is available in this environment. The workflow provisions an isolated PostgreSQL database and runs the release binary.
- Hosted CI on the current PR head: not yet observed; the latest pre-push API snapshot reported only CLA checks. The PR remains unmerged.

The Core-backed smoke scenario runs a real `ToolCallingAgent` with a deterministic local model. It checks read dispatch, approval-required write refusal, exact request approval, modified-argument refusal, one authorized execution with a receipt, and replay refusal. The performer is an in-process test callback, so the scenario does not assert an external business-system effect.

## Human approval gate

A distinct host-controlled approver must approve the exact Core request using the original tool, call ID, policy revision, and arguments. The model-facing result omits the call ID, approval event ID, and policy revision. Host code consumes the original request and arguments from the adapter's bounded pending map exactly once; it does not create a second request to obtain approval. An ALLOW response without a persisted request event fails closed as INDETERMINATE.

## Trust boundary

Core signatures and executor receipts support integrity and attribution under configured trust assumptions. They do not establish factual truth or prove an external effect. This adapter governs only the registered smolagents tools; arbitrary Python, shell, `CodeAgent`, or other unwrapped execution can bypass it. The host must isolate executor credentials and the performer. Pending handles are process-local and are lost on adapter restart; recovery across restart needs a trusted Core reconciliation path.

See [smolagents trusted execution](../integrations/smolagents-trusted-execution.md) for setup, flow, reproduction, and limits.
