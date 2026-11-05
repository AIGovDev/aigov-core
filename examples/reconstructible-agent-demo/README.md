# Reconstructible agent demo

Developer-facing runtime demonstrator for **append-only evidence**, **deterministic replay**, **policy evaluation**, **tool usage**, **human approval**, **ledger-authoritative compliance verdicts**, and **audit export**.

Not a SaaS dashboard. Uses **AIGov Core** mounted routes only.

## Prerequisites

- Running `aigov_audit` (see repo root `make run-audit` or Docker Compose)
- `GOVAI_API_KEY` matching server `GOVAI_API_KEYS` / `GOVAI_API_KEYS_JSON`
- Offline replay helpers built with `cd rust && cargo build --locked --bin replay_audit_export_once --bin epistemic_readiness_once`
- Optional: `GOVAI_AUDIT_BASE_URL` (default `http://127.0.0.1:8088`)
- Optional: `GOVAI_RUN_ID` (default `recon-demo-<pid>`)

## Run

```bash
export GOVAI_EXAMPLE_EXECUTE=1
export GOVAI_API_KEY=test-key
python3 examples/reconstructible-agent-demo/run_demo.py
```

## Simulated lifecycle

1. User request → model reasoning → tool call → tool output → policy evaluation  
2. Governance lifecycle (discovery, data, train, evaluation, risk)  
3. Final `ai_decision_completed`  
4. Compliance summary (**BLOCKED** until approval)  
5. `human_approved` → `model_promoted`  
6. Final compliance summary (**VALID** from ledger projection)  
7. `GET /api/export/:run_id` → `exports/<run_id>.json`  
8. `GET /verify/:run_id`  
9. Offline deterministic replay and epistemic-readiness evaluation
10. Offline replay viewer in `viewer/index.html`

## Mocked vs live

| Component | Mode |
|-----------|------|
| Provider call, request/response, reasoning text, tool result | Mocked (no external LLM). The invocation uses the provider-neutral event contract and digest-only capture; provider/backend identity and determinism are explicitly unknown. |
| Evidence ingest, summary, export, verify | Live `aigov_audit` |

## Replay viewer

Open `viewer/index.html` in a browser (local static file or simple HTTP server for `fetch`).

- File picker: load `exports/<run_id>.json`  
- Query param: `?export=../exports/<run_id>.json` (needs a local server)  

Shows ordered evidence timeline, tool/approval gates, ledger verdict, and hash-chain integrity from `evidence_hashes.log_chain`.

The run also executes `replay_audit_export_once` and the offline epistemic-readiness evaluator. It writes `exports/<run_id>-offline-readiness.json` and reports the reconstructed verdict separately from readiness. The demo deliberately evaluates without archived policy bytes, so a compliance-valid export may still be epistemically `partial`. The model invocation is also `digest_only`: it records digests, not reconstructible prompt or response content.

## Routes (Core only)

- `POST /evidence`
- `GET /compliance-summary/:run_id`
- `GET /api/export/:run_id`
- `GET /verify/:run_id`
- `GET /bundle-hash/:run_id` (hash continuity)

## Docs

- [Reconstructible agent demo](../../docs/reconstructible-agent-demo.md)
- [Audit report](../../docs/reports/reconstructible-agent-demo.md)
