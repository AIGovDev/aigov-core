# Reconstructible Agent Demo

## Summary

The demo exercises GovAI Core mounted routes only (`POST /evidence`, `GET /compliance-summary`, `GET /api/export`, `GET /verify`, `GET /bundle-hash`). Mocked agent text and tool results; live ledger ingest and verdict reads. After export, `run_demo.py` now runs the deterministic offline replay helper and the offline epistemic-readiness evaluator, saving `<run_id>-offline-readiness.json`. The viewer is described as a visualizer, not as the replay engine. No commercial SaaS dashboard or platform workflow routes.

## Evaluation gate

Evaluation evidence contributes to **deterministic ledger-authoritative verdicts**. The demo appends `evaluation_reported` with `passed: true` as part of the governance lifecycle. Compliance summary and audit export derive `evaluation_passed` and overall `verdict` from ledger projection—not from client-side scores or observability metrics. A failed evaluation would yield **INVALID** via the same projection rules.

## Human approval gate

Approval evidence contributes to **deterministic ledger-authoritative verdicts**. The demo records compliance summary while approval is still missing (typically **BLOCKED**), then appends `human_approved` and `model_promoted`, and re-reads summary and export until **VALID** when policy requirements are satisfied. Export includes `human_approved` in `evidence_events` and human-approval fields under `decision`; the replay viewer surfaces the approval gate explicitly.

## Offline replay and readiness

Replay is **export-driven**: `GET /api/export/:run_id` produces `aigov.audit_export.v1` with ordered `evidence_events` and `evidence_hashes.log_chain`. `replay_audit_export_once` independently reconstructs the governance verdict from the saved export and checks it against the live verdict. The viewer only displays the timeline and hash-chain linkage. The offline readiness evaluator runs with policy-artifact availability unset, so the report can show `compliance_verdict_valid=true` alongside `status=partial` and `missing_policy_artifact`. This is an intentional demonstration of the gap between replaying the verdict and preserving all knowledge required for later reconstruction. Digest-only model capture also cannot recover prompt/response contents.

## Verification

```bash
make reconstructible-demo-check
(cd rust && cargo build --locked --bin replay_audit_export_once --bin epistemic_readiness_once)
make reference-integrations-check
make core-runtime-examples-check
make gate
cd rust && cargo build --locked --bin aigov_audit && cargo test --locked
```

Live demo (operator-hosted `aigov_audit`):

```bash
export GOVAI_EXAMPLE_EXECUTE=1
export GOVAI_API_KEY=test-key
python3 examples/reconstructible-agent-demo/run_demo.py
```

CI runs structure and contract checks offline; it does not start a long-lived HTTP server.
