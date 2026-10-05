#!/usr/bin/env bash
# Run this BEFORE you go on stage (not during the timed 8 minutes).
# Trains a run, posts the AI-discovery evidence, delegates to a specialist
# sub-agent, and leaves the orchestrator run sitting BLOCKED on
# "awaiting_human_approval" — exactly where Beat A of the talk starts.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."
# shellcheck disable=SC1091
source examples/talk-demo/env.sh

RUN_ID="$(python3 -c 'import uuid; print(uuid.uuid4())')"
echo "$RUN_ID" > examples/talk-demo/.run-id
echo "RUN_ID=$RUN_ID"
echo ""

echo "== training pipeline (make run) =="
make run RUN_ID="$RUN_ID"

echo ""
echo "== posting AI discovery scan evidence =="
# ts_utc must be real/monotonic: /api/export's log_chain is sorted by ts_utc but
# still carries each record's original physical-ledger prev_hash/record_hash, so
# an out-of-order timestamp (e.g. a placeholder epoch) desyncs that ordering from
# the physical chain and makes replay_audit_export_once report a false chain_break.
curl -sS -X POST "$GOVAI_AUDIT_BASE_URL/evidence" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $GOVAI_API_KEY" \
  -d "{\"event_id\":\"ai_discovery_completed_$RUN_ID\",\"event_type\":\"ai_discovery_reported\",\"ts_utc\":\"$(date -u +%Y-%m-%dT%H:%M:%S.000000Z)\",\"actor\":\"local_flow\",\"system\":\"aigov_poc\",\"run_id\":\"$RUN_ID\",\"payload\":{\"status\":\"completed\",\"openai\":false,\"transformers\":false,\"model_artifacts\":false}}"
echo ""
echo ""

echo "== delegating to a specialist sub-agent (orchestrator -> risk-scanner) =="
CHILD_RUN_ID="$(python3 -c 'import uuid; print(uuid.uuid4())')"
echo "$CHILD_RUN_ID" > examples/talk-demo/.child-run-id
curl -sS -X POST "$GOVAI_AUDIT_BASE_URL/evidence" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $GOVAI_API_KEY" \
  -d "{\"event_id\":\"deleg_$CHILD_RUN_ID\",\"event_type\":\"agent_delegated\",\"ts_utc\":\"$(date -u +%Y-%m-%dT%H:%M:%S.000000Z)\",\"actor\":\"orchestrator\",\"system\":\"aigov_poc\",\"run_id\":\"$RUN_ID\",\"root_run_id\":\"$RUN_ID\",\"agent_id\":\"planner\",\"agent_role\":\"orchestrator\",\"delegation_reason\":\"specialist_risk_review\",\"payload\":{\"child_run_id\":\"$CHILD_RUN_ID\",\"parent_run_id\":\"$RUN_ID\"}}"
echo ""
echo ""

echo "== current state — should read BLOCKED / awaiting_human_approval =="
curl -sS "$GOVAI_AUDIT_BASE_URL/compliance-summary?run_id=$RUN_ID" \
  -H "Authorization: Bearer $GOVAI_API_KEY" | python3 -m json.tool

echo ""
echo "Pre-stage done. This is where Beat A starts on stage."
