#!/usr/bin/env bash
# Run this BEFORE you go on stage (not during the timed 5 minutes).
# Trains a run, posts the AI-discovery evidence, and leaves it sitting BLOCKED
# on "awaiting_human_approval" — exactly where Beat A of the talk starts.
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
curl -sS -X POST "$GOVAI_AUDIT_BASE_URL/evidence" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $GOVAI_API_KEY" \
  -d "{\"event_id\":\"ai_discovery_completed_$RUN_ID\",\"event_type\":\"ai_discovery_reported\",\"ts_utc\":\"1970-01-01T00:00:00Z\",\"actor\":\"local_flow\",\"system\":\"aigov_poc\",\"run_id\":\"$RUN_ID\",\"payload\":{\"status\":\"completed\",\"openai\":false,\"transformers\":false,\"model_artifacts\":false}}"
echo ""
echo ""

echo "== current state — should read BLOCKED / awaiting_human_approval =="
curl -sS "$GOVAI_AUDIT_BASE_URL/compliance-summary?run_id=$RUN_ID" \
  -H "Authorization: Bearer $GOVAI_API_KEY" | python3 -m json.tool

echo ""
echo "Pre-stage done. This is where Beat A starts on stage."
