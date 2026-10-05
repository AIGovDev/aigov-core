#!/usr/bin/env bash
# Pane 2 — run right after Beat B (still live, server still up).
# Posts the specialist sub-agent's own evidence (closing the lineage), then
# exports the orchestrator run to a plain file. This file is everything
# 05-replay-offline.sh needs — the server can go down right after this.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."
# shellcheck disable=SC1091
source examples/talk-demo/env.sh

RUN_ID="$(cat examples/talk-demo/.run-id)"
CHILD_RUN_ID="$(cat examples/talk-demo/.child-run-id)"
mkdir -p examples/talk-demo/.exports

echo "== specialist sub-agent posts its own result (run_id=$CHILD_RUN_ID) =="
curl -sS -X POST "$GOVAI_AUDIT_BASE_URL/evidence" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $GOVAI_API_KEY" \
  -d "{\"event_id\":\"child_eval_$CHILD_RUN_ID\",\"event_type\":\"evaluation_reported\",\"ts_utc\":\"$(date -u +%Y-%m-%dT%H:%M:%S.000000Z)\",\"actor\":\"risk_scanner_agent\",\"system\":\"aigov_poc\",\"run_id\":\"$CHILD_RUN_ID\",\"parent_run_id\":\"$RUN_ID\",\"root_run_id\":\"$RUN_ID\",\"agent_id\":\"risk-scanner\",\"agent_role\":\"specialist\",\"payload\":{\"ai_system_id\":\"aigov_poc\",\"dataset_id\":\"dataset_iris_v1\",\"model_version_id\":\"model_version_01_${RUN_ID}\",\"metric\":\"bias_scan\",\"value\":0.97,\"threshold\":0.9,\"passed\":true}}"
echo ""
echo ""

echo "== exporting the orchestrator run to examples/talk-demo/.exports/export.json =="
curl -sS "$GOVAI_AUDIT_BASE_URL/api/export/$RUN_ID" \
  -H "Authorization: Bearer $GOVAI_API_KEY" \
  -o examples/talk-demo/.exports/export.json
python3 -c "
import json
d = json.load(open('examples/talk-demo/.exports/export.json'))
print('exported verdict:', d['decision']['verdict'])
print('event_count:', len(d['evidence_hashes']['log_chain']))
"

echo ""
echo "Export done. You can now kill the server (Ctrl+C in pane 1) and run 05-replay-offline.sh."
