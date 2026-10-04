#!/usr/bin/env bash
# Beat B — live, one command. Appends the missing human_approved + model_promoted
# evidence, then re-reads the recomputed verdict (should flip to VALID).
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."
# shellcheck disable=SC1091
source examples/talk-demo/env.sh
RUN_ID="$(cat examples/talk-demo/.run-id)"

echo "== human approval =="
make approve RUN_ID="$RUN_ID"

echo ""
echo "== promotion =="
make promote RUN_ID="$RUN_ID"

echo ""
echo "== recomputed verdict =="
curl -sS "$GOVAI_AUDIT_BASE_URL/compliance-summary?run_id=$RUN_ID" \
  -H "Authorization: Bearer $GOVAI_API_KEY" \
  | python3 -c "import json,sys; d=json.load(sys.stdin); print('verdict:', d['verdict'])"
