#!/usr/bin/env bash
# Beat C — live, one command. Shows the chain is intact, flips one character
# inside the most recent ledger record by hand, then shows /verify catch it.
# Safe to re-run after 09-restore-ledger.sh.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."
# shellcheck disable=SC1091
source examples/talk-demo/env.sh

LEDGER="$GOVAI_LEDGER_DIR/audit_log__local-dev.jsonl"

echo "== /verify — before =="
curl -sS "$GOVAI_AUDIT_BASE_URL/verify" -H "Authorization: Bearer $GOVAI_API_KEY"
echo ""
echo ""

cp "$LEDGER" "$LEDGER.bak"

python3 - "$LEDGER" <<'PY'
import json, sys
path = sys.argv[1]
lines = open(path).read().splitlines()
record = json.loads(lines[-1])
before = record["event_json"]
after = before.replace("approved_by_human", "approvedXbyXhuman", 1)
if before == after:
    raise SystemExit("Expected marker not found in the last record — did the flow change? Check manually.")
record["event_json"] = after
lines[-1] = json.dumps(record, separators=(",", ":"))
open(path, "w").write("\n".join(lines) + "\n")
print("Tampered the most recent ledger record (one field, one character run).")
PY

echo ""
echo "== /verify — after (one byte changed, by hand, just now) =="
curl -sS "$GOVAI_AUDIT_BASE_URL/verify" -H "Authorization: Bearer $GOVAI_API_KEY"
echo ""
echo ""
echo "Reset for another rehearsal with: examples/talk-demo/09-restore-ledger.sh"
