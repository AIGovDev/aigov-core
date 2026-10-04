#!/usr/bin/env bash
# Undo the tamper from 03-tamper-and-verify.sh so you can rehearse it again.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."
# shellcheck disable=SC1091
source examples/talk-demo/env.sh

LEDGER="$GOVAI_LEDGER_DIR/audit_log__local-dev.jsonl"

if [ -f "$LEDGER.bak" ]; then
  cp "$LEDGER.bak" "$LEDGER"
  echo "Restored ledger from backup — chain is intact again."
else
  echo "No backup found at $LEDGER.bak (nothing to restore)."
fi
