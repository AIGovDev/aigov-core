#!/usr/bin/env bash
# Beat C — live, one command, server already dead (you killed it after
# 04-export-run.sh, Ctrl+C in pane 1). Replays the exported bundle from the
# bare file — zero network, zero server — then tampers a COPY of it and
# replays that copy too, to show the chain catch it.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."

EXPORT="examples/talk-demo/.exports/export.json"
TAMPERED="examples/talk-demo/.exports/export.tampered.json"

if [ ! -f "$EXPORT" ]; then
  echo "No export found at $EXPORT — run 04-export-run.sh first (before killing the server)." >&2
  exit 1
fi

echo "== replay from the bare file — no server, no network =="
(cd rust && cargo run --quiet --bin replay_audit_export_once --locked -- "../$EXPORT") \
  | python3 -c "
import json, sys
d = json.load(sys.stdin)
print('ok:', d['ok'])
print('reconstructed_verdict:', d['reconstructed_verdict'])
print('chain_continuity_ok:', d['validation']['chain_continuity_ok'])
"
echo ""

cp "$EXPORT" "$TAMPERED"
python3 - "$TAMPERED" <<'PY'
import json, sys
path = sys.argv[1]
doc = json.load(open(path))
chain = doc["evidence_hashes"]["log_chain"]
target = chain[-2]
rh = target["record_hash"]
target["record_hash"] = rh[:-1] + ("0" if rh[-1] != "0" else "1")
json.dump(doc, open(path, "w"))
print(f"Tampered a copy of the bundle: flipped one character in the "
      f"'{target['event_type']}' record's hash.")
PY
echo ""

echo "== replay the tampered copy =="
set +e
(cd rust && cargo run --quiet --bin replay_audit_export_once --locked -- "../$TAMPERED")
STATUS=$?
set -e
echo ""
echo "replay exit code: $STATUS (non-zero = chain_break caught)"
