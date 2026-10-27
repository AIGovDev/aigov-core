#!/usr/bin/env bash
# Beat C-extra (optional) — still offline, still after the server is dead.
# Signs the export with a demo Ed25519 key, verifies the signature, then
# shows what the signature does and doesn't catch:
#   - tampering the evidence content (e.g. who approved) -> signature fails
#   - tampering only the stored log_chain hashes -> signature still passes;
#     that class of tamper is 05-replay-offline.sh's job, not the signature's.
# Two independent checks, not one redundant with the other.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."
# shellcheck disable=SC1091
source examples/talk-demo/env.sh

EXPORT="examples/talk-demo/.exports/export.json"
SIGNED="examples/talk-demo/.exports/export.signed.json"
if [ ! -f "$EXPORT" ]; then
  echo "No export found at $EXPORT — run 04-export-run.sh first." >&2
  exit 1
fi

cp "$EXPORT" "$SIGNED"

echo "== sign the bundle (offline) =="
(cd rust && cargo run --quiet --bin sign_audit_export_once --locked -- \
  "../$SIGNED" "$GOVAI_DEMO_ISSUER_ID" "monika (talk demo)" "$GOVAI_DEMO_SIGNING_SEED_HEX")
echo ""

echo "== verify the signature (offline) =="
(cd rust && cargo run --quiet --bin verify_audit_export_signature_once --locked -- \
  "../$SIGNED" "$GOVAI_DEMO_ISSUER_ID" "$GOVAI_DEMO_SIGNING_PUBKEY_B64")
echo ""

TAMPERED="examples/talk-demo/.exports/export.signed.content-tampered.json"
cp "$SIGNED" "$TAMPERED"
python3 - "$TAMPERED" <<'PY'
import json, sys
path = sys.argv[1]
doc = json.load(open(path))
for ev in doc["evidence_events"]:
    if ev["event_type"] == "human_approved":
        ev["payload"]["approver"] = "someone_else"
        print(f"Tampered a copy's evidence content: changed the approver on {ev['event_id']}.")
        break
json.dump(doc, open(path, "w"))
PY
echo ""

echo "== verify the signature on the content-tampered copy — should fail =="
set +e
(cd rust && cargo run --quiet --bin verify_audit_export_signature_once --locked -- \
  "../$TAMPERED" "$GOVAI_DEMO_ISSUER_ID" "$GOVAI_DEMO_SIGNING_PUBKEY_B64")
STATUS=$?
set -e
echo "verify exit code: $STATUS (non-zero = caught)"
echo ""
echo "Note: the signature covers evidence CONTENT (evidence_events) and the"
echo "chain_head hash, not every stored log_chain row — that's what"
echo "05-replay-offline.sh's chain_continuity check is for. Two layers,"
echo "two different tamper classes, by design."
