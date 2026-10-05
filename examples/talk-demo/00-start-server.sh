#!/usr/bin/env bash
# Pane 1 — start this BEFORE you go on stage and leave it running for the whole talk.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."
# shellcheck disable=SC1091
source examples/talk-demo/env.sh

echo "Starting aigov_audit on $GOVAI_AUDIT_BASE_URL — leave this window open."
cd rust
exec cargo run --bin aigov_audit --locked
