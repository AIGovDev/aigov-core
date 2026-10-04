#!/usr/bin/env bash
# Shared environment for the AI Tinkerers talk demo scripts.
# Source this, don't execute it: `source examples/talk-demo/env.sh`
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

export GOVAI_LEDGER_DIR="$REPO_ROOT/.govai-ledger"
export GOVAI_API_KEY="talk-demo-key"
export GOVAI_API_KEYS="$GOVAI_API_KEY"
export GOVAI_API_KEYS_JSON="{\"$GOVAI_API_KEY\":\"local-dev\"}"
export AIGOV_ENVIRONMENT=dev
export AIGOV_POLICY_DIR="$REPO_ROOT/rust"
export GOVAI_AUDIT_BASE_URL="http://127.0.0.1:8088"
export GOVAI_PROJECT="ai-tinkerers-demo"

mkdir -p "$GOVAI_LEDGER_DIR"
