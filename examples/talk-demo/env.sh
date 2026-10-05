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

# Demo-only Ed25519 keypair for signing exported audit bundles (Beat C-extra).
# Not a secret: this is a throwaway local-dev signer, not used anywhere real.
export GOVAI_DEMO_ISSUER_ID="ai-tinkerers-demo"
export GOVAI_DEMO_SIGNING_SEED_HEX="d8cc4107d166accf57ebc54cd791934d1ebcbf1c216b548d1e5500a220975906"
export GOVAI_DEMO_SIGNING_PUBKEY_B64="YPzPMWSjUmZNGmKMbW6FRK1vEefYZfXFrZFdmq/5ZiY="

mkdir -p "$GOVAI_LEDGER_DIR"
