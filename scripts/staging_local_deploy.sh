#!/usr/bin/env bash
# Deploy AIGov Core staging on this machine with docker compose, then verify it.
#
# Secrets and the signed bundle live in a state directory OUTSIDE the repository
# (default: ~/.config/aigov-staging, mode 0700). Nothing secret is written to the repo,
# the image, or the logs. The Ed25519 signing seed is created inside `prepare` and is
# never written to disk.
#
# Usage:
#   scripts/staging_local_deploy.sh up       build image if missing, prepare bundle, start stack
#   scripts/staging_local_deploy.sh verify   run scripts/staging_policy_verify.py against the stack
#   scripts/staging_local_deploy.sh down     stop the stack (keeps data volumes)
#   scripts/staging_local_deploy.sh status   show container identity and health
#
# This is a local deployment target. It is not a remote staging environment.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
COMPOSE_DIR="$REPO/deployments/docker-compose"
STATE_DIR="${GOVAI_STAGING_STATE_DIR:-$HOME/.config/aigov-staging}"
PROJECT="aigov-staging-local"
IMAGE="aigov-core:staging-local"
CONTAINER="${PROJECT}-aigov-core-1"
BASE_URL="http://127.0.0.1:8088"
ENV_FILE="$STATE_DIR/staging.env"
LIVE_DIR="$STATE_DIR/live"
BUNDLE_DIR="$STATE_DIR/bundle"
PY="${PYTHON:-python3}"

compose() {
  docker compose -p "$PROJECT" -f "$COMPOSE_DIR/docker-compose.yml" -f "$COMPOSE_DIR/docker-compose.staging.yml" "$@"
}

ensure_state() {
  mkdir -p "$STATE_DIR"
  chmod 700 "$STATE_DIR"
}

ensure_env() {
  if [ -f "$ENV_FILE" ]; then
    return 0
  fi
  umask 077
  local api_key db_password
  api_key="$("$PY" -c 'import secrets; print(secrets.token_urlsafe(32))')"
  db_password="$("$PY" -c 'import secrets; print(secrets.token_urlsafe(24))')"
  {
    echo "GOVAI_STAGING_API_KEY='$api_key'"
    echo "GOVAI_STAGING_API_KEYS_JSON='{\"$api_key\":\"tenant-staging-verify\"}'"
    echo "GOVAI_STAGING_DB_PASSWORD='$db_password'"
  } > "$ENV_FILE"
  chmod 600 "$ENV_FILE"
  echo "created $ENV_FILE (secrets generated locally, not printed)"
}

load_env() {
  set -a
  # shellcheck disable=SC1090
  . "$ENV_FILE"
  set +a
}

ensure_bundle() {
  if [ -f "$BUNDLE_DIR/expected-manifest.json" ]; then
    return 0
  fi
  mkdir -p "$BUNDLE_DIR"
  chmod 700 "$BUNDLE_DIR"
  (cd "$REPO" && "$PY" scripts/staging_policy_verify.py prepare --out-dir "$BUNDLE_DIR" --expires-days 30)
  mkdir -p "$LIVE_DIR"
  chmod 700 "$LIVE_DIR"
  cp "$BUNDLE_DIR/policy.bundle.staging.json" "$LIVE_DIR/policy.bundle.staging.json"
}

export_trust() {
  GOVAI_STAGING_TRUST_JSON="$(cat "$BUNDLE_DIR/trust.json")"
  export GOVAI_STAGING_TRUST_JSON
  export GOVAI_STAGING_BUNDLE_DIR="$LIVE_DIR"
}

cmd_up() {
  ensure_state
  if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    (cd "$REPO" && docker build -f Dockerfile -t "$IMAGE" .)
  fi
  ensure_env
  ensure_bundle
  load_env
  export_trust
  export GOVAI_STAGING_IMAGE="$IMAGE"
  compose up -d --no-build
  echo "waiting for readiness at $BASE_URL/ready"
  for _ in $(seq 1 60); do
    if curl -fsS "$BASE_URL/ready" >/dev/null 2>&1; then
      echo "ready"
      cmd_status
      return 0
    fi
    sleep 2
  done
  echo "not ready after 120s; recent logs:" >&2
  compose logs --tail 40 aigov-core >&2 || true
  return 1
}

cmd_verify() {
  ensure_state
  load_env
  (cd "$REPO" && "$PY" scripts/staging_policy_verify.py \
    --skip-local \
    --target-kind local_container \
    --base-url "$BASE_URL" \
    --api-key-env GOVAI_STAGING_API_KEY \
    --container "$CONTAINER" \
    --image "$IMAGE" \
    --manifest "$BUNDLE_DIR/expected-manifest.json" \
    --fixtures "$BUNDLE_DIR" \
    --require-live \
    --out "$REPO/artifacts/staging-verify/deployed-evidence.json")
}

cmd_down() {
  ensure_env
  load_env
  export_trust
  compose down
}

cmd_status() {
  docker inspect --format 'container={{.Name}} state={{.State.Status}} image_id={{.Image}} started={{.State.StartedAt}}' "$CONTAINER" 2>/dev/null || echo "container not found"
}

case "${1:-}" in
  up) cmd_up ;;
  verify) cmd_verify ;;
  down) cmd_down ;;
  status) cmd_status ;;
  *) echo "usage: $0 {up|verify|down|status}" >&2; exit 64 ;;
esac
