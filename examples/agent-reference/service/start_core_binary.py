#!/usr/bin/env python3
"""Start a release AIGov Core process (no Docker) with the signed reference policy.

For continuous integration and for hosts where Docker is not available. It needs a built
``aigov_audit`` binary and a reachable PostgreSQL. It generates a fresh signing key, policy, and API key
for each run, starts the process in its own session, waits for ``/health``, and exports the address and
key. The key is masked in CI logs and is never printed.

Usage:
    python examples/agent-reference/service/start_core_binary.py \
        --binary rust/target/release/aigov_audit \
        --database-url postgres://user:pass@127.0.0.1:5432/govai \
        --port 18088 --state-dir /tmp/aigov-ref-core
"""

from __future__ import annotations

import argparse
import json
import os
import secrets
import shutil
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE))

from aigov_agent_reference.core_policy import (
    signing_keys,
    trust_store_json,
    write_signed_policy,
)


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--database-url", required=True)
    parser.add_argument("--port", type=int, default=18088)
    parser.add_argument("--state-dir", required=True, type=Path)
    parser.add_argument("--timeout", type=float, default=120.0)
    args = parser.parse_args()

    state = args.state_dir
    if state.exists():
        shutil.rmtree(state)
    state.mkdir(parents=True)
    ledger = state / "ledger"
    ledger.mkdir()
    seed, pub = signing_keys()
    policy_dir = state / "policies"
    write_signed_policy(policy_dir, seed)
    api_key = "aigov-ref-" + secrets.token_urlsafe(24)
    url = f"http://127.0.0.1:{args.port}"

    env = {
        **os.environ,
        "AIGOV_ENVIRONMENT": "staging",
        "AIGOV_BIND": f"127.0.0.1:{args.port}",
        "AIGOV_POLICY_DIR": str(policy_dir),
        "AIGOV_POLICY_BUNDLE_FILE": str(policy_dir / "policy.bundle.staging.json"),
        "AIGOV_POLICY_TRUST_ED25519_JSON": trust_store_json(pub),
        "GOVAI_API_KEYS": api_key,
        "GOVAI_API_KEYS_JSON": json.dumps({api_key: "ref-tenant"}),
        "GOVAI_DATABASE_URL": args.database_url,
        "GOVAI_AUTO_MIGRATE": "true",
        "GOVAI_LEDGER_DIR": str(ledger),
    }
    log = open(state / "core.log", "w", encoding="utf-8")  # noqa: SIM115 - lives as long as the process
    proc = subprocess.Popen(
        [str(args.binary)],
        env=env,
        stdout=log,
        stderr=subprocess.STDOUT,
        start_new_session=True,
        cwd=state,
    )
    deadline = time.time() + args.timeout
    while time.time() < deadline:
        if proc.poll() is not None:
            raise SystemExit(
                f"Core exited early with status {proc.returncode}; see {state / 'core.log'}"
            )
        try:
            if urllib.request.urlopen(url + "/health", timeout=3).status == 200:
                break
        except OSError:
            pass
        time.sleep(1)
    else:
        raise SystemExit(
            f"Core did not answer /health within {args.timeout}s; see {state / 'core.log'}"
        )

    (state / "state.json").write_text(
        json.dumps({"core_url": url, "api_key": api_key, "pid": proc.pid})
    )
    (state / "state.json").chmod(0o600)
    github_env = os.environ.get("GITHUB_ENV")
    if github_env:
        print(f"::add-mask::{api_key}")
        with open(github_env, "a", encoding="utf-8") as fh:
            fh.write(f"GOVAI_CORE_URL={url}\nGOVAI_CORE_API_KEY={api_key}\n")
    print(
        f"Core is up at {url} (pid {proc.pid}). Key written to {state / 'state.json'}, not printed."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
