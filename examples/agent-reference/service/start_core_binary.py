#!/usr/bin/env python3
"""Start a release AIGov Core process (no Docker) with the trusted-execution reference configuration.

For continuous integration and for hosts without Docker. It needs a built ``aigov_audit`` binary and a reachable
PostgreSQL. It generates the identities, keys, policy, and authorization signing key for this run (see
``trust_setup.py``), starts the process in its own session, waits for ``/health``, and writes the state file.

Keys are written only to ``<state-dir>/state.json``, with owner-only permissions. They are never printed. When
``GITHUB_ENV`` is set, only the core URL and the state-file path are exported.

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
import shutil
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent))

from trust_setup import build


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
    (state / "ledger").mkdir(parents=True)
    built = build(state)
    url = f"http://127.0.0.1:{args.port}"

    env = {
        **os.environ,
        **built["env"],
        "AIGOV_BIND": f"127.0.0.1:{args.port}",
        "GOVAI_DATABASE_URL": args.database_url,
        "GOVAI_LEDGER_DIR": str(state / "ledger"),
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

    state_file = state / "state.json"
    state_file.write_text(
        json.dumps({**built["state"], "core_url": url, "pid": proc.pid}, indent=2)
    )
    state_file.chmod(0o600)
    github_env = os.environ.get("GITHUB_ENV")
    if github_env:
        print(f"::add-mask::{state_file}")
        with open(github_env, "a", encoding="utf-8") as fh:
            fh.write(f"GOVAI_CORE_URL={url}\nGOVAI_TRUST_STATE={state_file}\n")
    print(
        f"Core is up at {url} (pid {proc.pid}). Identities and keys are in {state_file} (owner-only), not printed."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
