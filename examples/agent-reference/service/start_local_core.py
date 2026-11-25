#!/usr/bin/env python3
"""Start a local AIGov Core container with PostgreSQL and a signed policy, for the reference demo.

Everything runs on this machine: a private Docker network, a PostgreSQL 18 container, and the Core
image built from this repository. Credentials are generated per run and written only to a state
directory outside the repository. Nothing is deployed and no external service is contacted.

Usage (from the repository root):
    python examples/agent-reference/service/start_local_core.py start
    python examples/agent-reference/service/start_local_core.py stop

``start`` prints the environment to export for the demo. ``stop`` removes the containers, the
network, and the ledger volume.
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
REPO_ROOT = HERE.parents[2]
sys.path.insert(0, str(REPO_ROOT / "examples" / "agent-reference"))

IMAGE = os.environ.get("GOVAI_REF_IMAGE", "aigov-core:agent-reference")
PG_IMAGE = "postgres:18-alpine"
NETWORK = "aigov-agent-ref-net"
PG_NAME = "aigov-agent-ref-pg"
CORE_NAME = "aigov-agent-ref-core"
LEDGER_VOLUME = "aigov-agent-ref-ledger"
HOST_PORT = 18088
STATE_DIR = Path.home() / ".cache" / "aigov-agent-reference"
DB_NAME = "govai"
DB_USER = "govai"


def docker(
    *args: str, check: bool = True, capture: bool = True
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["docker", *args], check=check, capture_output=capture, text=True
    )


def docker_ok(*args: str) -> bool:
    result = subprocess.run(
        ["docker", *args], capture_output=True, text=True, check=False
    )
    return result.returncode == 0


def wait_until(predicate, timeout_s: float, what: str) -> None:
    last_error: Exception | None = None
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        try:
            if predicate():
                return
        except Exception as exc:  # noqa: BLE001 - retry until the deadline; the last error is shown below
            last_error = exc
        time.sleep(1)
    raise SystemExit(f"timed out waiting for {what}: {last_error}")


def build_policy(state: Path) -> tuple[str, str]:
    from aigov_agent_reference.core_policy import (
        signing_keys,
        trust_store_json,
        write_signed_policy,
    )

    seed, pub = signing_keys()
    bundle_dir = state / "policies"
    if bundle_dir.exists():
        shutil.rmtree(bundle_dir)
    write_signed_policy(bundle_dir, seed)
    return str(bundle_dir), trust_store_json(pub)


def start() -> None:
    if not docker_ok("info"):
        raise SystemExit("Docker is not running. Start Docker, then run this again.")
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    state_file = STATE_DIR / "state.json"
    if state_file.exists():
        raise SystemExit(f"already started (state in {state_file}). Run `stop` first.")

    if not docker_ok("image", "inspect", IMAGE):
        print(f"building {IMAGE} from {REPO_ROOT} ...", flush=True)
        subprocess.run(["docker", "build", "-t", IMAGE, str(REPO_ROOT)], check=True)

    pg_password = secrets.token_urlsafe(24)
    api_key = "aigov-ref-" + secrets.token_urlsafe(24)
    bundle_dir, trust_json = build_policy(STATE_DIR)

    docker("network", "create", NETWORK, check=False)
    docker("volume", "create", LEDGER_VOLUME, check=False)
    docker(
        "run",
        "-d",
        "--name",
        PG_NAME,
        "--network",
        NETWORK,
        "-e",
        f"POSTGRES_DB={DB_NAME}",
        "-e",
        f"POSTGRES_USER={DB_USER}",
        "-e",
        f"POSTGRES_PASSWORD={pg_password}",
        PG_IMAGE,
    )
    wait_until(
        lambda: docker_ok("exec", PG_NAME, "pg_isready", "-U", DB_USER, "-d", DB_NAME),
        90,
        "PostgreSQL",
    )

    database_url = f"postgres://{DB_USER}:{pg_password}@{PG_NAME}:5432/{DB_NAME}"
    api_keys_json = json.dumps({api_key: "ref-tenant"})
    docker(
        "run",
        "-d",
        "--name",
        CORE_NAME,
        "--network",
        NETWORK,
        "-p",
        f"127.0.0.1:{HOST_PORT}:8088",
        "-v",
        f"{bundle_dir}:/app/policies:ro",
        "-v",
        f"{LEDGER_VOLUME}:/var/lib/govai/ledger",
        "-e",
        "AIGOV_ENVIRONMENT=staging",
        "-e",
        "AIGOV_POLICY_BUNDLE_FILE=/app/policies/policy.bundle.staging.json",
        "-e",
        f"AIGOV_POLICY_TRUST_ED25519_JSON={trust_json}",
        "-e",
        f"GOVAI_API_KEYS={api_key}",
        "-e",
        f"GOVAI_API_KEYS_JSON={api_keys_json}",
        "-e",
        f"DATABASE_URL={database_url}",
        "-e",
        "GOVAI_AUTO_MIGRATE=true",
        IMAGE,
    )
    url = f"http://127.0.0.1:{HOST_PORT}"
    wait_until(
        lambda: urllib.request.urlopen(url + "/health", timeout=3).status == 200,
        120,
        "Core /health",
    )

    state_file.write_text(json.dumps({"core_url": url, "api_key": api_key}, indent=2))
    state_file.chmod(0o600)
    print("Core is up.")
    print(f"  export GOVAI_CORE_URL={url}")
    print(f"  export GOVAI_CORE_API_KEY={api_key}")
    print("Then run: python examples/agent-reference/run_core_demo.py")


def stop() -> None:
    for name in (CORE_NAME, PG_NAME):
        docker("rm", "-f", name, check=False)
    docker("network", "rm", NETWORK, check=False)
    docker("volume", "rm", LEDGER_VOLUME, check=False)
    state_file = STATE_DIR / "state.json"
    if state_file.exists():
        state_file.unlink()
    print("Stopped. Containers, network, and ledger volume removed.")


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("command", choices=["start", "stop"])
    args = parser.parse_args()
    if args.command == "start":
        start()
    else:
        stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
