#!/usr/bin/env python3
"""Read-only deployment preflight for AIGov Core.

Reads an environment file (KEY=VALUE lines) that the operator supplies by path. Reports, for each required and forbidden name,
whether it is set. It never prints a value. It does not contact any service, and it changes nothing.

Usage: deploy_preflight.py --env-file <path> --environment {staging,prod}

Exit status: 0 when no required name is missing and no forbidden name is set; 1 otherwise.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

COMMON_REQUIRED = {
    "AIGOV_ENVIRONMENT": "must equal the target environment",
    "GOVAI_LEDGER_DIR": "the ledger directory on a local volume",
    "AIGOV_BIND": "address the process listens on (inside a container, 0.0.0.0:8088)",
    "GOVAI_API_KEYS": "comma-separated API keys; must match GOVAI_API_KEYS_JSON",
    "GOVAI_API_KEYS_JSON": "JSON map of each key to its tenant",
    "GOVAI_PRINCIPALS_JSON": "required in staging and production (agent, approver, executor keys; see docs/release/pilot-package.md)",
    "AIGOV_POLICY_BUNDLE_FILE": "signed policy bundle (staging and production)",
    "AIGOV_POLICY_TRUST_ED25519_JSON": "trusted policy signing keys (staging and production)",
    "GOVAI_DATABASE_URL": "PostgreSQL URL for the policy anchor and the key registry (staging and production). DATABASE_URL is accepted too",
}
OPTIONAL_TUNING = {
    "AIGOV_REQUEST_TIMEOUT_SECS": "default 30",
    "AIGOV_MAX_CONCURRENT_REQUESTS": "default 256",
    "AIGOV_MAX_BODY_BYTES": "default 2097152",
}
REGISTRY_MODE = {
    "AIGOV_KEY_REGISTRY_PATH": "key registry file (needed for registry-mode authorization)",
    "AIGOV_KEY_REGISTRY_TRUST_FILE": "owner-only trust file for the registry roots",
    "AIGOV_KEY_REGISTRY_ANCHOR_URL": "PostgreSQL anchor URL for the registry",
    "AIGOV_EXECUTION_AUTH_SIGNING_SEEDS_DIR": "directory of <kid>.seed files, owner-only",
}
# Set in any of these names, the process refuses to start in staging or production, or the name is a test-only switch.
FORBIDDEN_IN_TARGET = {
    "AIGOV_POLICY_FILE": "unsigned policy file: refused in staging and production",
    "AIGOV_ALLOW_UNSIGNED_POLICY_FILE": "unsigned override: refused in staging and production",
    "AIGOV_APPROVER_ALLOWLIST": "env approver list: refused in staging and production",
    "AIGOV_TEST_FAULT_INJECTION": "fault injection is test-only; a release binary refuses to start with it set",
    "AIGOV_TEST_CRASH_AT": "fault injection is test-only; a release binary refuses to start with it set",
    "GOVAI_EXECUTION_AUTH_SIGNING_SEED_HEX": "environment seed: use the registry in staging and production",
}
ALIASES = {"GOVAI_DATABASE_URL": ("GOVAI_DATABASE_URL", "DATABASE_URL")}


def read_names(path: Path) -> dict[str, str]:
    out = {}
    for raw in path.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        out[key.strip().removeprefix("export ").strip()] = value.strip()
    return out


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--env-file", type=Path, required=True)
    ap.add_argument("--environment", choices=["staging", "prod"], required=True)
    args = ap.parse_args(argv)
    names = read_names(args.env_file)
    problems: list[str] = []
    print(f"preflight for {args.environment}: reading names from {args.env_file.name} (values are never printed)")

    def present(name: str) -> bool:
        return any(names.get(alias, "").strip() for alias in ALIASES.get(name, (name,)))

    print("\nRequired:")
    for name, note in COMMON_REQUIRED.items():
        ok = present(name)
        print(f"  [{'set' if ok else 'MISSING'}] {name} - {note}")
        if not ok:
            problems.append(f"missing {name}")
    if names.get("AIGOV_ENVIRONMENT", "").strip() and names["AIGOV_ENVIRONMENT"].strip() != args.environment:
        problems.append(f"AIGOV_ENVIRONMENT is {names['AIGOV_ENVIRONMENT'].strip()!r}, expected {args.environment!r}")
        print(f"  [MISMATCH] AIGOV_ENVIRONMENT is not {args.environment}")

    print("\nRegistry mode (needed when execution authorization is issued from the registry):")
    registry_set = [n for n in REGISTRY_MODE if present(n)]
    for name, note in REGISTRY_MODE.items():
        print(f"  [{'set' if present(name) else 'not set'}] {name} - {note}")
    if registry_set and len(registry_set) != len(REGISTRY_MODE):
        problems.append("registry mode is partly configured")
        print("  [INCOMPLETE] set all four registry names or none")

    print("\nTuning (optional; defaults apply when unset):")
    for name, note in OPTIONAL_TUNING.items():
        print(f"  [{'set' if present(name) else 'default'}] {name} - {note}")

    print("\nForbidden in the target environment:")
    for name, note in FORBIDDEN_IN_TARGET.items():
        if present(name):
            problems.append(f"{name} is set")
            print(f"  [SET - refused] {name} - {note}")
        else:
            print(f"  [absent] {name}")

    print("\nIncompatibilities with a configuration written before principals were required:")
    principals = names.get("GOVAI_PRINCIPALS_JSON", "").strip()
    if not principals:
        print("  [BLOCKING] no GOVAI_PRINCIPALS_JSON: staging and production refuse to start. Each agent, approver, and executor key needs its own entry.")
    else:
        print("  [ok] GOVAI_PRINCIPALS_JSON is set. Check by hand that each key's role matches its use (agent posts pipeline evidence; approver posts approvals and risk reviews; executor posts receipts).")

    print()
    if problems:
        print("RESULT: NOT READY")
        for p in problems:
            print(f"  - {p}")
        return 1
    print("RESULT: READY for this check (the database, the anchors, and the bundle are not contacted by this script)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
