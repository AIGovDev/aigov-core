#!/usr/bin/env python3
"""Negative controls for the trust boundary, run against any AIGov Core.

Each control separates two things:

- the **attack**: a credential tries to do what the trust boundary forbids, and
- the **mechanism**: the legitimate path the trust boundary needs (for example, the approver revoking an approval).

``protected`` means the attack was refused and the mechanism works (or the control is about refusal only).
``gap`` means the attack succeeded, or the mechanism is missing.

Give separate keys for the agent, the approver (maintainer), and the executor to test a trusted Core. Give only
``--key`` to test a Core with a single credential (for example, current staging): then every role is that one key, and
the controls show what a single credential can do.

The script uses raw HTTP, not the reference client, so the controls do not depend on the code they test.

Usage:
    python examples/agent-reference/negative_controls.py --core-url URL \
        --agent-key K1 --approver-key K2 --executor-key K3 --out results/negative_controls_trusted.json
    python examples/agent-reference/negative_controls.py --core-url URL --key K --out results/negative_controls_staging.json
"""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import threading
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib import error, request

DIGEST = "d" * 64


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


class Core:
    def __init__(self, url: str, key: str) -> None:
        self.url = url.rstrip("/")
        self.key = key

    def post(self, event_type: str, run: str, payload: dict[str, Any], event_id: str | None = None) -> tuple[int, dict]:
        body = json.dumps(
            {
                "event_id": event_id or f"{event_type}-{uuid.uuid4().hex}",
                "event_type": event_type,
                "ts_utc": _now(),
                "actor": "negative-control",
                "system": "negative-controls",
                "run_id": run,
                "payload": payload,
            }
        ).encode()
        req = request.Request(
            self.url + "/evidence",
            data=body,
            method="POST",
            headers={"Content-Type": "application/json", "Authorization": f"Bearer {self.key}"},
        )
        try:
            with request.urlopen(req, timeout=15) as resp:
                return resp.status, json.loads(resp.read() or b"{}")
        except error.HTTPError as exc:
            try:
                return exc.code, json.loads(exc.read() or b"{}")
            except json.JSONDecodeError:
                return exc.code, {}

    def health(self) -> bool:
        try:
            with request.urlopen(self.url + "/health", timeout=5) as resp:
                return resp.status == 200
        except OSError:
            return False


@dataclass
class Roles:
    agent: Core
    approver: Core
    executor: Core
    single: bool


def _message(body: dict) -> str:
    err = body.get("error")
    if isinstance(err, dict):
        return str(err.get("message", ""))
    return str(body.get("message", body))


def _unknown_event_type(body: dict) -> bool:
    return "unknown event_type" in _message(body)


def _request(roles: Roles, run: str, tc: str) -> str:
    eid = f"tool_approval_requested-{uuid.uuid4().hex}"
    roles.agent.post("tool_approval_requested", run,
                     {"tool_name": "create_file", "tool_call_id": tc, "args_binding_hash": DIGEST}, event_id=eid)
    return eid


def _approve(roles: Roles, run: str, tc: str, request_event: str, approver_identity: str,
             as_core: Core | None = None) -> tuple[int, dict, str]:
    eid = f"human_approved-{uuid.uuid4().hex}"
    status, body = (as_core or roles.approver).post(
        "human_approved",
        run,
        {"approver": approver_identity, "decision": "approve", "scope": "tool_execution", "tool_call_id": tc,
         "args_binding_hash": DIGEST, "tool_name": "create_file", "policy_revision": "1",
         "request_event_id": request_event},
        event_id=eid,
    )
    return status, body, eid


def _consequential(roles: Roles, run: str, tc: str, approval: str) -> tuple[int, dict]:
    return roles.agent.post("consequential_tool_call", run,
                            {"tool_name": "create_file", "tool_call_id": tc, "approval_event_id": approval,
                             "args_binding_hash": DIGEST})


def controls(roles: Roles) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []

    # 1. Self-approval: the agent's credential records an approval.
    run = f"nc-self-{uuid.uuid4().hex[:8]}"
    req = _request(roles, run, "tc-1")
    status, body, _ = _approve(roles, run, "tc-1", req, "maintainer@acme-corp.example", as_core=roles.agent)
    out.append({
        "control": "agent_self_approval",
        "attack": "the agent's credential records an approval naming an allowlisted approver",
        "attack_succeeded": status == 200,
        "core_answer": f"HTTP {status}: {'accepted' if status == 200 else _message(body)}",
        "verdict": "gap" if status == 200 else "protected",
    })

    # 2. Forged approver identity: the approver's credential names another approver.
    run = f"nc-forge-{uuid.uuid4().hex[:8]}"
    req = _request(roles, run, "tc-2")
    status, body, _ = _approve(roles, run, "tc-2", req, "lead@acme-corp.example")
    out.append({
        "control": "forged_approver_identity",
        "attack": "an approver's credential records an approval in another approver's name",
        "attack_succeeded": status == 200,
        "core_answer": f"HTTP {status}: {'accepted' if status == 200 else _message(body)}",
        "verdict": "gap" if status == 200 else "protected",
    })

    # 3. Revocation. Attack: the agent withdraws an approval. Mechanism: the approver withdraws its own approval.
    run = f"nc-rev-{uuid.uuid4().hex[:8]}"
    req = _request(roles, run, "tc-3")
    _, _, approval = _approve(roles, run, "tc-3", req, "maintainer@acme-corp.example")
    attack_status, attack_body = roles.agent.post("human_approval_revoked", run,
                                                  {"approval_event_id": approval, "reason": "attack"})
    mech_status, mech_body = roles.approver.post("human_approval_revoked", run,
                                                 {"approval_event_id": approval, "reason": "withdrawn"})
    attack_refused = attack_status != 200
    mechanism = mech_status == 200
    out.append({
        "control": "approval_revocation",
        "attack": "the agent withdraws an approval; mechanism: the approver withdraws its own",
        "attack_succeeded": not attack_refused,
        "mechanism_present": mechanism,
        "core_answer": (f"agent: HTTP {attack_status}: {_message(attack_body)}; "
                        f"approver: HTTP {mech_status}: {'accepted' if mechanism else _message(mech_body)}"),
        "verdict": "protected" if attack_refused and mechanism else "gap",
    })

    # 4. Core-issued authorization for an accepted consequential call.
    run = f"nc-auth-{uuid.uuid4().hex[:8]}"
    req = _request(roles, run, "tc-4")
    _, _, approval = _approve(roles, run, "tc-4", req, "maintainer@acme-corp.example")
    w_status, w_body = _consequential(roles, run, "tc-4", approval)
    auth = w_body.get("execution_authorization") if isinstance(w_body, dict) else None
    out.append({
        "control": "core_issued_authorization",
        "attack": "an executor needs a verifiable statement that Core accepted the call",
        "attack_succeeded": None,
        "mechanism_present": auth is not None,
        "core_answer": f"HTTP {w_status}, accepted={w_status == 200}, execution_authorization_present={auth is not None}",
        "verdict": "protected" if auth is not None else "gap",
        "_authorization_id": (auth or {}).get("payload", {}).get("authorization_id") if isinstance(auth, dict) else None,
        "_run": run,
    })
    auth_id = out[-1].pop("_authorization_id")
    auth_run = out[-1].pop("_run")

    # 5. Execution receipts. Attack: the agent records a receipt. Mechanism: the executor records one.
    r_attack_status, r_attack_body = roles.agent.post(
        "execution_receipt", auth_run,
        {"execution_authorization_id": auth_id or "auth_none", "tool_name": "create_file", "args_binding_hash": DIGEST,
         "outcome": "success", "result_digest": "0" * 64})
    r_mech_status, r_mech_body = roles.executor.post(
        "execution_receipt", auth_run,
        {"execution_authorization_id": auth_id or "auth_none", "tool_name": "create_file", "args_binding_hash": DIGEST,
         "outcome": "success", "result_digest": "0" * 64})
    attack_refused = r_attack_status != 200
    mech_known = not _unknown_event_type(r_attack_body) and not _unknown_event_type(r_mech_body)
    mechanism = r_mech_status == 200
    out.append({
        "control": "execution_receipt",
        "attack": "the agent records a receipt; mechanism: the executor records one for the authorization",
        "attack_succeeded": not attack_refused,
        "mechanism_present": mech_known,
        "core_answer": (f"agent: HTTP {r_attack_status}: {_message(r_attack_body) or 'accepted'}; "
                        f"executor: HTTP {r_mech_status}: {'accepted' if mechanism else _message(r_mech_body)}"),
        "verdict": "protected" if attack_refused and mech_known and mechanism else "gap",
    })

    # 6. Concurrent consumption: eight submissions on one approval.
    run = f"nc-race-{uuid.uuid4().hex[:8]}"
    req = _request(roles, run, "tc-6")
    _, _, approval = _approve(roles, run, "tc-6", req, "maintainer@acme-corp.example")
    barrier = threading.Barrier(8)

    def submit(_: int) -> int:
        barrier.wait()
        return _consequential(roles, run, "tc-6", approval)[0]

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        codes = list(pool.map(submit, range(8)))
    accepted = codes.count(200)
    out.append({
        "control": "concurrent_consumption",
        "attack": "eight concurrent submissions consume one approval",
        "attack_succeeded": accepted > 1,
        "core_answer": f"accepted {accepted} of 8",
        "verdict": "protected" if accepted == 1 else "gap",
    })

    # 7. One credential approves and performs the write.
    run = f"nc-solo-{uuid.uuid4().hex[:8]}"
    req = _request(roles, run, "tc-7")
    status, body, approval = _approve(roles, run, "tc-7", req, "maintainer@acme-corp.example", as_core=roles.agent)
    if status == 200:
        w_status, _ = _consequential(roles, run, "tc-7", approval)
    else:
        w_status = 0
    write_done = w_status == 200
    out.append({
        "control": "single_credential_write",
        "attack": "the agent's credential requests, approves, and submits a write",
        "attack_succeeded": write_done,
        "core_answer": f"approval {'accepted' if status == 200 else 'refused: ' + _message(body)}; write accepted: {write_done}",
        "verdict": "protected" if not write_done else "gap",
    })
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--core-url", required=True)
    parser.add_argument("--key", help="one credential for every role (single-credential Core)")
    parser.add_argument("--agent-key")
    parser.add_argument("--approver-key")
    parser.add_argument("--executor-key")
    parser.add_argument("--out", type=Path, default=None)
    args = parser.parse_args()
    if args.key:
        roles = Roles(Core(args.core_url, args.key), Core(args.core_url, args.key), Core(args.core_url, args.key), True)
    else:
        if not (args.agent_key and args.approver_key and args.executor_key):
            raise SystemExit("give --key, or all of --agent-key, --approver-key, and --executor-key")
        roles = Roles(Core(args.core_url, args.agent_key), Core(args.core_url, args.approver_key),
                      Core(args.core_url, args.executor_key), False)
    if not roles.agent.health():
        raise SystemExit(f"Core at {args.core_url} is not answering /health")
    results = controls(roles)
    mode = "single credential" if roles.single else "separate agent, approver, and executor credentials"
    print(f"Negative controls ({mode}):\n")
    for r in results:
        print(f"  [{r['verdict']:<9}] {r['control']:<28} {r['core_answer']}")
    gaps = sum(1 for r in results if r["verdict"] == "gap")
    print(f"\n  {len(results) - gaps} protected, {gaps} gap(s).")
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps({"core_url": args.core_url, "mode": mode, "controls": results}, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
