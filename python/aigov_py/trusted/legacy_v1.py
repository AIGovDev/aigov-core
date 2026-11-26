"""Replay of the v1 registry log (``govai.key_event.v1``), kept only for the explicit migration to v2.

v1 events were not signed in the log: they record only a ``request_sha256``. Replay here checks the hash chain, the
sequence, and the lifecycle transitions. It cannot prove who made a change. The migration (``keys.migrate_v1``) therefore
imports this state only under a root signature, and marks every imported key as unsigned history.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any

from aigov_py.canonical_json import canonical_bytes

V1_SCHEMA = "govai.key_event.v1"


class V1IntegrityError(Exception):
    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code


@dataclass
class _Key:
    kid: str
    purpose: str
    public_key_b64: str
    owner: str
    status: str = "pending"
    registered_at_utc: str = ""
    activated_at_utc: str | None = None
    retired_at_utc: str | None = None
    revoked_at_utc: str | None = None
    compromised_from_utc: str | None = None
    revocation_reason: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "purpose": self.purpose,
            "public_key_b64": self.public_key_b64,
            "owner": self.owner,
            "status": self.status,
            "registered_at_utc": self.registered_at_utc,
            "activated_at_utc": self.activated_at_utc,
            "retired_at_utc": self.retired_at_utc,
            "revoked_at_utc": self.revoked_at_utc,
            "compromised_from_utc": self.compromised_from_utc,
            "revocation_reason": self.revocation_reason,
        }


@dataclass
class V1State:
    version: int = 0
    keys: dict[str, _Key] = field(default_factory=dict)
    operators: dict[str, dict[str, Any]] = field(default_factory=dict)


def _hash(body: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_bytes(body)).hexdigest()


def _apply(state: V1State, ev: dict[str, Any]) -> None:
    op, kid, ts = ev["op"], ev.get("kid"), ev["ts_utc"]
    detail = ev.get("detail", {})
    if op == "operator_register":
        state.operators[detail["identity"]] = {"public_key_b64": detail["public_key_b64"], "roles": list(detail["roles"])}
    elif op == "register":
        if kid in state.keys:
            raise V1IntegrityError("kid_already_registered", kid)
        state.keys[kid] = _Key(kid, detail["purpose"], detail["public_key_b64"], detail["owner"], registered_at_utc=ts)
    elif op == "activate":
        rec = state.keys.get(kid)
        if rec is None or rec.status != "pending":
            raise V1IntegrityError("illegal_transition", f"activate {kid}")
        if any(k.status == "active" and k.purpose == rec.purpose for k in state.keys.values()):
            raise V1IntegrityError("second_active_key", kid)
        rec.status, rec.activated_at_utc = "active", ts
    elif op == "retire":
        rec = state.keys.get(kid)
        if rec is None or rec.status != "active":
            raise V1IntegrityError("illegal_transition", f"retire {kid}")
        rec.status, rec.retired_at_utc = "retired", ts
    elif op == "revoke":
        rec = state.keys.get(kid)
        if rec is None or rec.status not in ("pending", "active", "retired"):
            raise V1IntegrityError("illegal_transition", f"revoke {kid}")
        rec.status, rec.revoked_at_utc = "revoked", ts
        rec.compromised_from_utc = detail.get("compromised_from_utc") or ts
        rec.revocation_reason = detail.get("reason", "")
    else:
        raise V1IntegrityError("unknown_event", op)
    state.version = ev["version"]


def replay(events: list[dict[str, Any]]) -> V1State:
    state = V1State()
    prev: str | None = None
    for seq, ev in enumerate(events, start=1):
        if ev.get("schema") != V1_SCHEMA or ev.get("seq") != seq:
            raise V1IntegrityError("event_sequence_broken", f"event {seq}")
        if ev.get("prev_hash") != prev:
            raise V1IntegrityError("event_chain_broken", f"event {seq}")
        body = {k: v for k, v in ev.items() if k != "hash"}
        if _hash(body) != ev.get("hash"):
            raise V1IntegrityError("event_altered", f"event {seq}")
        _apply(state, ev)
        prev = ev["hash"]
    return state
