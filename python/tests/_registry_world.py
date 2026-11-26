"""Shared world for registry tests: a trust file, an anchor, a root, operators, and keys, all in a temporary directory.

The anchor is the SQLite one (same contract as PostgreSQL). PostgreSQL-backed tests use ``test_registry_postgres.py``.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from aigov_py.trusted import keys as K
from _sqlite_anchor import SqliteAnchor

REGISTRY_ID = "test-registry"


def write_secret_file(path: Path, text: str, mode: int = 0o600) -> None:
    path.write_text(text, encoding="utf-8")
    os.chmod(path, mode)


class World:
    def __init__(self, root: Path, *, registry_id: str = REGISTRY_ID, anchor: object | None = None) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.registry_id = registry_id
        self.root_seed, self.root_pub = K.new_signing_seed()
        self.trust_doc: dict[str, Any] = {
            "schema": K.TRUST_SCHEMA,
            "registry_id": registry_id,
            "roots": [{"kid": "root-a", "public_key_b64": self.root_pub, "status": "current"}],
        }
        self.trust_path = self.root / "trust.json"
        write_secret_file(self.trust_path, json.dumps(self.trust_doc, indent=2))
        self.trust = K.TrustConfig.load(self.trust_path)
        self.anchor = anchor if anchor is not None else SqliteAnchor(self.root / "anchor.sqlite", registry_id)
        self.anchor.init()
        self.registry_path = self.root / "registry.json"
        self.reg = K.KeyRegistry(self.registry_path, trust=self.trust, anchor=self.anchor)
        self.operators: dict[str, str] = {}  # identity -> seed
        self.keys: dict[str, tuple[str, str]] = {}  # kid -> (seed, public key)

    # --- readers and writers ----------------------------------------------------------------------------------------

    def reader(self) -> K.KeyRegistry:
        """A fresh reader, as Core or the executor would be."""
        return K.KeyRegistry(self.registry_path, trust=self.trust, anchor=self.anchor)

    def install_operator(self, identity: str, roles: tuple[str, ...] = ("keyadmin", "revoker")) -> str:
        seed, pub = K.new_signing_seed()
        self.operators[identity] = seed
        self.reg.refresh()
        req = K.KeyRegistry.sign_request(K.KeyRegistry.new_request(
            op="operator_install", actor="root-a", expected_version=self.reg.version,
            identity=identity, public_key_b64=pub, roles=list(roles)), self.root_seed)
        self.reg.apply(req)
        return seed

    def root_op(self, op: str, **fields: Any) -> dict[str, Any]:
        self.reg.refresh()
        req = K.KeyRegistry.sign_request(K.KeyRegistry.new_request(
            op=op, actor="root-a", expected_version=self.reg.version, **fields), self.root_seed)
        return self.reg.apply(req)

    def op(self, identity: str, op: str, **fields: Any) -> dict[str, Any]:
        self.reg.refresh()
        req = K.KeyRegistry.sign_request(K.KeyRegistry.new_request(
            op=op, actor=identity, expected_version=self.reg.version, **fields), self.operators[identity])
        return self.reg.apply(req)

    def new_key(self, kid: str) -> tuple[str, str]:
        seed, pub = K.new_signing_seed()
        self.keys[kid] = (seed, pub)
        return seed, pub

    def register_pending(self, kid: str, identity: str = "ops-admin") -> None:
        """Register a key without activating it (a successor, or a key that is not yet in use)."""
        seed, pub = self.keys.get(kid) or self.new_key(kid)
        self.op(identity, "register", kid=kid, purpose="execution_authorization", public_key_b64=pub, owner="authz")

    def register_active(self, kid: str, identity: str = "ops-admin") -> str:
        seed, pub = self.keys.get(kid) or self.new_key(kid)
        self.op(identity, "register", kid=kid, purpose="execution_authorization", public_key_b64=pub, owner="authz")
        self.op(identity, "activate", kid=kid)
        return seed

    def rotate(self, old: str, new: str, identity: str = "ops-admin") -> None:
        if new not in self.keys:
            self.new_key(new)
        _, pub = self.keys[new]
        self.op(identity, "register", kid=new, purpose="execution_authorization", public_key_b64=pub, owner="authz")
        self.op(identity, "rotate", kid=old, successor_kid=new)

    def revoke(self, kid: str, identity: str = "ops-admin", *, compromised_from: str = "2026-11-26T00:00:00+00:00") -> None:
        self.op(identity, "revoke", kid=kid, reason="test compromise", compromised_from_utc=compromised_from)

    def events(self) -> list[dict[str, Any]]:
        p = self.registry_path.with_name(self.registry_path.name + ".events.jsonl")
        return [json.loads(line) for line in p.read_text(encoding="utf-8").splitlines() if line.strip()]

    def write_events(self, events: list[dict[str, Any]]) -> None:
        p = self.registry_path.with_name(self.registry_path.name + ".events.jsonl")
        p.write_text("".join(json.dumps(e, sort_keys=True) + "\n" for e in events), encoding="utf-8")


def settle_anchor(world: World) -> None:
    """Anchor the log as it is: the state a completed write leaves behind (used after a deliberate tamper test)."""
    events = world.events()
    head = events[-1]["hash"] if events else "GENESIS"
    with world.anchor.exclusive() as tx:
        cur = tx.current()
        tx.set(_state(len(events), head), expected=cur)


def _state(seq: int, head: str):
    from aigov_py.trusted.registry_anchor import AnchorState

    return AnchorState(seq, head)


def _commit_worker(args: tuple[str, str, str, str, str, str]) -> str:
    """Process-pool worker: try to revoke ``kid`` against the registry at ``expected_version``. Returns the outcome.

    ``anchor_url`` empty means the SQLite anchor in the registry directory; otherwise the PostgreSQL anchor at that URL.
    """
    root, identity, seed, kid, anchor_url, registry_id = args
    from aigov_py.trusted import keys as _K
    from aigov_py.trusted.registry_anchor import PostgresAnchor as _P
    from _sqlite_anchor import SqliteAnchor as _A

    anchor = _P(anchor_url, registry_id) if anchor_url else _A(Path(root) / "anchor.sqlite", registry_id)
    reg = _K.KeyRegistry(Path(root) / "registry.json", trust=_K.TrustConfig.load(Path(root) / "trust.json"),
                         anchor=anchor)
    try:
        req = _K.KeyRegistry.sign_request(_K.KeyRegistry.new_request(
            op="revoke", actor=identity, expected_version=reg.version, kid=kid, reason="race",
            compromised_from_utc="2026-11-26T00:00:00+00:00"), seed)
        reg.apply(req)
        return "applied"
    except _K.KeyRegistryError as exc:
        return exc.code
