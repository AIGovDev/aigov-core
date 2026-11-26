"""Generate the cross-language registry fixture (format v2) from the Python writer.

    python python/tests/_registry_fixture.py rust/tests/fixtures/key_registry_v2

Writes: registry.json.events.jsonl (the signed log), trust.json (root public keys only), anchor.json (the anchor the log
matches), and expected.json (what a correct reader must conclude). The Rust reader and the Python reader both verify these
files. Seeds are generated into a temporary directory and never written to the fixture.
"""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

from aigov_py.trusted import keys as K
from aigov_py.trusted.registry_anchor import SqliteAnchor


def build(out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="registry-fixture-") as tmp:
        tmpdir = Path(tmp)
        root_seed, root_pub = K.new_signing_seed()
        op_seed, op_pub = K.new_signing_seed()
        op2_seed, op2_pub = K.new_signing_seed()
        a_seed, a_pub = K.new_signing_seed()
        b_seed, b_pub = K.new_signing_seed()
        c_seed, c_pub = K.new_signing_seed()
        trust_doc = {"schema": K.TRUST_SCHEMA, "registry_id": "fixture-registry",
                     "roots": [{"kid": "root-a", "public_key_b64": root_pub, "status": "current"}]}
        trust = K.TrustConfig.from_dict(trust_doc)
        anchor = SqliteAnchor(tmpdir / "anchor.sqlite", "fixture-registry")
        anchor.init()
        reg = K.KeyRegistry(tmpdir / "registry.json", trust=trust, anchor=anchor)

        def root(payload: dict) -> None:
            reg.apply(K.KeyRegistry.sign_request(K.KeyRegistry.new_request(
                expected_version=reg.version, actor="root-a", **payload), root_seed))

        def op(seed: str, identity: str, payload: dict) -> None:
            reg.apply(K.KeyRegistry.sign_request(K.KeyRegistry.new_request(
                expected_version=reg.version, actor=identity, **payload), seed))

        root({"op": "operator_install", "identity": "ops-admin", "public_key_b64": op_pub, "roles": ["keyadmin", "revoker"]})
        op(op_seed, "ops-admin", {"op": "register", "kid": "exe-a", "purpose": "execution_authorization",
                                  "public_key_b64": a_pub, "owner": "authz"})
        op(op_seed, "ops-admin", {"op": "activate", "kid": "exe-a"})
        op(op_seed, "ops-admin", {"op": "register", "kid": "exe-b", "purpose": "execution_authorization",
                                  "public_key_b64": b_pub, "owner": "authz"})
        op(op_seed, "ops-admin", {"op": "rotate", "kid": "exe-a", "successor_kid": "exe-b"})
        root({"op": "operator_revoke", "identity": "ops-admin", "reason": "rotated operator"})
        root({"op": "operator_install", "identity": "ops-admin-2", "public_key_b64": op2_pub, "roles": ["keyadmin", "revoker"]})
        op(op2_seed, "ops-admin-2", {"op": "register", "kid": "exe-c", "purpose": "execution_authorization",
                                     "public_key_b64": c_pub, "owner": "authz"})
        op(op2_seed, "ops-admin-2", {"op": "revoke", "kid": "exe-a", "reason": "retired key confirmed exposed",
                                     "compromised_from_utc": "2026-11-26T00:00:00+00:00"})

        events_text = (tmpdir / "registry.json.events.jsonl").read_text(encoding="utf-8")
        events = [json.loads(line) for line in events_text.splitlines() if line.strip()]
        anchored = anchor.current()
        assert anchored is not None and anchored.seq == len(events)
        out.joinpath("registry.json.events.jsonl").write_text(events_text, encoding="utf-8")
        out.joinpath("trust.json").write_text(json.dumps(trust_doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        out.joinpath("anchor.json").write_text(
            json.dumps({"seq": anchored.seq, "head_hash": anchored.head_hash}, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        active = reg.active_for("execution_authorization")
        expected = {
            "version": len(events),
            "head_hash": anchored.head_hash,
            "statuses": {kid: rec.status for kid, rec in reg.state.keys.items()},
            "active_execution_key": active.kid if active else None,
            "operators": {k: v["status"] for k, v in reg.state.operators.items()},
        }
        out.joinpath("expected.json").write_text(json.dumps(expected, indent=2, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    build(Path(sys.argv[1]))
    print("fixture written")
