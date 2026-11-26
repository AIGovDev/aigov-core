"""Operator tool for the trusted key registry (format v2).

    python -m aigov_py.trusted.key_admin --registry PATH --trust TRUST_FILE [--anchor-url URL] <command>

Commands:

    inspect                          verify the log and the anchor; print keys, operators, and the head (read only)
    anchor-init                      create the anchor row at genesis (once per registry; refused if it exists)
    new-key OUT_SEED                 create an Ed25519 key pair: write the seed to OUT_SEED (0600), print the public key
    request OP SEED_FILE [fields]    build and sign a request and print it as JSON on stdout (nothing is written)
    apply REQUEST_FILE               verify and commit one signed request (log append, then anchor compare-and-swap)
    reconcile                        anchor the one event a crash left between the append and the anchor commit
    migrate-v1 --v1-registry PATH --root-kid K --root-seed-file F
                                     import a v1 registry as one root-signed legacy_import event (explicit; see the runbook)

Root operations (``operator_install``, ``operator_revoke``) are signed by a root key pinned in the trust file, never by a
key from the registry. Other operations are signed by an operator in the registry with the needed role. Every request
carries the expected version and a fresh nonce; a request applies once, to the version it names.

Anchor: ``--anchor-url`` (or ``AIGOV_KEY_REGISTRY_ANCHOR_URL``, else ``GOVAI_DATABASE_URL``) selects the PostgreSQL anchor.
The table is created by migration ``0004_key_registry_anchor``; ``anchor-init`` refuses if it is missing.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import sys
from pathlib import Path
from typing import Any

from aigov_py.trusted import keys as K
from aigov_py.trusted.registry_anchor import AnchorError, PostgresAnchor


def _load_seed(path: str) -> str:
    seed = Path(path).read_text(encoding="utf-8").strip()
    base64.b64decode(seed, validate=True)
    return seed


def _write_secret(path: str, value: str) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(value + "\n")


def _anchor(args: argparse.Namespace, registry_id: str, factory: Any = None) -> object:
    if factory is not None:  # tests only: an injected anchor with the same contract
        return factory(registry_id)
    url = args.anchor_url or os.environ.get("AIGOV_KEY_REGISTRY_ANCHOR_URL") or os.environ.get("GOVAI_DATABASE_URL") or ""
    return PostgresAnchor(url, registry_id)


def cmd_inspect(reg: K.KeyRegistry) -> dict:
    return {
        "version": reg.version,
        "integrity": reg.verify_integrity(),
        "operators": {k: {"roles": sorted(v["roles"]), "status": v["status"]} for k, v in reg.state.operators.items()},
        "keys": {kid: {"purpose": r.purpose, "status": r.status, "owner": r.owner, "provenance": r.provenance}
                 for kid, r in reg.state.keys.items()},
    }


def _request_fields(args: argparse.Namespace) -> dict:
    if args.op == "operator_install":
        return {"identity": args.identity, "public_key_b64": args.public_key_b64, "roles": args.roles}
    if args.op == "operator_revoke":
        return {"identity": args.identity, "reason": args.reason or ""}
    if args.op == "register":
        return {"kid": args.kid, "purpose": args.purpose, "public_key_b64": args.public_key_b64,
                "owner": args.owner or args.actor}
    if args.op == "rotate":
        return {"kid": args.kid, "successor_kid": args.successor_kid}
    if args.op == "revoke":
        return {"kid": args.kid, "reason": args.reason or "", "compromised_from_utc": args.compromised_from}
    return {"kid": args.kid}


def main(argv: list[str] | None = None, *, anchor_factory: Any = None) -> int:
    parser = argparse.ArgumentParser(prog="key_admin", description=__doc__.split("\n\n")[0])
    parser.add_argument("--registry", required=True, type=Path)
    parser.add_argument("--trust", required=True, type=Path)
    parser.add_argument("--anchor-url", default=None)
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("inspect")
    sub.add_parser("anchor-init")
    sub.add_parser("reconcile")
    p = sub.add_parser("new-key")
    p.add_argument("out_seed")
    p = sub.add_parser("request")
    p.add_argument("op", choices=K.OPS)
    p.add_argument("seed_file")
    p.add_argument("--actor", required=True, help="operator identity, or a root kid for root operations")
    p.add_argument("--identity")
    p.add_argument("--roles", nargs="+", choices=K.OPERATOR_ROLES)
    p.add_argument("--kid")
    p.add_argument("--purpose", choices=K.PURPOSES)
    p.add_argument("--public-key-b64")
    p.add_argument("--owner")
    p.add_argument("--successor-kid")
    p.add_argument("--reason")
    p.add_argument("--compromised-from")
    p = sub.add_parser("apply")
    p.add_argument("request_file")
    p = sub.add_parser("migrate-v1")
    p.add_argument("--v1-registry", required=True, type=Path)
    p.add_argument("--root-kid", required=True)
    p.add_argument("--root-seed-file", required=True)
    args = parser.parse_args(argv)

    if args.cmd == "new-key":
        seed, pub = K.new_signing_seed()
        _write_secret(args.out_seed, seed)
        print(json.dumps({"seed_file": args.out_seed, "public_key_b64": pub}))
        return 0

    try:
        trust = K.TrustConfig.load(args.trust)
        anchor = _anchor(args, trust.registry_id, anchor_factory)
        if args.cmd == "anchor-init":
            anchor.init()
            print(json.dumps({"anchor": "initialized", "registry_id": trust.registry_id}))
            return 0
        if args.cmd == "migrate-v1":
            result = K.migrate_v1(args.v1_registry, args.registry, trust=trust, anchor=anchor, root_kid=args.root_kid,
                                  root_seed_b64=_load_seed(args.root_seed_file))
            print(json.dumps({"migrated": True, **result}, sort_keys=True))
            return 0
        reg = K.KeyRegistry(args.registry, trust=trust, anchor=anchor)
        if args.cmd == "inspect":
            print(json.dumps(cmd_inspect(reg), indent=2, sort_keys=True))
            return 0
        if args.cmd == "reconcile":
            new = reg.reconcile()
            print(json.dumps({"reconciled_to": new.seq, "head_hash": new.head_hash}))
            return 0
        if args.cmd == "request":
            seed = _load_seed(args.seed_file)
            payload = K.KeyRegistry.new_request(op=args.op, actor=args.actor, expected_version=reg.version,
                                                **_request_fields(args))
            print(json.dumps(K.KeyRegistry.sign_request(payload, seed), sort_keys=True))
            return 0
        if args.cmd == "apply":
            request = json.loads(Path(args.request_file).read_text(encoding="utf-8"))
            ev = reg.apply(request)
            print(json.dumps({"applied": request["payload"]["op"], "seq": ev["seq"], "head_hash": ev["hash"]}))
            return 0
    except (K.KeyRegistryError, AnchorError) as exc:
        print(json.dumps({"error": exc.code, "detail": exc.detail}), file=sys.stderr)
        return 3
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
