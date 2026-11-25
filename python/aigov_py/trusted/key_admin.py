"""Operator tool for the trusted key registry.

    python -m aigov_py.trusted.key_admin --registry PATH <command> ...

Commands:

    inspect                         show keys, statuses, operators, and the integrity check (read only)
    new-operator-key OUT_SEED       create an operator key pair: writes the seed to OUT_SEED (0600), prints the public key
    install-operator IDENTITY PUB ROLES
                                    bootstrap the first operator (only while no operator exists)
    request OP SEED_FILE [args]     build and sign a request, print it as JSON on stdout
    apply REQUEST_FILE              apply a signed request file to the registry

Every state change is a signed request: an operator in the registry, the needed role, the current registry version, and a
fresh nonce. Seeds are read from files and are never printed or logged. ``request`` prints the signed request; ``apply``
checks it against the registry at the moment of application.

Emergency revocation: ``request revoke SEED --kid K --reason TEXT --compromised-from ISO8601`` then ``apply``. Revocation
is terminal and needs the ``revoker`` role. See docs/operations/key-management-runbook.md.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import sys
from pathlib import Path

from aigov_py.trusted import keys as K


def _load_seed(path: str) -> str:
    seed = Path(path).read_text(encoding="utf-8").strip()
    base64.b64decode(seed, validate=True)
    return seed


def _write_secret(path: str, value: str) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(value + "\n")


def cmd_inspect(reg: K.KeyRegistry) -> dict:
    return {
        "version": reg.version,
        "snapshot_matches_log": reg.snapshot_matches,
        "integrity": reg.verify_integrity(),
        "operators": {k: sorted(v["roles"]) for k, v in reg.state.operators.items()},
        "keys": {kid: {"purpose": r.purpose, "status": r.status, "owner": r.owner} for kid, r in reg.state.keys.items()},
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="key_admin", description=__doc__.split("\n\n")[0])
    parser.add_argument("--registry", required=True, type=Path)
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("inspect")
    p = sub.add_parser("new-operator-key")
    p.add_argument("out_seed")
    p = sub.add_parser("install-operator")
    p.add_argument("identity")
    p.add_argument("public_key_b64")
    p.add_argument("roles", nargs="+", choices=K.OPERATOR_ROLES)
    p = sub.add_parser("request")
    p.add_argument("op", choices=K.OPS)
    p.add_argument("seed_file")
    p.add_argument("--actor", required=True)
    p.add_argument("--kid")
    p.add_argument("--purpose", choices=K.PURPOSES)
    p.add_argument("--public-key-b64")
    p.add_argument("--owner")
    p.add_argument("--successor-kid")
    p.add_argument("--reason")
    p.add_argument("--compromised-from")
    p = sub.add_parser("apply")
    p.add_argument("request_file")
    args = parser.parse_args(argv)

    if args.cmd == "new-operator-key":
        seed, pub = K.new_signing_seed()
        _write_secret(args.out_seed, seed)
        print(json.dumps({"seed_file": args.out_seed, "public_key_b64": pub}))
        return 0

    reg = K.KeyRegistry(args.registry)

    try:
        if args.cmd == "inspect":
            print(json.dumps(cmd_inspect(reg), indent=2, sort_keys=True))
            return 0
        if args.cmd == "install-operator":
            reg.install_operator(args.identity, args.public_key_b64, tuple(args.roles))
            print(json.dumps({"installed": args.identity, "roles": args.roles, "version": reg.version}))
            return 0
        if args.cmd == "request":
            seed = _load_seed(args.seed_file)
            fields = {}
            if args.op == "register":
                fields = {"kid": args.kid, "purpose": args.purpose, "public_key_b64": args.public_key_b64,
                          "owner": args.owner or args.actor}
            elif args.op == "rotate":
                fields = {"kid": args.kid, "purpose": args.purpose, "successor_kid": args.successor_kid}
            elif args.op == "revoke":
                fields = {"kid": args.kid, "reason": args.reason or "",
                          "compromised_from_utc": args.compromised_from}
            else:
                fields = {"kid": args.kid}
            payload_req = K.KeyRegistry.new_request(op=args.op, actor=args.actor, expected_version=reg.version, **fields)
            print(json.dumps(K.KeyRegistry.sign_request(payload_req, seed), sort_keys=True))
            return 0
        if args.cmd == "apply":
            request = json.loads(Path(args.request_file).read_text(encoding="utf-8"))
            op = request["payload"]["op"]
            handlers = {
                "register": reg.register,
                "activate": reg.activate,
                "retire": reg.retire,
                "revoke": reg.revoke,
                "rotate": reg.rotate,
            }
            if op not in handlers:
                print(json.dumps({"error": "unsupported_op", "op": op}), file=sys.stderr)
                return 2
            handlers[op](request)
            print(json.dumps({"applied": op, "version": reg.version}))
            return 0
    except K.KeyRegistryError as exc:
        print(json.dumps({"error": exc.code, "detail": exc.detail}), file=sys.stderr)
        return 3
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
