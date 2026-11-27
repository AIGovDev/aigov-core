#!/usr/bin/env python3
"""Verify a JSONL ledger against an independently obtained tenant checkpoint."""
import argparse
import hashlib
import json
import re
import sys

def verify(stream, expected_count, expected_hash):
    if expected_count < 0 or not (re.fullmatch(r"[0-9a-f]{64}", expected_hash) or expected_count == 0 and expected_hash == "GENESIS"):
        raise ValueError("invalid checkpoint")
    previous = "GENESIS"
    count = 0
    for line in stream:
        if not line.endswith(b"\n"):
            raise ValueError("incomplete record")
        record = json.loads(line)
        event = record["event_json"]
        if not isinstance(json.loads(event), dict):
            raise ValueError("invalid event")
        digest = hashlib.sha256((previous + "\n" + event).encode("utf-8")).hexdigest()
        if record["prev_hash"] != previous or record["record_hash"] != digest:
            raise ValueError("chain mismatch")
        previous = digest
        count += 1
        if count > expected_count:
            raise ValueError("unexpected additional record")
    if count != expected_count or previous != expected_hash:
        raise ValueError("checkpoint mismatch")
    return {"verified": True, "records": count, "head": previous}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("ledger")
    parser.add_argument("--count", type=int, required=True)
    parser.add_argument("--head", required=True)
    args = parser.parse_args()
    try:
        with open(args.ledger, "rb") as stream:
            print(json.dumps(verify(stream, args.count, args.head)))
    except (OSError, ValueError, KeyError, TypeError) as error:
        print("verification failed: " + type(error).__name__, file=sys.stderr)
        return 1
    return 0

if __name__ == "__main__":
    sys.exit(main())
