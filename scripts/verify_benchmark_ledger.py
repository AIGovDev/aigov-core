"""Verify a complete JSONL chain and exact benchmark event coverage offline."""
import argparse
import hashlib
import json
from pathlib import Path


def verify(path, run_id, count):
    previous = "GENESIS"
    observed = set()
    records = 0
    with Path(path).open("rb") as stream:
        for line in stream:
            if not line.endswith(b"\n"):
                raise ValueError("incomplete record")
            record = json.loads(line)
            event_json = record["event_json"]
            expected = hashlib.sha256((previous + "\n" + event_json).encode()).hexdigest()
            if record["prev_hash"] != previous or record["record_hash"] != expected:
                raise ValueError("invalid chain")
            previous = expected
            records += 1
            event = json.loads(event_json)
            if event.get("run_id") == run_id:
                event_id = event["event_id"]
                if event_id in observed:
                    raise ValueError("duplicate event")
                observed.add(event_id)
    if observed != {f"{run_id}-{i}" for i in range(count)}:
        raise ValueError("incorrect event coverage")
    return {"records": records, "head_sha256": previous, "verified": True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ledger", required=True)
    parser.add_argument("--result", required=True)
    args = parser.parse_args()
    path = Path(args.result)
    result = json.loads(path.read_text())
    result["offline_ledger_verification"] = verify(
        args.ledger, result["run_id"], result["events"])
    path.write_text(json.dumps(result, indent=2) + "\n")


if __name__ == "__main__":
    main()
