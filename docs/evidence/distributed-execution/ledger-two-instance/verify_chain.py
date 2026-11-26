import json, hashlib, sys
path = sys.argv[1]
lines = [l for l in open(path, encoding="utf-8").read().split("\n") if l.strip()]
prev = "GENESIS"; bad = 0; ids = set(); dups = 0
for i, l in enumerate(lines, 1):
    try:
        rec = json.loads(l)
    except Exception:
        print("line", i, "is not JSON"); bad += 1; continue
    if rec.get("prev_hash") != prev:
        bad += 1
        if bad <= 3: print("chain break at", i)
    h = hashlib.sha256((rec["prev_hash"] + "\n" + rec["event_json"]).encode()).hexdigest()
    if h != rec.get("record_hash"):
        bad += 1
        if bad <= 3: print("hash mismatch at", i)
    eid = json.loads(rec["event_json"])["event_id"]
    if eid in ids: dups += 1
    ids.add(eid)
    prev = rec.get("record_hash", prev)
print(f"records={len(lines)} unique_event_ids={len(ids)} duplicate_ids={dups} chain_violations={bad}")
