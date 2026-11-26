import json, sys, threading, urllib.request, hashlib, uuid
from concurrent.futures import ThreadPoolExecutor
PORTS = [18101, 18102]
N = int(sys.argv[1]) if len(sys.argv) > 1 else 150
RUN = "run-mc-" + uuid.uuid4().hex[:8]
def post(port, eid):
    body = {"event_id": eid, "event_type": "tool_call", "ts_utc": "2026-11-26T10:00:00Z", "actor": "agent",
            "system": "mc", "run_id": RUN, "payload": {"tool_name": "create_file", "n": eid}}
    req = urllib.request.Request(f"http://127.0.0.1:{port}/evidence", data=json.dumps(body).encode(),
        headers={"Authorization": "Bearer mc-key", "Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=20) as r: return r.status
    except urllib.error.HTTPError as e: return e.code
    except Exception as e: return type(e).__name__
jobs = [(PORTS[i % 2], f"evt-{i}") for i in range(N)]
with ThreadPoolExecutor(max_workers=16) as ex:
    res = list(ex.map(lambda j: post(*j), jobs))
from collections import Counter
print("statuses", Counter(res))
