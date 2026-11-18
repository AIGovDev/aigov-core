"""Deterministic synthetic benchmark; no production/model claims."""
import hashlib
import json

def hash_obj(obj):
    return hashlib.sha256(json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()).hexdigest()

SCENARIOS = ("authorized", "post_approval_change", "wrong_approval_version", "missing_evidence", "tampered_evidence", "replayed_execution", "divergent_state", "partial_failure")

def make_case(name):
    if name not in SCENARIOS:
        raise ValueError(name)
    proposal = {"action": "set_deadline", "target": "tender-1", "value": "2027-06-30T17:00:00+02:00"}
    approval = {"decision": "approve", "proposal_hash": hash_obj(proposal)}
    execution = dict(proposal)
    observed = dict(execution)
    if name == "post_approval_change":
        execution["value"] = "2027-07-02T17:00:00+02:00"
        observed = dict(execution)
    if name == "wrong_approval_version":
        approval["proposal_hash"] = "f" * 64
    if name == "divergent_state":
        observed["value"] = "2027-07-02T17:00:00+02:00"
    if name == "partial_failure":
        observed["value"] = None
    prev, entries = "0" * 64, []
    for kind, payload in zip(("proposal", "approval", "execution", "observation"), (proposal, approval, execution, observed)):
        item = {"kind": kind, "payload": payload, "previous_hash": prev}
        item["hash"] = hash_obj(item)
        entries.append(item)
        prev = item["hash"]
    if name == "missing_evidence":
        entries.pop(1)
    if name == "tampered_evidence":
        entries[1]["payload"]["decision"] = "reject"
    if name == "replayed_execution":
        entries.append(dict(entries[2]))
    return entries

def verify(entries):
    if [e.get("kind") for e in entries] != ["proposal", "approval", "execution", "observation"]:
        return False, "missing_or_replayed_evidence"
    prev = "0" * 64
    for e in entries:
        if e.get("previous_hash") != prev or e.get("hash") != hash_obj({k: v for k, v in e.items() if k != "hash"}):
            return False, "chain_integrity"
        prev = e["hash"]
    proposal, approval, execution, observed = (e["payload"] for e in entries)
    if approval.get("decision") != "approve" or approval.get("proposal_hash") != hash_obj(proposal):
        return False, "approval_binding"
    if execution != proposal:
        return False, "execution_mismatch"
    if observed != execution:
        return False, "observed_state_mismatch"
    return True, "verified"

def run():
    rows = []
    for name in SCENARIOS:
        actual, reason = verify(make_case(name))
        expected = name == "authorized"
        rows.append({"scenario": name, "expected_verified": expected, "verified": actual, "reason": reason, "correct": actual == expected})
    return {"benchmark": "agent-action-verification-v0", "scenario_count": len(rows), "accuracy": sum(x["correct"] for x in rows) / len(rows), "results": rows, "limitations": "Deterministic synthetic fixtures; no real agent, API, or external state."}

if __name__ == "__main__":
    print(json.dumps(run(), indent=2, sort_keys=True))
