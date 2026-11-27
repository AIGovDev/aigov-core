"""Generate the deterministic, synthetic evidence export bundled with the HF Space."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "spaces/aigov-core-evidence-viewer/sample-evidence-export.json"


def build_sample() -> dict[str, object]:
    event = {
        "event_id": "sample-run-001",
        "event_type": "evaluation_passed",
        "actor": "synthetic-demo",
        "ts_utc": "2026-01-01T00:00:00Z",
    }
    event_json = json.dumps(event, separators=(",", ":"), sort_keys=True)
    record_hash = hashlib.sha256(f"GENESIS\n{event_json}".encode("utf-8")).hexdigest()
    return {
        "schema_version": "aigov.audit-export.v1",
        "run": {"run_id": "sample-run-001"},
        "policy_version": "demo-policy-1",
        "environment": "synthetic-example",
        "exported_at_utc": "2026-01-01T00:00:01Z",
        "decision": {
            "verdict": "VALID",
            "evaluation_passed": True,
            "blocked_reasons": [],
            "promotion": {"state": "not_requested"},
        },
        "evidence_events": [event],
        "evidence_hashes": {
            "log_chain": [
                {
                    "prev_hash": "GENESIS",
                    "event_json": event_json,
                    "record_hash": record_hash,
                }
            ],
            "chain_head_record_sha256": record_hash,
        },
        "sample_notice": "Synthetic demonstration data; this does not attest to a real action.",
    }


def main() -> None:
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps(build_sample(), indent=2) + "\n", encoding="utf-8")
    print(f"Wrote deterministic synthetic sample: {OUTPUT.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
