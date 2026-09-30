#!/usr/bin/env python3
"""Synthetic microbenchmark driver (docs/research/microbenchmarks.md).

Measures synthetic hash-chain construction, verification, a toy compliance
projection, and JSON export serialization. Complements, but does not
replace, docs/research/empirical-evaluation.md's larger suite or
production observability under docs/observability/.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import empirical_benchmark_lib as lib

SEED = 1337
CHAIN_LENGTH = 5_000


def toy_compliance_derivation(events: list[dict]) -> str:
    """Deterministic toy check: BLOCKED unless both evaluation_reported and human_approved are present."""
    types = {e["event_type"] for e in events}
    if "human_approved" not in types:
        return "BLOCKED"
    if "evaluation_reported" not in types:
        return "BLOCKED"
    return "VALID"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    # event_creation_throughput
    start = lib.timer()
    chain = lib.build_synthetic_chain(CHAIN_LENGTH, payload_bytes=256, seed=SEED)
    create_s = lib.elapsed_ms(start) / 1000.0
    event_creation_throughput_events_per_sec = round(CHAIN_LENGTH / create_s, 3) if create_s > 0 else None

    # hash_chain_verification_seconds
    start = lib.timer()
    ok, _ = lib.verify_chain(chain)
    hash_chain_verification_seconds = round(lib.elapsed_ms(start) / 1000.0, 6)

    # compliance_derivation_seconds (toy, deterministic — alternate event types for variety)
    toy_types = ("data_registered", "evaluation_reported", "human_approved", "model_promoted")
    toy_events = [{"event_type": toy_types[i % len(toy_types)]} for i in range(1000)]
    start = lib.timer()
    verdict = toy_compliance_derivation(toy_events)
    compliance_derivation_seconds = round(lib.elapsed_ms(start) / 1000.0, 6)

    # export_generation_seconds
    events = [json.loads(r["event_json"]) for r in chain]
    start = lib.timer()
    json.dumps({"events": events}, separators=(",", ":"), sort_keys=True)
    export_generation_seconds = round(lib.elapsed_ms(start) / 1000.0, 6)

    result = {
        "version": 1,
        "ok": ok,
        "seed": SEED,
        "chain_length": CHAIN_LENGTH,
        "environment": lib.env_metadata(),
        "measurements": {
            "event_creation_throughput_events_per_sec": event_creation_throughput_events_per_sec,
            "hash_chain_verification_seconds": hash_chain_verification_seconds,
            "compliance_derivation_seconds": compliance_derivation_seconds,
            "export_generation_seconds": export_generation_seconds,
        },
        "toy_compliance_verdict_sample": verdict,
    }

    if args.json:
        print(json.dumps(result, sort_keys=True))
    else:
        print(f"microbenchmark_audit_engine: ok={ok}")
        for k, v in result["measurements"].items():
            print(f"  {k}: {v}")

    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
