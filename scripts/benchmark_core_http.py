"""Opt-in benchmark against a disposable local Core instance, not a production tenant."""
import argparse
import concurrent.futures
import json
import math
import os
import platform
import statistics
import time
import urllib.parse
import uuid

import requests


def percentile(samples, p):
    return sorted(samples)[math.ceil(len(samples) * p) - 1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", required=True)
    parser.add_argument("--events", type=int, default=100)
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--out", required=True)
    parser.add_argument("--disposable", action="store_true", required=True)
    args = parser.parse_args()
    url = urllib.parse.urlsplit(args.url)
    if (url.scheme != "http" or url.hostname not in ("127.0.0.1", "::1")
            or url.username or url.password or url.path not in ("", "/")
            or url.query or url.fragment):
        parser.error("use a disposable loopback HTTP Core")
    if not 1 <= args.events <= 10000 or not 1 <= args.workers <= 32:
        parser.error("events must be 1–10000 and workers 1–32")
    key = os.environ["GOVAI_API_KEY"]
    base = args.url.rstrip("/")
    run = "http-benchmark-" + uuid.uuid4().hex
    headers = {"Authorization": "Bearer " + key}

    def send(i):
        event_id = f"{run}-{i}"
        event = {
            "event_id": event_id, "event_type": "huggingface_evaluation_observed",
            "ts_utc": "2026-01-01T00:00:00Z", "actor": "benchmark",
            "system": "benchmark", "run_id": run,
            "payload": {"record_sha256": "a" * 64, "measurement": "caller_reported"},
        }
        start = time.perf_counter_ns()
        with requests.Session() as session:
            session.trust_env = False
            response = session.post(base + "/evidence", headers=headers, json=event,
                                    timeout=30, allow_redirects=False)
        elapsed = time.perf_counter_ns() - start
        if response.status_code != 200 or response.json().get("ok") is not True:
            raise RuntimeError(f"event rejected: HTTP {response.status_code}")
        return elapsed

    start = time.perf_counter_ns()
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
        samples = list(pool.map(send, range(args.events)))
    elapsed = time.perf_counter_ns() - start
    with requests.Session() as session:
        session.trust_env = False
        response = session.get(base + "/bundle", params={"run_id": run},
                               headers=headers, timeout=30, allow_redirects=False)
    if response.status_code != 200:
        raise RuntimeError("bundle retrieval failed")
    # Verify exact event identifiers as JSON values, not substring matches.
    def strings(value):
        if isinstance(value, dict):
            for v in value.values():
                yield from strings(v)
        elif isinstance(value, list):
            for v in value:
                yield from strings(v)
        elif isinstance(value, str):
            yield value
            if value.startswith("{"):
                try:
                    yield from strings(json.loads(value))
                except json.JSONDecodeError:
                    pass

    observed = set(strings(response.json()))
    if not all(f"{run}-{i}" in observed for i in range(args.events)):
        raise RuntimeError("bundle missing accepted event identifiers")
    result = {
        "schema_version": 1, "benchmark": "core-http-ingestion",
        "revision": os.getenv("AIGOV_BENCHMARK_REVISION"),
        "client_environment": platform.platform(),
        "run_id": run, "events": args.events, "workers": args.workers,
        "samples_ns": samples, "median_ns": statistics.median(samples),
        "p95_ns": percentile(samples, .95), "p99_ns": percentile(samples, .99),
        "wall_ns": elapsed, "events_per_second": args.events * 1e9 / elapsed,
        "all_event_ids_retrieved": True,
        "limitations": ["New HTTP session per event; includes connection setup.",
                        "Backend and server revision require independent runner verification.",
                        "Bundle presence is not independent cryptographic verification."],
    }
    with open(args.out, "x", encoding="utf-8") as output:
        json.dump(result, output, indent=2)


if __name__ == "__main__":
    main()
