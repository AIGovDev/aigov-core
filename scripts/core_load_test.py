#!/usr/bin/env python3
"""Reproducible load test of one Core process: throughput, latency percentiles, status codes, client timeouts, memory, and
recovery after overload. Starts its own Core (dev mode, principals configured, no database) on a fresh ledger, sweeps the
concurrency levels for a fixed duration each, probes recovery at low concurrency after the peak, and verifies the ledger chain.

Measured from the client. The load generator runs on the same host as Core, so it shares CPU with it; the numbers are for
this host and this generator, not for a production deployment.

Usage: core_load_test.py --binary rust/target/release/aigov_audit --out-dir <dir> [--levels 1,4,16,64,256]
       [--seconds 15] [--max-concurrent N] [--timeout-secs N]
"""

from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import os
import platform
import statistics
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

AGENT = "agent-load"
TENANT = "t-load"


def _free_port() -> int:
    import socket

    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _rss_kb(pid: int) -> int | None:
    out = subprocess.run(["ps", "-o", "rss=", "-p", str(pid)], capture_output=True, text=True).stdout.strip()
    return int(out) if out.isdigit() else None


class Core:
    def __init__(self, binary: Path, ledger: Path, port: int, extra_env: dict[str, str], log: Path) -> None:
        env = {k: v for k, v in os.environ.items() if not k.startswith(("AIGOV_", "GOVAI_")) and k != "DATABASE_URL"}
        env.update({
            "AIGOV_ENVIRONMENT": "dev",
            "GOVAI_LEDGER_DIR": str(ledger),
            "AIGOV_BIND": f"127.0.0.1:{port}",
            "GOVAI_API_KEYS": AGENT,
            "GOVAI_API_KEYS_JSON": json.dumps({AGENT: TENANT}),
            "GOVAI_PRINCIPALS_JSON": json.dumps({AGENT: {"principal": "agent:load", "identity": "agent:load", "role": "agent", "tenant": TENANT}}),
        })
        env.update(extra_env)
        self.port = port
        self.log = open(log, "w")  # noqa: SIM115
        self.proc = subprocess.Popen([str(binary)], env=env, stdout=self.log, stderr=subprocess.STDOUT)
        deadline = time.time() + 30
        while time.time() < deadline:
            if self.proc.poll() is not None:
                raise RuntimeError(f"Core exited at start: {self.proc.returncode}")
            try:
                c = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
                c.request("GET", "/health")
                if c.getresponse().status == 200:
                    return
            except OSError:
                time.sleep(0.1)
        raise RuntimeError("Core did not start")

    def close(self) -> None:
        self.proc.terminate()
        try:
            self.proc.wait(timeout=20)
        except subprocess.TimeoutExpired:
            self.proc.kill()
        self.log.close()


def _event() -> bytes:
    return json.dumps({
        "event_id": f"load-{uuid.uuid4().hex}",
        "event_type": "ai_discovery_reported",
        "ts_utc": "2026-11-26T10:00:00Z",
        "actor": "load",
        "system": "load",
        "run_id": f"load-run-{uuid.uuid4().hex[:6]}",
        "payload": {"openai": False},
    }).encode()


def _worker(port: int, stop_at: float, timeout: float, out: list) -> None:
    conn = None
    headers = {"Authorization": f"Bearer {AGENT}", "Content-Type": "application/json"}
    while time.time() < stop_at:
        if conn is None:
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
        t0 = time.perf_counter()
        try:
            conn.request("POST", "/evidence", body=_event(), headers=headers)
            resp = conn.getresponse()
            resp.read()
            out.append((resp.status, (time.perf_counter() - t0) * 1000))
            if resp.getheader("Connection", "").lower() == "close":
                conn.close()
                conn = None
        except (OSError, http.client.HTTPException) as e:
            out.append(("client:" + type(e).__name__, (time.perf_counter() - t0) * 1000))
            conn.close()
            conn = None
    if conn is not None:
        conn.close()


def _percentile(xs: list[float], p: float) -> float | None:
    if not xs:
        return None
    xs = sorted(xs)
    k = max(0, min(len(xs) - 1, int(round(p / 100 * len(xs) + 0.5)) - 1))
    return round(xs[k], 2)


def run_level(port: int, pid: int, concurrency: int, seconds: float, timeout: float) -> dict:
    samples: list = []
    rss: list[int] = []
    stop_at = time.time() + seconds
    stop_rss = threading.Event()

    def sampler() -> None:
        while not stop_rss.is_set():
            v = _rss_kb(pid)
            if v:
                rss.append(v)
            time.sleep(0.5)

    st = threading.Thread(target=sampler, daemon=True)
    st.start()
    start = time.time()
    with ThreadPoolExecutor(max_workers=concurrency) as ex:
        futs = [ex.submit(_worker, port, stop_at, timeout, samples) for _ in range(concurrency)]
        for f in futs:
            f.result()
    wall = time.time() - start
    stop_rss.set()
    st.join(2)
    codes: dict[str, int] = {}
    ok_lat = []
    all_lat = []
    for code, ms in samples:
        codes[str(code)] = codes.get(str(code), 0) + 1
        all_lat.append(ms)
        if code == 200:
            ok_lat.append(ms)
    total = len(samples)
    refused = sum(v for k, v in codes.items() if k != "200")
    return {
        "concurrency": concurrency,
        "seconds": round(wall, 2),
        "requests": total,
        "ok_200": codes.get("200", 0),
        "throughput_ok_per_s": round(codes.get("200", 0) / wall, 1) if wall else None,
        "latency_ok_ms": {"p50": _percentile(ok_lat, 50), "p95": _percentile(ok_lat, 95), "p99": _percentile(ok_lat, 99), "n": len(ok_lat)},
        "latency_all_ms": {"p50": _percentile(all_lat, 50), "p95": _percentile(all_lat, 95), "p99": _percentile(all_lat, 99)},
        "status_codes": codes,
        "non_200_fraction": round(refused / total, 4) if total else None,
        "client_timeouts": sum(v for k, v in codes.items() if k in ("client:timeout", "client:TimeoutError", "client:socket.timeout")),
        "rss_kb_max": max(rss) if rss else None,
        "rss_kb_end": rss[-1] if rss else None,
    }


def verify_chain(ledger: Path) -> dict:
    files = list(ledger.glob("audit_log__*.jsonl"))
    total = 0
    ok = True
    for f in files:
        prev = "GENESIS"
        for line in f.read_text().splitlines():
            if not line.strip():
                continue
            rec = json.loads(line)
            if rec["prev_hash"] != prev:
                ok = False
            if hashlib.sha256((rec["prev_hash"] + "\n" + rec["event_json"]).encode()).hexdigest() != rec["record_hash"]:
                ok = False
            prev = rec["record_hash"]
            total += 1
    return {"chain_ok": ok, "records": total}


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--binary", type=Path, required=True)
    ap.add_argument("--out-dir", type=Path, required=True)
    ap.add_argument("--levels", default="1,4,16,64,256")
    ap.add_argument("--seconds", type=float, default=15)
    ap.add_argument("--max-concurrent", type=int, default=None, help="AIGOV_MAX_CONCURRENT_REQUESTS for this sweep")
    ap.add_argument("--timeout-secs", type=float, default=30, help="AIGOV_REQUEST_TIMEOUT_SECS for this sweep")
    args = ap.parse_args(argv)
    args.out_dir.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix="load-core-"))
    ledger = work / "ledger"
    ledger.mkdir()
    port = _free_port()
    extra = {"AIGOV_REQUEST_TIMEOUT_SECS": str(int(args.timeout_secs))}
    if args.max_concurrent is not None:
        extra["AIGOV_MAX_CONCURRENT_REQUESTS"] = str(args.max_concurrent)
    core = Core(args.binary, ledger, port, extra, work / "core.log")
    levels = [int(x) for x in args.levels.split(",")]
    result = {
        "started_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "platform": platform.platform(),
        "cpu_count": os.cpu_count(),
        "load_average_start": os.getloadavg(),
        "settings": {"max_concurrent_requests": args.max_concurrent or "default (256)", "request_timeout_secs": args.timeout_secs, "seconds_per_level": args.seconds},
        "levels": [],
    }
    try:
        for c in levels:
            lvl = run_level(port, core.proc.pid, c, args.seconds, timeout=args.timeout_secs + 5)
            result["levels"].append(lvl)
            print(f"c={c}: ok/s={lvl['throughput_ok_per_s']} p50={lvl['latency_ok_ms']['p50']} p95={lvl['latency_ok_ms']['p95']} p99={lvl['latency_ok_ms']['p99']} codes={lvl['status_codes']} rss_max_kb={lvl['rss_kb_max']}", flush=True)
        # Recovery: after the peak, a light probe must return to the low-load latency and error rate.
        probe = run_level(port, core.proc.pid, 1, 10, timeout=args.timeout_secs + 5)
        result["recovery_probe_c1"] = probe
        print(f"recovery c=1: ok/s={probe['throughput_ok_per_s']} p50={probe['latency_ok_ms']['p50']} codes={probe['status_codes']}", flush=True)
        alive = core.proc.poll() is None
        result["process_alive_after_sweep"] = alive
    finally:
        core.close()
    result["ledger"] = verify_chain(ledger)
    # Requests that the client saw as 200 are recorded. A record without a 200 is an outcome the client did not see
    # (a timeout or a refusal that was still recorded). Counted here so the gap is measured, not assumed.
    ok_total = sum(lvl["ok_200"] for lvl in result["levels"]) + result.get("recovery_probe_c1", {}).get("ok_200", 0)
    result["ledger"]["records_without_200_response"] = result["ledger"]["records"] - ok_total
    result["load_average_end"] = os.getloadavg()
    result["process_exit_code"] = core.proc.returncode
    tag = ("max" + str(args.max_concurrent)) if args.max_concurrent else "default"
    name = f"load-{tag}-timeout{int(args.timeout_secs)}s.json"
    (args.out_dir / name).write_text(json.dumps(result, indent=2) + "\n")
    print(f"wrote {args.out_dir / name}; chain_ok={result['ledger']['chain_ok']} records={result['ledger']['records']}")
    return 0 if result["ledger"]["chain_ok"] and result["process_alive_after_sweep"] else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
