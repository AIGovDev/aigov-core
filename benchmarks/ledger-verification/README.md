# Rust long-ledger verification benchmark

This benchmark times AIGov Core's production Rust JSONL hash-chain verifier,
`aigov_audit::verify_chain::verify_chain`, on deterministic synthetic ledgers.
It complements the existing Python in-memory microbenchmarks; it does not replace
the HTTP, PostgreSQL, durability, or concurrent-writer tests.

## Run

From the repository root, with Rust stable installed:

```bash
make long-ledger-verification-benchmark
```

Defaults are 1,000, 10,000, and 100,000 records, a 256-byte payload, one
unrecorded warm-up per scenario, and five timed iterations. Override them with
`AIGOV_LEDGER_BENCHMARK_SIZES` (comma-separated counts up to 1,000,000) and
`AIGOV_LEDGER_BENCHMARK_ITERATIONS` (1–100). The output defaults to
`benchmark-runs/ledger-verification.json` (ignored by Git) and can be overridden
with `AIGOV_LEDGER_BENCHMARK_OUT`. The JSON includes a dataset SHA-256, revision,
Rust compiler, operating system, architecture, raw samples, median, and
nearest-rank p95.

To retain a shareable result, run the repository's manual **Rust ledger
verification benchmark** workflow. Its inputs select the record counts and
iterations, and it uploads the JSON as a workflow artifact. The first run is a
candidate reference, not a universal baseline: compare later runs only when
runner, toolchain, sizes, and iteration count are comparable. No prior timing
numbers are committed or claimed.

Scenarios verify an intact chain and detect a hash alteration at the first,
middle, or last record. The regular Rust integration test separately checks a
small valid chain and a tampered chain; it does not run timing workloads.

## Reproducibility and comparisons

The event payloads and chain construction are deterministic. Timings are not:
they depend on hardware, compiler, filesystem, and OS-managed cache state. For a
comparison, retain the generated JSON, keep the workload and environment fixed,
and repeat the full command on the same machine. Do not turn a single run into a
universal performance claim or a CI timing threshold.

The existing Python hash-chain benchmarks use in-memory data and Python code;
they are useful as a reference workload but are not an apples-to-apples runtime
competitor. This benchmark makes no comparative performance claim against other
products. A fair cross-product study needs aligned record formats, trust and
failure semantics, hardware, and independent runs. No such results are currently
published.

## Scope limits

This measures the file-backed Rust chain verifier only. It does not measure HTTP
request latency, PostgreSQL, concurrent appends, fsync durability, signed-bundle
verification, or cold-cache performance. Synthetic payloads are not a substitute
for customer traces.
