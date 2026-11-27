# AIGov Core benchmark suites

The repository contains functional evaluation scenarios and opt-in performance measurements. Their purposes and limits differ; results must be described using the scope of the specific suite.

## Suites

| Suite | Path | Purpose |
| --- | --- | --- |
| Auditability failure catalogue | [auditability-failures](auditability-failures/README.md) | Deterministic teaching and regression signals; not a second verdict engine. |
| Agent verification | [agent-verification](agent-verification/README.md) | Synthetic evaluation of self-report, tool response, independent read-back, and evidence verification conditions. |
| OpenAI Agents SDK integration | [openai-agents-integration](openai-agents-integration/README.md) | Offline adversarial integration tests; no live inference or performance comparison. |
| Rust long-ledger verification | [ledger-verification](ledger-verification/README.md) | Opt-in timing of the production Rust file-backed hash-chain verifier on valid and tampered ledgers. |

The Python empirical suite under `scripts/run_full_empirical_evaluation.py` measures synthetic in-memory workloads. The new Rust benchmark complements it by calling Core's actual file-backed verifier; neither measures production HTTP or PostgreSQL load.

## Run functional checks

```bash
python benchmarks/auditability-failures/run_benchmark.py
# or via Makefile aggregation:
make oss-ecosystem-check
```

## Run the Rust ledger benchmark

```bash
make long-ledger-verification-benchmark
```

This is a manual performance run, separate from ordinary timing-insensitive tests. It writes machine-readable output under the ignored `benchmark-runs/` directory. A manual GitHub Actions workflow uploads the same JSON as an artifact.

## Comparison limits

No cross-product performance numbers are published. The existing Python in-memory timings are not comparable to the Rust file-backed verifier. A fair external comparison needs identical input data, verification semantics, hardware, compiler/runtime settings, and repeat runs. The repository does not present results until that protocol has been followed.

## Non-goals

- No leaderboard hosting, no external APIs, no GPU workloads.
- Synthetic scenarios do not represent customer traffic, and timings are not CI thresholds.
