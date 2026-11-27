# AIGov Core benchmark note for public use

## Measured study available today

The reproducible result currently suitable for technical discussion is the repository 20-scenario independent agent-verification benchmark, reported on 2026-11-19. It contains 5 positive and 15 negative synthetic/scripted scenarios. In that dataset, AIGov evidence-verification condition D produced 5 true positives, 2 false positives, 13 true negatives and 0 false negatives: precision 0.71, recall 1.00, F1 0.833, accuracy 0.90, false-accept rate 0.133 and false-reject rate 0.000. The sample is small; its reported Wilson 95% accuracy interval is [0.768, 1.000].

The two false positives are particularly important: one cross-tenant scenario and one external-state disagreement had a structurally valid chain but insufficient authorization context. This illustrates that chain integrity by itself cannot verify external truth or authorization context.

## What was and was not measured

- Measured: deterministic harness outcomes over 20 designed scenarios with an independent scenario oracle; local regression tests include oracle independence and a broken-chain negative control.
- Not measured: a live external agent, production customer workload, HTTP or PostgreSQL throughput, user adoption, regulatory outcomes, or comparative performance against other products.
- The report real-agent evaluation was blocked because no Anthropic API key was configured. The benchmark is not evidence of an OpenAI or Anthropic partnership.
- Scenario design and verifier implementation were by the same project engineer. The report calls for an independent red-team dataset and at least 100 scenarios for stronger precision.
- The distinct Rust long-ledger timing benchmark was prepared, but no timing workflow has produced a published result yet. Do not quote performance figures until a run artifact is available with hardware, toolchain, sizes and commit SHA.

Full report and harness: docs/reports/aigov-independent-benchmark-2026-11-19.md, benchmarks/agent-verification/independent_benchmark.py, and python/tests/test_independent_benchmark.py.

## Public wording

Use: “On a 20-scenario synthetic benchmark, the evidence-verification condition achieved 0.90 accuracy; the dataset is small, the real-agent run was not performed, and two false accepts show that chain integrity does not establish external truth.”

Do not generalize the result to production safety, all agents, all evidence quality, or regulatory compliance.
