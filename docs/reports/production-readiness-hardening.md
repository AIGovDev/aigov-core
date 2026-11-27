# Production readiness hardening

Baseline: `be28b0dd231f980d105a93d76ee2db2f1f7cbd6a`.

## Existing capabilities and gaps

- `benchmarks/ledger-verification/README.md`: actual Rust file verifier benchmark; timing results not yet published.
- `scripts/distributed_benchmark.py`: concurrent executor-store benchmark using stand-in Core and side effects; not production HTTP throughput.
- `deployments/kubernetes/README.md`: single replica with RWO volume; not HA.
- `docs/trust/cross-organization-attestation.md`: documented trust exchange model; implementation coverage requires further audit.
- `docs/evidence/release-candidate/reproducibility.md`: previous clean builds differ; no independent clean-builder confirmation.

## Acceptance criteria

- [ ] Retain measured raw Rust benchmark results and environment metadata.
- [ ] Measure real HTTP and PostgreSQL workloads with correctness assertions.
- [ ] Audit multi-host storage and authorization invariants before changing deployment topology.
- [ ] Verify replay, concurrent policy changes, crash recovery and partition behavior.
- [ ] Verify independent clean builds with exact artifact digests.
- [ ] Audit offline verification and cross-organization trust before extending interfaces.
- [ ] Formalize security invariants and test model assumptions.
- [ ] Validate Kubernetes deployment; do not enable unsupported multi-replica operation.

## Evaluation gate

Baseline documentation only. No new runtime behavior or measured results are claimed. Implementation and exact-head CI remain pending.

## Human approval gate

Draft only. Maintainer approval required before merge. External audit and paid services are outside this PR.


## Measured benchmark evidence (2026-11-27)

CI PR head 61b8e355f8666cde2b96f5e98b1f2186d5e0a659; checked-out merge revision reported by both artifacts: be9b34514a6c81663250c63f4e9a2d9ca271244d.

- [Rust raw measurements](https://github.com/AIGovDev/aigov-core/actions/runs/46001276269/artifacts/15197913252): Linux x86_64, four available CPUs, rustc 1.100.0, release, five samples per scenario. Valid ledger median/p95 in ms: 1,000 records 1.476377/1.566333; 10,000 records 14.155981/14.760070; 100,000 records 161.971001/172.002926. All twelve valid/corrupted scenarios returned the expected result.
- [HTTP raw measurements](https://github.com/AIGovDev/aigov-core/actions/runs/46001276088/artifacts/15199205619): 100 events, four workers, 593.0236 events/s, median 5.7956935 ms, p95 7.045532 ms, p99 10.065706 ms. All event IDs retrieved; offline file ledger verification reported 100 records and success.

These are single-run synthetic measurements, not production capacity or comparative claims. The HTTP service uses a file ledger with PostgreSQL configured separately; these figures do not establish transactional PostgreSQL ledger throughput or multi-host scaling. Artifact retention is finite; permanent raw evidence and repeated measurements remain pending.
