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
