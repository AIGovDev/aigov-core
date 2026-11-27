# Long-ledger verification benchmark

## Scope
Add an opt-in benchmark that measures the production Rust file-backed ledger
hash-chain verifier on deterministic synthetic JSONL ledgers.

## Changes
- Add an ignored Rust integration benchmark for 1,000, 10,000, and 100,000
  records by default, with configurable sizes and iterations.
- Measure valid chains and detect hash alterations at the first, middle, and
  last record. Emit per-sample timings and machine-readable environment metadata.
- Add a manual GitHub Actions workflow that runs the benchmark and uploads its
  JSON result as an artifact.
- Document reproduction steps, data fingerprints, cache limits, and comparison
  boundaries alongside existing Python microbenchmarks.

## Evaluation gate
This benchmark does not change production verdicts, evidence ingestion, policy
evaluation, tenant isolation, or ledger write behavior. Timing workloads are
ignored during ordinary tests and are not used as a CI performance threshold.
The test validates that the current Rust verifier accepts a valid chain and
rejects a validly encoded record with a changed record hash.

## Human approval gate
This PR requires maintainer review and approval before merge. No approval is
claimed by this report.

## Verification
- `cargo test --locked`, including the valid/tampered ledger regression: passed
  in GitHub Actions on the implementation commit.
- Report, developer-experience, security, dependency, and portable runtime gates:
  passed on the implementation commit.
- The manual timing workflow has not been run; no timing baseline or performance
  comparison is claimed.
- No performance numbers or cross-product comparisons are claimed here.
