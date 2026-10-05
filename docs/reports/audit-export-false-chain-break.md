# Audit Export False Chain Break Fix

## Summary

This change fixes false `chain_break` failures in run-scoped audit exports.

A run-scoped export contains a filtered and sorted subset of records from the shared ledger. Previously, exported records retained their physical ledger `prev_hash` values even when records from other runs were omitted from the export or timestamps caused the exported subset to be reordered.

Replay validation checks adjacency within the exported subset. This mismatch could therefore report `chain_break` for valid, untampered exports.

The fix rewrites `prev_hash` for exported records after sorting so that each record points to the preceding record in the exported subset. The original `record_hash` values remain unchanged.

## Evaluation gate

The change is covered by regression testing for:

- foreign-run records physically interleaved between records of the exported run;
- non-monotonic timestamps;
- successful replay of an untampered export;
- continued detection of genuine `record_hash` tampering.

Validation:

    cargo test --locked --lib audit_export
    cargo test --locked --lib

The full Rust library test suite passes with 158/158 tests.

## Human approval gate

This change modifies audit-export chain representation and therefore requires maintainer review before merge.

Human review should confirm that:

- exported subset continuity is the intended replay contract;
- `record_hash` remains the ledger-computed value;
- only exported `prev_hash` linkage is normalized;
- genuine record tampering remains detectable.

## Risk assessment

The primary risk is changing the interpretation of `prev_hash` inside a run-scoped export from physical-ledger adjacency to exported-subset adjacency.

This is intentional because replay validation operates only on records actually present in the export.

The first exported record retains its original physical `prev_hash` as an informational anchor. Existing replay behavior already permits a run-scoped export to begin mid-ledger.

No policy evaluation, evidence admission, tenant isolation, or ledger write behavior is changed.

## Rollback plan

Rollback consists of reverting the audit-export chain normalization change and its regression tests.

This would restore the previous behavior where exported records retain their physical ledger `prev_hash` values, including the known false `chain_break` behavior for interleaved or reordered run-scoped exports.
