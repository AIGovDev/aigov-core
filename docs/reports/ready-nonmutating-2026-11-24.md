# Non-mutating readiness — 2026-11-24

## Scope

`/ready` wrote to the ledger on every request. It created the ledger directory if it was missing, and
wrote and deleted a probe file. This change makes readiness read-only. Writability is still proven once at
startup, where validation fails closed.

## Evidence

| Check | Result |
|-------|--------|
| Unit tests `ledger_storage::readiness_tests` | 5 passed |
| Demonstration: the old write probe fails on a read-only directory; the new check passes | observed |
| Container regression: ledger listing unchanged across repeated `/ready` requests | passed |
| Container tests on a clean no-cache image, PostgreSQL 18 | 16 of 16 passed |
| Rust `cargo test --locked` | 242 passed, 0 failed |

## Evaluation gate

Passes when the readiness regression tests pass, the container tests pass against a clean image on PostgreSQL 18,
and the Rust suite passes. All three hold on the change set in this PR.

## Human approval gate

Not approved for production by this report. Merging into `staging` is a separate decision.
