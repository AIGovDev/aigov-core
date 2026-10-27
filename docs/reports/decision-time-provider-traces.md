# Decision-time provider traces implementation

## Summary

This change adds provider-neutral evidence for model invocations and decision reasoning, with full, redacted, and digest-only capture profiles. It extends the API contract, OpenAPI schema, Rust and Python helpers, and reconstructible-agent demo while keeping governance replay deterministic and offline.

## Files changed

| Area | Change |
|------|--------|
| Rust runtime | Validates invocation, reasoning, and trace-link events against prior ledger events. |
| API and documentation | Defines the evidence schema and decision-time trace contract. |
| Python SDK | Adds reference helpers and tests for decision traces. |
| Reconstructible demo | Demonstrates trace capture and review. |

## Evaluation gate

Status: pending CI.

Evidence:
- Rust compilation and tests, including downstream locked consumption.
- Python tests and SDK checks.
- Compliance and supply-chain checks.

## Human approval gate

Status: pending maintainer review.
