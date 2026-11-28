# Multi-host ledger design (proposed, not implemented)

The current Rust audit store uses process mutexes, local flock sidecars, JSONL, state files and run indexes. PostgreSQL configuration does not relocate this ledger. Separate hosts can diverge even if they share the database. Helm must remain single replica with Recreate rollout until migration is validated.

## Required transaction boundary

Use one authoritative tenant-scoped database ledger. Serialize policy evaluation, approval consumption, event deduplication, hash-head advancement and authorization issuance under the same transaction. Enforce unique tenant/event identifiers and tenant/sequence identifiers. Never acknowledge before commit. Bind retries to the original canonical request digest; reject conflicting reuse. Reads must observe a committed snapshot. Do not dual-write as an authority mechanism.

## Migration and recovery

Quiesce writers, verify full legacy chain against a trusted head, import exact event bytes and hashes, compare counts and heads, and switch all readers and writers together. Reject writes when the database is unavailable. Test concurrent approvals, policy/key changes, lost commit acknowledgments, failover, partitions and cross-tenant access. A transactional ledger cannot alone guarantee exactly-once external side effects; retain executor reservation and reconciliation semantics.

## Release gates

Two independent Core processes with distinct local directories must observe the same committed ledger and reject replay. Test database restart, crash before and after commit, policy revision races, tenant isolation and export compatibility. No HA or multi-host claim until these gates pass. Existing executor recovery workflow is not evidence of multi-host Core consistency.
