# Trust boundaries

| Boundary | Trusted side | Untrusted side | What protects the crossing |
|---|---|---|---|
| Client to Core (HTTP) | Core | Any caller | API key or OIDC token; principal resolved from the key; role decides which event types may be posted (`role_may_post`); body, time, and concurrency limits (`request_limits.rs`) |
| Principal to event type | Core's role table | The caller's claim about the event type | The role check runs before any append. Protected types (approvals, revocations, risk reviews, receipts) have one owning role each |
| Operator to policy | The trust file (owner-only) | The policy bundle contents | Ed25519 signature verification at start; anti-rollback by the database anchor; the signed bundle is the only policy source in staging and production |
| Process to database | The anchor row | A process holding a stale view of its revision | Each evidence write checks the anchored revision (`check_in_force_not_superseded`), and refuses if the anchor is ahead, missing, or unreadable |
| Process to registry | The registry log and its anchor | A file that can be edited | The log is hash-chained, verified against the trust file's roots, and the head is anchored in PostgreSQL. Compare-and-swap on the anchor |
| Core to executor | The authorization signature | The executor's inputs | The executor verifies the signature against the registry key for its key id, the audience, the tool, the argument digest, and the expiry (`python/aigov_py/trusted/executor.py`). The signing seed is never sent to the executor |
| Executor to downstream system | The downstream system | The executor | Not verified by AIGov. The downstream system must accept the authorization id as an idempotency key, or the duplicate risk is accepted (R-9) |
| Downstream to reconciliation | The reconciler's signature in the registry | The evidence content | `verify_reconciliation` checks the signature; an applied evidence is refused a second time |
| Host to ledger | Filesystem permissions and the host operator | Anyone with write access to the volume | Hash chain detects edits that do not recompute the chain. Recomputing it needs no key, so the chain is not authentication (see R-2) |
| Database administrator | Not trusted by design | A privileged database user | Not protected against: a person who can change the anchor row and the record together can roll back the revision (R-2). Recorded as a residual, owner decision D1 |
