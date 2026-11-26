# Owner acceptance package: release 0.4.0-rc.1

**Nothing in this document is approved.** Every decision below is open. Each entry gives the recommended option, the alternatives, the consequences, and the
criteria the owner must check before accepting. The owner records the decision in the "Owner record" line of each entry. Until then the status is
"open", and the release stays a candidate.

Related documents: `docs/decisions/issue-501-owner-decisions.md` (D1–D4 in full), `docs/release/pilot-readiness.md`, `docs/release/pilot-package.md`,
`docs/reports/pilot-readiness-closure-2026-11-26.md`, `docs/audit-handoff/known-limitations.md`.

---

## 1. Issue #501, D1: where the authoritative policy revision lives

- **Recommended.** Keep the PostgreSQL row as the only authority (`policy_revision_anchor`). The filesystem record is a cache.
- **Alternatives.** (a) An external signed or MAC'd store with its key in a KMS. (b) A replicated database with a synchronous standby. Option (b) protects the row against loss, not against an administrator.
- **Consequences.** The row is trusted by anyone with database write access (R-2). Option (a) moves that trust to a key holder; it adds a service, key custody, and a recovery path.
- **Acceptance criteria.** (1) The owner accepts R-2 in writing. (2) Named people control database write access to that table. (3) Backups follow D4.
- **Owner record:** _open_

## 2. Issue #501, D2: authenticating the filesystem record

- **Recommended.** Do not add a MAC. Keep the checksum as a corruption check, and state in writing that the database row is the only authority.
- **Alternatives.** (a) A MAC whose key lives outside the host (KMS or HSM). This is real protection and needs custody and rotation. (b) Remove the record as an input to any decision.
- **Consequences.** A MAC whose key is on the same host does not help: whoever can read the file can read the key. Option (a) adds a dependency that can fail at start.
- **Acceptance criteria.** The owner chooses one option. If (a): a named key custodian, rotation, and a recovery procedure are approved before the pilot.
- **Owner record:** _open_

## 3. Issue #501, D3: an empty-ledger first start in production

- **Recommended.** Keep the explicit bootstrap. Add a logged operator event for each bootstrap (operator identity, revision, digest). The logging change is not implemented; it needs approval.
- **Alternatives.** (a) Refuse every production first start and require an operator command. (b) Accept an empty-ledger first start silently (not recommended: it is the case the anchor exists to stop).
- **Consequences.** The logging change adds one small operations-log entry and a runbook line. Option (a) adds a step to each new deployment.
- **Acceptance criteria.** The owner names who may bootstrap, and accepts either the logging change or the stricter procedure in writing.
- **Owner record:** _open_

## 4. Issue #501, D4: backups, restores, and who may reset the record

- **Recommended.** Back up the database and the ledger volume from one snapshot. Record the head hashes off host. A reset of an anchor row or a restore of the database to an older point needs two named people and a written reason.
- **Alternatives.** Append-only anchor rows, so a reset is a new row and the history stays visible. This needs a migration and a change to the reset path.
- **Consequences.** A restore from the same older backup of both stores is the case no single control catches (R-2). The off-host hashes are how an investigation notices it.
- **Acceptance criteria.** (1) Two named people for each reset. (2) A backup job that captures both stores together. (3) One restore drill completed before the pilot starts, with the restored ledger verifying (`store_admin verify-history` and the chain check).
- **Owner record:** _open_

## 5. Event-role assignment, F-10

- **Recommended.** Keep the current rule: protected event types have one owning role each (`approval`, `approval_revoked`, `risk_reviewed` to the approver; `execution_receipt` to the executor). Every other event type is pipeline or agent evidence and only the agent role may post it. The policy still checks each gate: a `model_promoted` event is refused without a prior approval.
- **Alternatives.** (a) An explicit list of allowed types per role. More precise, and it must be maintained for each new event type. (b) A separate pipeline role for evaluation and model events, distinct from the agent role.
- **Consequences.** An agent key can record evaluation and model events that the policy then checks. An agent cannot approve, review, or post a receipt. Option (a) would refuse some SDK events until they are listed.
- **Acceptance criteria.** The owner confirms (1) the protected list; (2) that the agent may post `evaluation_reported` and `model_promoted`, which the policy gates; (3) that no other role gets pipeline events. The regression test `role_may_post` in `rust/src/principals.rs` asserts this rule.
- **Owner record:** _open_

## 6. Residual risk R-2: database authority over the policy anchor

- **Recommended.** Accept R-2 for the pilot in writing, with D1, D2, and D4 as the controls.
- **Alternatives.** Do not start a pilot until D1 option (a) is built.
- **Consequences.** A database administrator who changes the anchor and the record together can roll a revision back, and the process will not notice.
- **Acceptance criteria.** Written acceptance by the owner, naming the people with database write access.
- **Owner record:** _open_

## 7. Residual risk R-6: concurrent issuance during key and policy change

- **Recommended.** Accept R-6 in the tested configuration: one host, one ledger, one registry anchor, three processes, rotation and revocation, and a superseded revision (tests in `python/tests/test_issuance_cross_process.py` and `test_policy_revision_across_processes.py`). Outside it, the risk is not accepted: several hosts, a database restart during issuance, and a policy change during a rotation are not tested.
- **Alternatives.** Commission the untested cases before the pilot.
- **Consequences.** An authorization is refused after a key is retired and the approval is then consumed (a human must approve again). That is fail closed, and it is recorded.
- **Acceptance criteria.** The owner accepts the tested scope and the untested exclusions in writing.
- **Owner record:** _open_

## 8. Residual risk R-9: exactly-once external effects

- **Recommended.** The pilot's downstream system accepts the authorization id as an idempotency key. Where it cannot, the customer accepts the duplicate risk in writing.
- **Alternatives.** Restrict the pilot to downstream actions that are idempotent by nature.
- **Consequences.** AIGov does not claim exactly-once external effects. The store guarantees one execution per authorization.
- **Acceptance criteria.** The customer's engineering owner confirms the deduplication key, or signs the risk acceptance.
- **Owner record:** _open_

## 9. Residual risk R-11: version

- **Recommended.** `0.4.0-rc.1` (Python: `0.4.0rc1`). Pre-1.0 minor bump: the changes break integrations (receipts need an executor; staging and production need principals; the role rule changed). `0.3.0` is avoided because the tag `v0.3.0-core-replay-operations` already uses that number.
- **Alternatives.** `0.4.0` for a final release later; `0.2.2` (not recommended: understates the change).
- **Consequences.** The bump touches the files listed in `docs/release/release-artifacts.md`, including pinned tests and a CI snippet. Tagging is separate, and the existing tags stay.
- **Acceptance criteria.** The owner approves the version string. Tagging and publishing are separate decisions and are not made here.
- **Owner record:** _open_

## 10. Proposed version `0.4.0-rc.1`

Covered by item 9. Acceptance also requires the owner to confirm that this candidate is the one the pilot will run, and that the release notes
(`docs/release/release-artifacts.md`) describe the behaviour changes to integrators.

## 11. Supported pilot topology

- **Recommended.** One tenant, one ledger host, one Core process per tenant, production mode, principals configured, PostgreSQL 16 or 18 for the anchors and the executor store, executors as library code in the customer's workers.
- **Not supported.** Several Core processes on different hosts sharing a ledger directory. SQLite executor stores on more than one host. Dev mode in any deployment.
- **Consequences.** The measured single-process ceiling is about 37 to 49 evidence writes per second on the test workstation (see `docs/evidence/release-candidate/load/`). Pilot volume must stay under the measured ceiling of the chosen hardware, or the pilot needs a second tenant host, which is a new decision.
- **Acceptance criteria.** The owner confirms the topology, the expected write rate, and that the hardware will be measured with `scripts/core_load_test.py` before the pilot starts.
- **Owner record:** _open_

## 12. Remaining security and operational limitations

These are stated in full in `docs/audit-handoff/known-limitations.md`. The owner accepts, or asks for a fix, for each:

- Overload: requests above the in-flight limit are refused with 503 OVERLOADED and recorded nothing. A request admitted and then timed out (408) may still complete its append; the client must resolve it by event id (a duplicate is refused). See the load evidence.
- Container networking depends on the host (R-8). The hosted runner's result is the authority.
- No external audit has been performed. The handoff package in `docs/audit-handoff/` is prepared for one.
- Provenance and SBOMs are not signed. Artifact signing needs a procedure and a key, which are not created here (`docs/release/artifact-signing.md`).
- The root-level `aigov_py` shim changes import behaviour from the repository root (L-3).
- `chrono` is unmaintained (L-4). No known vulnerability.
- L-2: an oversized body is answered with a closed connection, not HTTP 413. The limit is enforced.
- **Owner record:** _open_

---

## Summary table

| # | Decision | Recommended | Owner record |
|---|---|---|---|
| 1 | #501 D1 | Keep the database row as the authority | _open_ |
| 2 | #501 D2 | No MAC; the row is the only authority | _open_ |
| 3 | #501 D3 | Explicit, logged bootstrap | _open_ |
| 4 | #501 D4 | Joint snapshot; off-host hashes; two people for a reset | _open_ |
| 5 | F-10 event roles | Protected types to one role; other types to the agent | _open_ |
| 6 | R-2 | Accept with D1, D2, D4 | _open_ |
| 7 | R-6 | Accept in the tested scope | _open_ |
| 8 | R-9 | Accept, or confirm a deduplication key | _open_ |
| 9 | R-11 / version | 0.4.0-rc.1 | _open_ |
| 10 | Version proposal | 0.4.0-rc.1 | _open_ |
| 11 | Pilot topology | One tenant, one host, production mode | _open_ |
| 12 | Limitations | Accept as listed, or request a fix | _open_ |

Issue #501 stays open until the owner records D1 to D4 and closes it in review.
