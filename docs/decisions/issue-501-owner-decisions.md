# Issue #501: owner decisions D1–D4, with recommendations

Status: **recommendations for owner review. None of these is decided.** Issue #501 stays open until the owner records each decision.
This document is not in `docs/reports/`, so it does not change the one-report rule of the compliance gate.

Each item lists the question as #501 states it, what the code does today, the recommendation, the alternatives, the security implications,
and the operational cost.

## D1 — Where the authoritative policy revision lives

**Question.** A shared PostgreSQL table with row locking, or an external signed or MAC'd store?

**Today.** The PostgreSQL row `policy_revision_anchor` is the authority for the accepted revision of each policy. Activation takes a
transaction-scoped advisory lock per policy. The filesystem record is a cache that is restored from the row. The two-volume test (`make two-volume-rollback`)
shows a refusal from the row on two real filesystems.

**Recommendation: keep the PostgreSQL row as the authority.** Staging and production already require the database for it.

**Alternatives.**
- An external signed or MAC'd store (a KMS-backed record, or a signed log that is checked on each start). This would detect a lowered row
  as well as a lowered file, but needs key custody and a second service.
- A replicated database with a synchronous standby. This protects the row against loss, not against a privileged administrator.

**Security implications.** The row is trusted by anyone with database write access, which is the residual threat R-2. A signed store moves that trust to
the key holder, which is a smaller set of people, if custody is well run. A signed store does not help if the key holder and the database
administrator are the same person.

**Operational cost.** Recommendation: none beyond the current runbook. Alternative: one more service, key rotation, a recovery procedure for the key,
and an audit of who can sign.

## D2 — Authenticating the filesystem record

**Question.** Whether to authenticate the record, and who holds the key, so that lowering is detectable.

**Today.** The record carries a SHA-256 checksum over its own content. The checksum detects accidental edits. It does not authenticate anything: whoever can
write the file can recompute it. Lowering is detected through the database row, not through the record. Without a database URL the staging and
production starts are refused, so this gap is closed in those environments.

**Recommendation: do not add a MAC.** Keep the checksum as a corruption check, and state in writing that the database row is the only authority. A MAC
with a key on the same host gives the attacker the key whenever they have the file, so it adds code and a key file without adding protection.

**Alternatives.**
- A MAC whose key is held outside the host (in a KMS or an HSM). This is real protection, and it is the option that answers D2 as written. It needs key custody
  for every Core host, rotation, and a recovery procedure.
- Remove the file as an input to decisions. The record would then be only a cache, and a cache is always restored from the row. This is the simplest
  change, and it removes the question.

**Security implications.** With the row as the authority, a lowered file cannot lower the accepted revision, because the start is refused or restored
from the row. A lowered row is not detected by the file. The file-level MAC would not change that.

**Operational cost.** Recommendation: none. Alternative (external MAC): a key service, custody, rotation, and a second failure mode if the key service is
unavailable at start.

## D3 — Empty-ledger first start in production

**Question.** Is an empty-ledger first start acceptable in production, or must it be an explicit, logged operator action?

**Today.** A missing record with an existing row is restored from the row. A missing record with no row and existing ledger data is refused, and needs an explicit
bootstrap. A missing record with no row and an empty ledger is a first start. The first-start window admits nothing until an explicit bootstrap
(`first_start_window_admits_nothing_until_an_explicit_bootstrap`). The bootstrap is not logged as a separate audit event.

**Recommendation: keep the explicit bootstrap, and log it.** Record each bootstrap as an operator event with the operator's identity, the revision, and the digest,
in the ledger's operations log. The first start of a new production deployment is then a recorded act, not an absence of a record.

**Alternatives.**
- Refuse any production first start, and require a bootstrap command run by an operator. This is stricter, and adds a step to every new deployment.
- Accept an empty-ledger first start silently. This is the weakest option, and it is the one the current code avoids by refusing a record without a row.

**Security implications.** The risk is an attacker who empties a volume and presents an older bundle at a first start. The row check defeats this when the row exists.
The bootstrap log makes a deliberate first start visible after the fact.

**Operational cost.** Recommendation: a small change to write one operations-log entry per bootstrap, and a runbook line. Alternative: an operator step per deployment.

## D4 — Backup, restore, and who may reset the record

**Question.** Backup and restore rules for the record alongside the ledger volume, and who may reset it.

**Today.** Backup and restore rules are in `docs/operations/policy-anchor-runbook.md` and `docs/operations/distributed-execution-runbook.md` section 8. The two-volume
test covers a restored older volume: it is brought forward from the row. "Who may reset" is an organisational rule that no code enforces.

**Recommendation.**
- Back up the database and the ledger volumes at the same time, from the same snapshot, and record the head hashes off host.
- A reset of the anchor row, or a restore of the database to an older point, needs two named people and a written reason. The reset is an incident, not a routine step.
- The root key and the trust file are under change control, and are not restored from the database backup.

**Alternatives.**
- Make the anchor row append-only at the database level, so a reset is a new row and not an overwrite. This keeps history, and makes a rollback of the row visible.
- Take no reset path at all. Recovery from a lost row would then need a new deployment.

**Security implications.** A restore of the database and the volume from the same older backup is the residual threat that no single control catches. The off-host head hashes
are how an investigation notices it.

**Operational cost.** Recommendation: a second person for each reset, and a backup job that captures both stores together. Alternative (append-only rows):
a migration and a small change to the reset path.

## Summary for the owner

| # | Recommendation | What the owner must decide | Blocks the pilot? |
|---|---|---|---|
| D1 | Keep the PostgreSQL row as the authority | Accept the row as the authority, with R-2 recorded | No, if R-2 is accepted in writing |
| D2 | No MAC on the file; state that the row is the only authority | Accept, or choose an external MAC | No, if accepted in writing |
| D3 | Keep the explicit bootstrap and log it | Accept the logging change | No; the pilot should run the logged bootstrap |
| D4 | Joint backups, off-host head hashes, two people for a reset | Accept the procedure and name the two people | Yes for the reset procedure: a pilot needs named people before it starts |

None of these recommendations is implemented as an owner decision. D3's logging change and D4's append-only option are code or procedure changes that need
approval before they are made.
