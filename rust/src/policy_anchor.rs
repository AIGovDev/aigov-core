//! Durable policy revision anchor in PostgreSQL, independent of the filesystem watermark.
//!
//! ## What this protects, and what it does not
//!
//! - The database row is the **authority** for the accepted revision of each policy. The filesystem record
//!   (`policy_watermark.json`) is a cache that can be rebuilt from it.
//! - It defends against an older filesystem record (for example, a restored ledger volume) and against deletion
//!   of the filesystem record. It rejects a bundle older than the anchor, and a different digest at the anchored
//!   revision.
//! - It does **not** protect against simultaneous rollback of both the database and the filesystem, and it does not
//!   protect against a privileged database administrator who can rewrite the row. Both are declared residual risks.
//!
//! ## Atomicity: there is no cross-store transaction
//!
//! PostgreSQL and the filesystem cannot be committed together. The protocol below is ordered so that every crash
//! point has a deterministic outcome:
//!
//! 1. Take the per-host filesystem lock (`flock`). Read the filesystem record, if any.
//! 2. Open a database transaction and take a transaction-scoped advisory lock keyed by the policy identifier. This
//!    serializes decisions across hosts. Read the anchor row.
//! 3. Decide (`decide`). Refusals end the transaction with nothing written.
//! 4. Write the filesystem record first (atomically, under the lock).
//! 5. Commit the database change.
//!
//! Crash outcomes:
//!
//! - Crash or failure before step 4: nothing changed.
//! - Failure of step 4 (filesystem write): the transaction is rolled back. **The anchor did not advance.**
//! - Crash between steps 4 and 5, or a failure of the commit: the filesystem record is **ahead** of the anchor. The next
//!   start rolls the anchor forward only if the bundle matches that filesystem record exactly (same revision, same
//!   digest). Any other bundle older than the filesystem record is refused.
//! - Anchor ahead of the filesystem record (restored older ledger volume, or a deleted record): the filesystem record is
//!   restored from the anchor on the next successful start.
//!
//! The anchor is advanced only after the filesystem write succeeds, so a failed activation cannot move it.
//!
//! ## Bootstrap and migration
//!
//! The table is created by migration `0003_policy_revision_anchor`. An existing deployment with a filesystem record but
//! no anchor row is refused until an operator inserts the row, after checking the digest. See the runbook. The service
//! never bootstraps the anchor from the filesystem on its own, because a tampered record would then become the anchor.

use crate::db::DbPool;
use crate::policy_watermark::{self, Watermark, WatermarkEntry};
use std::path::PathBuf;

/// A verified bundle whose revision must be anchored. Created during policy loading; committed at the end of startup.
#[derive(Debug, Clone)]
pub struct PendingAnchor {
    pub ledger_dir: PathBuf,
    pub policy_id: String,
    pub version_raw: String,
    pub digest_sha256: String,
}

#[derive(Debug, PartialEq, Eq)]
pub enum DbAction {
    None,
    Insert,
    Advance,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Plan {
    /// Filesystem entry to write, if it differs from the current record.
    pub fs_target: Option<(u64, String)>,
    pub db: DbAction,
}

/// The decision, separated from I/O so every recovery rule can be tested directly.
///
/// `anchor` and `fs` are `(revision, digest)` pairs. `ledger_has_data` says whether the ledger directory already holds
/// evidence, which decides what a missing filesystem record means when no anchor exists.
pub fn decide(
    anchor: Option<(u64, &str)>,
    fs: Option<(u64, &str)>,
    candidate: (u64, &str),
    ledger_has_data: bool,
) -> Result<Plan, String> {
    let (cr, cd) = candidate;
    match anchor {
        None => {
            if fs.is_some() {
                return Err(
                    "policy revision anchor is missing while the filesystem record exists; run the anchor bootstrap procedure before startup"
                        .to_string(),
                );
            }
            if ledger_has_data {
                return Err(
                    "policy revision anchor and filesystem record are both missing while the ledger holds data; refusing to assume a first start"
                        .to_string(),
                );
            }
            Ok(Plan {
                fs_target: Some((cr, cd.to_string())),
                db: DbAction::Insert,
            })
        }
        Some((ar, ad)) => {
            if let Some((fr, fd)) = fs {
                if fr == ar && fd != ad {
                    return Err(
                        "filesystem record conflicts with the anchor at the same revision".to_string(),
                    );
                }
                if fr > ar && cr < fr {
                    return Err(format!(
                        "filesystem record (revision {fr}) is ahead of the anchor ({ar}) and the bundle (revision {cr}) is older than it; refusing: possible database restore"
                    ));
                }
                if fr > ar && cr == fr && cd != fd {
                    return Err(format!(
                        "conflicting pending content at revision {cr}: the filesystem record has a different digest"
                    ));
                }
            }
            if cr < ar {
                return Err(format!(
                    "rollback refused: revision {cr} is older than the anchored revision {ar}"
                ));
            }
            if cr == ar {
                if cd != ad {
                    return Err(format!(
                        "same-revision content change refused: revision {cr} has a different digest than the anchor"
                    ));
                }
                // Idempotent. Restore the filesystem record if it is behind or missing.
                let wanted = (ar, ad.to_string());
                let fs_target = if fs.map(|(r, d)| (r, d.to_string())) == Some(wanted.clone()) {
                    None
                } else {
                    Some(wanted)
                };
                return Ok(Plan {
                    fs_target,
                    db: DbAction::None,
                });
            }
            // cr > ar: advance. A matching filesystem record ahead of the anchor is rolled forward here.
            Ok(Plan {
                fs_target: Some((cr, cd.to_string())),
                db: DbAction::Advance,
            })
        }
    }
}

fn is_hex_digest(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn db_err(e: sqlx::Error) -> String {
    let text = e.to_string();
    if text.contains("does not exist") {
        return "policy revision anchor table is missing; apply migrations (0003_policy_revision_anchor) before startup"
            .to_string();
    }
    format!("policy revision anchor unavailable: {text}")
}

/// Reconcile the filesystem record with the database anchor, and commit the revision. Fail closed on any error.
pub async fn reconcile_and_commit(pool: &DbPool, p: &PendingAnchor) -> Result<(), String> {
    if !is_hex_digest(&p.digest_sha256) {
        return Err("policy revision anchor: digest is not a lowercase SHA-256 hex string".to_string());
    }
    let candidate_rev = policy_watermark::parse_version(&p.version_raw)?;

    // Step 1: per-host lock over the filesystem record. The lock is a blocking `flock`, so it is taken on the
    // blocking pool: a blocked worker thread could otherwise stop the task that holds the lock from finishing.
    let dir = p.ledger_dir.clone();
    let _fs_lock = tokio::task::spawn_blocking(move || policy_watermark::FsLock::acquire(&dir))
        .await
        .map_err(|e| format!("policy watermark lock task failed: {e}"))??;
    let fs_wm: Option<Watermark> = policy_watermark::read_optional(&p.ledger_dir)?;
    let fs_entry: Option<(u64, String)> = fs_wm
        .as_ref()
        .and_then(|w| w.policies.get(&p.policy_id))
        .map(|e| (e.version, e.digest_sha256.clone()));
    let ledger_has_data = policy_watermark::ledger_has_data(&p.ledger_dir);

    // Step 2: database transaction, serialized per policy identifier.
    let mut tx = pool.begin().await.map_err(db_err)?;
    sqlx::query("select pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(&p.policy_id)
        .execute(&mut *tx)
        .await
        .map_err(db_err)?;
    let row: Option<(i64, String)> = sqlx::query_as(
        "select revision, digest_sha256 from policy_revision_anchor where policy_id = $1",
    )
    .bind(&p.policy_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(db_err)?;
    let anchor: Option<(u64, String)> = match row {
        Some((rev, dg)) => {
            let rev = u64::try_from(rev)
                .map_err(|_| "policy revision anchor holds a negative revision".to_string())?;
            Some((rev, dg))
        }
        None => None,
    };

    // Step 3: decide. Any refusal returns here, and the transaction is dropped without committing.
    let plan = decide(
        anchor.as_ref().map(|(r, d)| (*r, d.as_str())),
        fs_entry.as_ref().map(|(r, d)| (*r, d.as_str())),
        (candidate_rev, &p.digest_sha256),
        ledger_has_data,
    )?;

    // Step 4: filesystem first. A failure here rolls the transaction back, so the anchor does not move.
    if let Some((rev, dg)) = plan.fs_target.clone() {
        let mut wm = fs_wm.unwrap_or_else(Watermark::empty);
        wm.policies.insert(
            p.policy_id.clone(),
            WatermarkEntry {
                version: rev,
                digest_sha256: dg,
            },
        );
        policy_watermark::write_record(&p.ledger_dir, &wm)?;
    }

    // Step 5: database commit. A failure here leaves the filesystem record ahead; the next start rolls it forward.
    match plan.db {
        DbAction::None => {}
        DbAction::Insert => {
            sqlx::query(
                "insert into policy_revision_anchor (policy_id, revision, digest_sha256) values ($1, $2, $3)",
            )
            .bind(&p.policy_id)
            .bind(candidate_rev as i64)
            .bind(&p.digest_sha256)
            .execute(&mut *tx)
            .await
            .map_err(db_err)?;
        }
        DbAction::Advance => {
            sqlx::query(
                "update policy_revision_anchor set revision = $2, digest_sha256 = $3, updated_at = now() where policy_id = $1",
            )
            .bind(&p.policy_id)
            .bind(candidate_rev as i64)
            .bind(&p.digest_sha256)
            .execute(&mut *tx)
            .await
            .map_err(db_err)?;
        }
    }
    tx.commit().await.map_err(db_err)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    fn d(
        anchor: Option<(u64, &str)>,
        fs: Option<(u64, &str)>,
        cand: (u64, &str),
        data: bool,
    ) -> Result<Plan, String> {
        decide(anchor, fs, cand, data)
    }

    #[test]
    fn first_start_inserts_the_anchor() {
        assert_eq!(
            d(None, None, (1, A), false).unwrap(),
            Plan { fs_target: Some((1, A.into())), db: DbAction::Insert }
        );
    }

    #[test]
    fn missing_anchor_with_a_filesystem_record_is_refused_until_bootstrap() {
        let err = d(None, Some((2, A)), (2, A), true).unwrap_err();
        assert!(err.contains("bootstrap"), "{err}");
    }

    #[test]
    fn missing_anchor_and_record_with_ledger_data_is_refused() {
        let err = d(None, None, (1, A), true).unwrap_err();
        assert!(err.contains("refusing to assume a first start"), "{err}");
    }

    #[test]
    fn revision_1_to_2_advances_and_2_to_1_is_refused() {
        assert_eq!(
            d(Some((1, A)), Some((1, A)), (2, B), false).unwrap(),
            Plan { fs_target: Some((2, B.into())), db: DbAction::Advance }
        );
        let err = d(Some((2, B)), Some((2, B)), (1, A), false).unwrap_err();
        assert!(err.contains("rollback refused"), "{err}");
    }

    #[test]
    fn same_revision_same_digest_is_idempotent() {
        assert_eq!(
            d(Some((2, A)), Some((2, A)), (2, A), false).unwrap(),
            Plan { fs_target: None, db: DbAction::None }
        );
    }

    #[test]
    fn same_revision_different_digest_is_refused() {
        let err = d(Some((2, A)), Some((2, A)), (2, B), false).unwrap_err();
        assert!(err.contains("same-revision content change refused"), "{err}");
    }

    #[test]
    fn filesystem_record_behind_the_anchor_is_restored_from_it() {
        // Restored older ledger volume: the record is at 1, the anchor is at 2, the bundle is 2.
        assert_eq!(
            d(Some((2, B)), Some((1, A)), (2, B), false).unwrap(),
            Plan { fs_target: Some((2, B.into())), db: DbAction::None }
        );
    }

    #[test]
    fn deleted_filesystem_record_is_restored_from_the_anchor() {
        assert_eq!(
            d(Some((2, B)), None, (2, B), true).unwrap(),
            Plan { fs_target: Some((2, B.into())), db: DbAction::None }
        );
    }

    #[test]
    fn older_bundle_cannot_be_activated_against_a_restored_older_record() {
        // Anchor at 3, a restored record at 1, and a signed bundle at 2: refused against the anchor.
        let err = d(Some((3, B)), Some((1, A)), (2, A), false).unwrap_err();
        assert!(err.contains("rollback refused"), "{err}");
    }

    #[test]
    fn filesystem_ahead_of_anchor_rolls_forward_only_for_the_matching_bundle() {
        // Crash after a filesystem write at revision 3, before the anchor commit.
        assert_eq!(
            d(Some((2, A)), Some((3, B)), (3, B), false).unwrap(),
            Plan { fs_target: Some((3, B.into())), db: DbAction::Advance }
        );
    }

    #[test]
    fn filesystem_ahead_of_anchor_refuses_an_older_bundle() {
        let err = d(Some((2, A)), Some((3, B)), (2, A), false).unwrap_err();
        assert!(err.contains("possible database restore"), "{err}");
    }

    #[test]
    fn filesystem_ahead_with_a_different_digest_at_the_same_revision_is_refused() {
        let err = d(Some((2, A)), Some((3, B)), (3, A), false).unwrap_err();
        assert!(err.contains("conflicting pending content"), "{err}");
    }

    #[test]
    fn filesystem_record_conflicting_with_the_anchor_at_the_same_revision_is_refused() {
        let err = d(Some((2, A)), Some((2, B)), (2, A), false).unwrap_err();
        assert!(err.contains("conflicts with the anchor"), "{err}");
    }

    #[test]
    fn key_rotation_keeps_the_same_digest_and_is_idempotent() {
        // Re-signing the same content with a new key leaves the document digest unchanged.
        assert_eq!(
            d(Some((2, A)), Some((2, A)), (2, A), false).unwrap(),
            Plan { fs_target: None, db: DbAction::None }
        );
    }

    #[test]
    fn digest_must_be_lowercase_hex() {
        assert!(is_hex_digest(A));
        assert!(!is_hex_digest(&A.to_uppercase().replace('A', "A")));
        assert!(!is_hex_digest("abc"));
        assert!(!is_hex_digest(&"g".repeat(64)));
    }
}
