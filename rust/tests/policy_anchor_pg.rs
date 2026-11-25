//! PostgreSQL-backed policy revision anchor: regression tests against a real database.
//!
//! These tests are ignored by default. They run against a throwaway PostgreSQL server named by
//! `AIGOV_TEST_PG_ADMIN_URL`, each in its own fresh database. Run them with:
//!   AIGOV_TEST_PG_ADMIN_URL=postgres://... cargo test --locked --test policy_anchor_pg -- --ignored
//! Synthetic data only.

mod common;

use aigov_audit::db;
use aigov_audit::policy_anchor::{reconcile_and_commit, PendingAnchor};
use aigov_audit::policy_watermark::{self, Watermark, WatermarkEntry};
use sqlx::postgres::PgPoolOptions;
use std::path::{Path, PathBuf};

const D1: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const D2: &str = "2222222222222222222222222222222222222222222222222222222222222222";
const D3: &str = "3333333333333333333333333333333333333333333333333333333333333333";
const POLICY: &str = "anchor-policy";

fn pending(ledger: &Path, version: &str, digest: &str) -> PendingAnchor {
    PendingAnchor {
        ledger_dir: ledger.to_path_buf(),
        policy_id: POLICY.to_string(),
        version_raw: version.to_string(),
        digest_sha256: digest.to_string(),
    }
}

async fn fresh_pool() -> sqlx::PgPool {
    fresh_pool_with_url().await.0
}

async fn fresh_pool_with_url() -> (sqlx::PgPool, String) {
    let url = common::fresh_database_url()
        .await
        .expect("AIGOV_TEST_PG_ADMIN_URL must be set for ignored PostgreSQL tests");
    let pool = PgPoolOptions::new()
        .max_connections(8)
        .connect(&url)
        .await
        .expect("connect");
    db::run_sqlx_migrations(&pool).await.expect("migrations");
    (pool, url)
}

fn ledger(tmp: &tempfile::TempDir) -> PathBuf {
    let dir = tmp.path().join("ledger");
    std::fs::create_dir(&dir).unwrap();
    dir
}

async fn anchor_revision(pool: &sqlx::PgPool) -> Option<(i64, String)> {
    sqlx::query_as(
        "select revision, digest_sha256 from policy_revision_anchor where policy_id = $1",
    )
    .bind(POLICY)
    .fetch_optional(pool)
    .await
    .unwrap()
}

/// A valid, authentic record at `version` (its own integrity tag), written through the public API.
fn authentic_record_bytes(version: &str, digest: &str) -> Vec<u8> {
    let scratch = tempfile::tempdir().unwrap();
    policy_watermark::enforce(scratch.path(), POLICY, version, digest).unwrap();
    std::fs::read(policy_watermark::watermark_path(scratch.path())).unwrap()
}

fn fs_version(ledger: &Path) -> Option<u64> {
    policy_watermark::read_optional(ledger)
        .unwrap()
        .and_then(|w: Watermark| w.policies.get(POLICY).map(|e: &WatermarkEntry| e.version))
}

#[tokio::test]
#[ignore = "requires AIGOV_TEST_PG_ADMIN_URL (PostgreSQL)"]
async fn first_start_advances_and_rollback_is_refused_across_restart() {
    let (pool, url) = fresh_pool_with_url().await;
    let tmp = tempfile::tempdir().unwrap();
    let l = ledger(&tmp);
    reconcile_and_commit(&pool, &pending(&l, "1", D1))
        .await
        .unwrap();
    reconcile_and_commit(&pool, &pending(&l, "2", D2))
        .await
        .unwrap();
    // Restart: drop every connection, then reconnect to the same database and ledger.
    pool.close().await;
    let restarted = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .unwrap();
    let err = reconcile_and_commit(&restarted, &pending(&l, "1", D1))
        .await
        .unwrap_err();
    assert!(err.contains("rollback refused"), "{err}");
    assert_eq!(anchor_revision(&restarted).await.unwrap().0, 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires AIGOV_TEST_PG_ADMIN_URL (PostgreSQL)"]
async fn concurrent_activations_never_regress_the_anchor() {
    let pool = fresh_pool().await;
    let tmp = tempfile::tempdir().unwrap();
    let l = ledger(&tmp);
    reconcile_and_commit(&pool, &pending(&l, "1", D1))
        .await
        .unwrap();
    let mut handles = Vec::new();
    for i in 0..16u64 {
        let pool = pool.clone();
        let l = l.clone();
        handles.push(tokio::spawn(async move {
            let v = (i % 8) + 2; // revisions 2..=9, several copies of each
            let digest = format!("{:0>64}", v);
            let _ = reconcile_and_commit(&pool, &pending(&l, &v.to_string(), &digest)).await;
        }));
    }
    for h in handles {
        h.await.unwrap();
    }
    let (rev, _) = anchor_revision(&pool).await.unwrap();
    assert_eq!(
        rev, 9,
        "the highest committed revision must win; a lower one must never move the anchor back"
    );
    assert_eq!(
        fs_version(&l),
        Some(9),
        "the filesystem record must follow the anchor"
    );
}

#[tokio::test]
#[ignore = "requires AIGOV_TEST_PG_ADMIN_URL (PostgreSQL)"]
async fn failed_filesystem_write_does_not_advance_the_anchor() {
    let pool = fresh_pool().await;
    let tmp = tempfile::tempdir().unwrap();
    let l = ledger(&tmp);
    reconcile_and_commit(&pool, &pending(&l, "1", D1))
        .await
        .unwrap();
    // Make the record path a directory: the next filesystem write cannot succeed.
    std::fs::remove_file(policy_watermark::watermark_path(&l)).unwrap();
    std::fs::create_dir(policy_watermark::watermark_path(&l)).unwrap();
    assert!(reconcile_and_commit(&pool, &pending(&l, "2", D2))
        .await
        .is_err());
    assert_eq!(
        anchor_revision(&pool).await.unwrap().0,
        1,
        "a failed activation must not advance the anchor"
    );
}

#[tokio::test]
#[ignore = "requires AIGOV_TEST_PG_ADMIN_URL (PostgreSQL)"]
async fn malicious_older_record_with_a_recomputed_tag_is_refused() {
    let pool = fresh_pool().await;
    let tmp = tempfile::tempdir().unwrap();
    let l = ledger(&tmp);
    reconcile_and_commit(&pool, &pending(&l, "3", D3))
        .await
        .unwrap();
    // An attacker replaces the record with an older, authentic one (its own valid tag).
    std::fs::write(
        policy_watermark::watermark_path(&l),
        authentic_record_bytes("1", D1),
    )
    .unwrap();
    let err = reconcile_and_commit(&pool, &pending(&l, "2", D2))
        .await
        .unwrap_err();
    assert!(
        err.contains("rollback refused") || err.contains("ahead"),
        "{err}"
    );
    assert_eq!(
        anchor_revision(&pool).await.unwrap().0,
        3,
        "the anchor is authoritative"
    );
}

#[tokio::test]
#[ignore = "requires AIGOV_TEST_PG_ADMIN_URL (PostgreSQL)"]
async fn restored_older_ledger_snapshot_is_brought_forward_from_the_anchor() {
    let pool = fresh_pool().await;
    let tmp = tempfile::tempdir().unwrap();
    let l = ledger(&tmp);
    reconcile_and_commit(&pool, &pending(&l, "2", D2))
        .await
        .unwrap();
    std::fs::write(
        policy_watermark::watermark_path(&l),
        authentic_record_bytes("1", D1),
    )
    .unwrap();
    reconcile_and_commit(&pool, &pending(&l, "2", D2))
        .await
        .unwrap();
    assert_eq!(
        fs_version(&l),
        Some(2),
        "the filesystem record is restored from the anchor"
    );
}

#[tokio::test]
#[ignore = "requires AIGOV_TEST_PG_ADMIN_URL (PostgreSQL)"]
async fn deleted_filesystem_record_does_not_reset_the_accepted_revision() {
    let pool = fresh_pool().await;
    let tmp = tempfile::tempdir().unwrap();
    let l = ledger(&tmp);
    reconcile_and_commit(&pool, &pending(&l, "2", D2))
        .await
        .unwrap();
    std::fs::remove_file(policy_watermark::watermark_path(&l)).unwrap();
    assert!(
        reconcile_and_commit(&pool, &pending(&l, "1", D1))
            .await
            .is_err(),
        "deletion must not reset the revision"
    );
    reconcile_and_commit(&pool, &pending(&l, "2", D2))
        .await
        .unwrap();
    assert_eq!(fs_version(&l), Some(2));
}

#[tokio::test]
#[ignore = "requires AIGOV_TEST_PG_ADMIN_URL (PostgreSQL)"]
async fn missing_anchor_with_a_filesystem_record_requires_bootstrap() {
    let pool = fresh_pool().await;
    let tmp = tempfile::tempdir().unwrap();
    let l = ledger(&tmp);
    std::fs::write(
        policy_watermark::watermark_path(&l),
        authentic_record_bytes("2", D2),
    )
    .unwrap();
    let err = reconcile_and_commit(&pool, &pending(&l, "2", D2))
        .await
        .unwrap_err();
    assert!(err.contains("bootstrap"), "{err}");
    // Operator bootstrap: insert the row with the digest checked against the record.
    sqlx::query("insert into policy_revision_anchor (policy_id, revision, digest_sha256) values ($1, 2, $2)")
        .bind(POLICY)
        .bind(D2)
        .execute(&pool)
        .await
        .unwrap();
    reconcile_and_commit(&pool, &pending(&l, "2", D2))
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires AIGOV_TEST_PG_ADMIN_URL (PostgreSQL)"]
async fn unreachable_database_fails_closed_and_writes_nothing() {
    let tmp = tempfile::tempdir().unwrap();
    let l = ledger(&tmp);
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(std::time::Duration::from_secs(2))
        .connect_lazy("postgres://nobody:nothing@127.0.0.1:1/none")
        .unwrap();
    assert!(reconcile_and_commit(&pool, &pending(&l, "1", D1))
        .await
        .is_err());
    assert!(
        !policy_watermark::watermark_path(&l).exists(),
        "no filesystem record may be written without the anchor"
    );
}

#[tokio::test]
#[ignore = "requires AIGOV_TEST_PG_ADMIN_URL (PostgreSQL)"]
async fn filesystem_ahead_after_a_failed_commit_rolls_forward_only_for_the_matching_bundle() {
    let pool = fresh_pool().await;
    let tmp = tempfile::tempdir().unwrap();
    let l = ledger(&tmp);
    reconcile_and_commit(&pool, &pending(&l, "2", D2))
        .await
        .unwrap();
    // Crash after the filesystem write at revision 3, before the anchor commit.
    std::fs::write(
        policy_watermark::watermark_path(&l),
        authentic_record_bytes("3", D3),
    )
    .unwrap();
    assert!(
        reconcile_and_commit(&pool, &pending(&l, "2", D2))
            .await
            .is_err(),
        "an older bundle is refused"
    );
    reconcile_and_commit(&pool, &pending(&l, "3", D3))
        .await
        .unwrap();
    assert_eq!(anchor_revision(&pool).await.unwrap().0, 3);
}

#[tokio::test]
#[ignore = "requires AIGOV_TEST_PG_ADMIN_URL (PostgreSQL)"]
async fn key_rotation_keeps_the_same_digest_and_is_idempotent_on_the_database() {
    let pool = fresh_pool().await;
    let tmp = tempfile::tempdir().unwrap();
    let l = ledger(&tmp);
    reconcile_and_commit(&pool, &pending(&l, "2", D2))
        .await
        .unwrap();
    reconcile_and_commit(&pool, &pending(&l, "2", D2))
        .await
        .unwrap();
    assert_eq!(anchor_revision(&pool).await, Some((2, D2.to_string())));
}

#[tokio::test]
#[ignore = "requires AIGOV_TEST_PG_ADMIN_URL (PostgreSQL)"]
async fn migration_creates_the_anchor_table_and_its_constraints() {
    let pool = fresh_pool().await;
    let n: i64 = sqlx::query_scalar(
        "select count(*) from information_schema.columns where table_name = 'policy_revision_anchor'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(n, 4, "policy_id, revision, digest_sha256, updated_at");
    let bad = sqlx::query("insert into policy_revision_anchor (policy_id, revision, digest_sha256) values ('x', 1, 'NOT-HEX')")
        .execute(&pool)
        .await;
    assert!(
        bad.is_err(),
        "the digest constraint must reject a non-hex digest"
    );
}

#[tokio::test]
#[ignore = "requires AIGOV_TEST_PG_ADMIN_URL (PostgreSQL)"]
async fn missing_table_reports_that_migrations_are_needed() {
    let url = common::fresh_database_url()
        .await
        .expect("AIGOV_TEST_PG_ADMIN_URL");
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await
        .unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let l = ledger(&tmp);
    let err = reconcile_and_commit(&pool, &pending(&l, "1", D1))
        .await
        .unwrap_err();
    assert!(err.contains("apply migrations"), "{err}");
}

// ---- Activation protocol: multiple policies, first-start failures, explicit transaction boundaries ----

fn pending_for(ledger: &Path, policy: &str, version: &str, digest: &str) -> PendingAnchor {
    PendingAnchor {
        ledger_dir: ledger.to_path_buf(),
        policy_id: policy.to_string(),
        version_raw: version.to_string(),
        digest_sha256: digest.to_string(),
    }
}

async fn anchor_row(pool: &sqlx::PgPool, policy: &str) -> Option<(i64, String)> {
    sqlx::query_as(
        "select revision, digest_sha256 from policy_revision_anchor where policy_id = $1",
    )
    .bind(policy)
    .fetch_optional(pool)
    .await
    .unwrap()
}

fn record_policies(ledger: &Path) -> Option<Vec<String>> {
    policy_watermark::read_optional(ledger)
        .unwrap()
        .map(|w| w.policies.keys().cloned().collect())
}

#[tokio::test]
#[ignore = "requires AIGOV_TEST_PG_ADMIN_URL (PostgreSQL)"]
async fn multi_policy_activation_with_one_refusal_writes_nothing() {
    use aigov_audit::policy_anchor::reconcile_all_and_commit;
    let pool = fresh_pool().await;
    let tmp = tempfile::tempdir().unwrap();
    let l = ledger(&tmp);
    // Policy B is anchored at revision 3; policy A is new.
    sqlx::query("insert into policy_revision_anchor (policy_id, revision, digest_sha256) values ('policy-b', 3, $1)")
        .bind(D3)
        .execute(&pool)
        .await
        .unwrap();
    let batch = vec![
        pending_for(&l, "policy-a", "2", D2),
        pending_for(&l, "policy-b", "1", D1), // rollback: refused
    ];
    let err = reconcile_all_and_commit(&pool, &batch).await.unwrap_err();
    assert!(err.contains("rollback refused"), "{err}");
    assert!(
        anchor_row(&pool, "policy-a").await.is_none(),
        "policy A must not be advanced by a refused activation"
    );
    assert_eq!(anchor_row(&pool, "policy-b").await.unwrap().0, 3);
    assert!(
        record_policies(&l).is_none(),
        "no filesystem record may be written by a refused activation"
    );
}

#[tokio::test]
#[ignore = "requires AIGOV_TEST_PG_ADMIN_URL (PostgreSQL)"]
async fn multi_policy_activation_commits_every_policy_together() {
    use aigov_audit::policy_anchor::reconcile_all_and_commit;
    let pool = fresh_pool().await;
    let tmp = tempfile::tempdir().unwrap();
    let l = ledger(&tmp);
    let batch = vec![
        pending_for(&l, "policy-a", "2", D2),
        pending_for(&l, "policy-b", "1", D1),
    ];
    reconcile_all_and_commit(&pool, &batch).await.unwrap();
    assert_eq!(anchor_row(&pool, "policy-a").await.unwrap().0, 2);
    assert_eq!(anchor_row(&pool, "policy-b").await.unwrap().0, 1);
    let mut names = record_policies(&l).unwrap();
    names.sort();
    assert_eq!(names, vec!["policy-a".to_string(), "policy-b".to_string()]);
}

#[tokio::test]
#[ignore = "requires AIGOV_TEST_PG_ADMIN_URL (PostgreSQL)"]
async fn first_start_insert_failure_writes_no_filesystem_record() {
    // The identifier exceeds the column constraint, so the database insert fails inside the transaction.
    // The filesystem write comes after the database writes, so no record may be left behind.
    let pool = fresh_pool().await;
    let tmp = tempfile::tempdir().unwrap();
    let l = ledger(&tmp);
    let long = "x".repeat(300);
    assert!(
        reconcile_and_commit(&pool, &pending_for(&l, &long, "1", D1))
            .await
            .is_err()
    );
    assert!(
        record_policies(&l).is_none(),
        "a failed first start must not leave a filesystem record"
    );
    // A retry with a valid identifier is a clean first start.
    reconcile_and_commit(&pool, &pending(&l, "1", D1))
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires AIGOV_TEST_PG_ADMIN_URL (PostgreSQL)"]
async fn filesystem_failure_rolls_back_the_first_start_insert() {
    let pool = fresh_pool().await;
    let tmp = tempfile::tempdir().unwrap();
    let l = ledger(&tmp);
    // The record path is a directory, so the filesystem write cannot succeed.
    std::fs::create_dir(policy_watermark::watermark_path(&l)).unwrap();
    assert!(reconcile_and_commit(&pool, &pending(&l, "1", D1))
        .await
        .is_err());
    assert!(
        anchor_row(&pool, POLICY).await.is_none(),
        "the insert must roll back when the filesystem write fails"
    );
}

#[tokio::test]
#[ignore = "requires AIGOV_TEST_PG_ADMIN_URL (PostgreSQL)"]
async fn commit_failure_after_the_filesystem_write_needs_bootstrap_and_is_deterministic() {
    // The documented first-start window: the record is written, then the commit fails.
    let pool = fresh_pool().await;
    sqlx::query(
        "create function fail_commit() returns trigger language plpgsql as $$ begin raise exception 'injected commit failure'; end $$",
    )
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "create constraint trigger anchor_fail after insert on policy_revision_anchor deferrable initially deferred for each row when (new.policy_id = 'trig-policy') execute function fail_commit()",
    )
    .execute(&pool)
    .await
    .unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let l = ledger(&tmp);
    let p = pending_for(&l, "trig-policy", "2", D2);
    let err = reconcile_and_commit(&pool, &p).await.unwrap_err();
    assert!(err.contains("injected commit failure"), "{err}");
    assert_eq!(
        record_policies(&l),
        Some(vec!["trig-policy".to_string()]),
        "the record was written before the commit"
    );
    assert!(
        anchor_row(&pool, "trig-policy").await.is_none(),
        "the commit failed, so no anchor row exists"
    );
    // The next start refuses deterministically and asks for the bootstrap procedure. It never guesses.
    let err = reconcile_and_commit(&pool, &p).await.unwrap_err();
    assert!(err.contains("bootstrap"), "{err}");
}

// Accepted staging window: a commit failure on a first start leaves the record ahead of the (absent) anchor.
// Recovery must be explicit. Nothing automatic may activate an older policy or a different digest.
#[tokio::test]
#[ignore = "requires AIGOV_TEST_PG_ADMIN_URL (PostgreSQL)"]
async fn first_start_window_admits_nothing_until_an_explicit_bootstrap() {
    let pool = fresh_pool().await;
    sqlx::query(
        "create function fail_window_commit() returns trigger language plpgsql as $$ begin raise exception 'injected commit failure'; end $$",
    )
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "create constraint trigger window_fail after insert on policy_revision_anchor deferrable initially deferred for each row when (new.policy_id = 'window-policy') execute function fail_window_commit()",
    )
    .execute(&pool)
    .await
    .unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let l = ledger(&tmp);
    let current = pending_for(&l, "window-policy", "2", D2);
    assert!(reconcile_and_commit(&pool, &current).await.is_err());
    assert!(anchor_row(&pool, "window-policy").await.is_none());
    assert_eq!(record_policies(&l), Some(vec!["window-policy".to_string()]));

    // Startup fails closed for the same bundle, for an older revision, and for a different digest at the same revision.
    let same = reconcile_and_commit(&pool, &current).await.unwrap_err();
    assert!(same.contains("bootstrap"), "{same}");
    let older = reconcile_and_commit(&pool, &pending_for(&l, "window-policy", "1", D1))
        .await
        .unwrap_err();
    assert!(
        older.contains("bootstrap"),
        "older bundle must not activate: {older}"
    );
    let other_digest = reconcile_and_commit(&pool, &pending_for(&l, "window-policy", "2", D1))
        .await
        .unwrap_err();
    assert!(
        other_digest.contains("bootstrap"),
        "different digest must not activate: {other_digest}"
    );
    assert!(
        anchor_row(&pool, "window-policy").await.is_none(),
        "no automatic anchor row may appear"
    );

    // Explicit operator bootstrap with the verified (revision, digest), on a healthy database (the injected
    // failure is removed). The same bundle is then accepted; an older bundle is refused as a rollback.
    sqlx::query("drop trigger window_fail on policy_revision_anchor")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("insert into policy_revision_anchor (policy_id, revision, digest_sha256) values ('window-policy', 2, $1)")
        .bind(D2)
        .execute(&pool)
        .await
        .unwrap();
    reconcile_and_commit(&pool, &current).await.unwrap();
    let rollback = reconcile_and_commit(&pool, &pending_for(&l, "window-policy", "1", D1))
        .await
        .unwrap_err();
    assert!(rollback.contains("rollback refused"), "{rollback}");
}
