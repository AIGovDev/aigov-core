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
