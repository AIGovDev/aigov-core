use aigov_audit::{db, transactional_ledger::append};
use sha2::{Digest, Sha256};
use sqlx::{postgres::PgPoolOptions, Row};
use uuid::Uuid;

#[tokio::test]
#[ignore = "requires disposable PostgreSQL; run explicitly in CI"]
async fn concurrent_writers_and_replays() {
    let url = std::env::var("GOVAI_DATABASE_URL").expect("disposable PostgreSQL URL");
    let pool = PgPoolOptions::new().max_connections(12).connect(&url).await.unwrap();
    db::run_sqlx_migrations(&pool).await.unwrap();
    let tenant = Uuid::new_v4().to_string();
    let mut tasks = tokio::task::JoinSet::new();
    for i in 0..64 {
        let pool = pool.clone();
        let tenant = tenant.clone();
        tasks.spawn(async move {
            let id = format!("event-{}", i % 32);
            let event = serde_json::json!({"event_id": id}).to_string();
            append(&pool, &tenant, &id, &event).await.unwrap()
        });
    }
    let mut fresh = 0;
    while let Some(result) = tasks.join_next().await {
        if !result.unwrap().replay {
            fresh += 1;
        }
    }
    assert_eq!(fresh, 32);
    let rows = sqlx::query("SELECT seq, event_json, prev_hash, record_hash FROM core_ledger_records WHERE tenant_id=$1 ORDER BY seq")
        .bind(&tenant).fetch_all(&pool).await.unwrap();
    assert_eq!(rows.len(), 32);
    let mut previous = "GENESIS".to_owned();
    for (i, row) in rows.iter().enumerate() {
        assert_eq!(row.get::<i64, _>("seq"), i as i64 + 1);
        assert_eq!(row.get::<String, _>("prev_hash"), previous);
        let event: String = row.get("event_json");
        previous = hex::encode(Sha256::digest(format!("{previous}\n{event}").as_bytes()));
        assert_eq!(row.get::<String, _>("record_hash"), previous);
    }
    let head = sqlx::query("SELECT seq, head_hash FROM core_ledger_heads WHERE tenant_id=$1")
        .bind(&tenant).fetch_one(&pool).await.unwrap();
    assert_eq!(head.get::<i64, _>("seq"), 32);
    assert_eq!(head.get::<String, _>("head_hash"), previous);
    assert!(append(&pool, &tenant, "event-0", r#"{"event_id":"event-0","changed":true}"#).await.is_err());
    let other = Uuid::new_v4().to_string();
    let result = append(&pool, &other, "event-0", r#"{"event_id":"event-0"}"#).await.unwrap();
    assert_eq!(result.sequence, 1);
    assert!(!result.replay);
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL; run explicitly in CI"]
async fn approval_reservation_is_atomic_and_single_use() {
    use aigov_audit::transactional_ledger::{append_in_transaction, reserve_validated_approval};
    let url = std::env::var("GOVAI_DATABASE_URL").expect("disposable PostgreSQL URL");
    let pool = PgPoolOptions::new().max_connections(8).connect(&url).await.unwrap();
    db::run_sqlx_migrations(&pool).await.unwrap();
    let tenant = Uuid::new_v4().to_string();
    append(&pool, &tenant, "approval", r#"{"event_id":"approval"}"#).await.unwrap();
    let mut tx = pool.begin().await.unwrap();
    append_in_transaction(&mut tx, &tenant, "aborted", r#"{"event_id":"aborted"}"#).await.unwrap();
    reserve_validated_approval(&mut tx, &tenant, "approval", "aborted").await.unwrap();
    tx.rollback().await.unwrap();
    let mut tasks = tokio::task::JoinSet::new();
    for i in 0..8 {
        let pool = pool.clone();
        let tenant = tenant.clone();
        tasks.spawn(async move {
            let id = format!("decision-{i}");
            let event = serde_json::json!({"event_id": id}).to_string();
            let mut tx = pool.begin().await.unwrap();
            append_in_transaction(&mut tx, &tenant, &id, &event).await.unwrap();
            match reserve_validated_approval(&mut tx, &tenant, "approval", &id).await {
                Ok(()) => { tx.commit().await.unwrap(); true }
                Err(error) => {
                    assert_eq!(error.as_database_error().and_then(|e| e.code()).as_deref(), Some("23505"));
                    tx.rollback().await.unwrap();
                    false
                }
            }
        });
    }
    let mut winners = 0;
    while let Some(result) = tasks.join_next().await {
        if result.unwrap() { winners += 1; }
    }
    assert_eq!(winners, 1);
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM core_ledger_records WHERE tenant_id=$1")
        .bind(&tenant).fetch_one(&pool).await.unwrap();
    assert_eq!(count, 2);
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM core_approval_consumptions WHERE tenant_id=$1")
        .bind(&tenant).fetch_one(&pool).await.unwrap();
    assert_eq!(count, 1);
    let other = Uuid::new_v4().to_string();
    let mut tx = pool.begin().await.unwrap();
    append_in_transaction(&mut tx, &other, "decision", r#"{"event_id":"decision"}"#).await.unwrap();
    assert!(reserve_validated_approval(&mut tx, &other, "approval", "decision").await.is_err());
    tx.rollback().await.unwrap();
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL; run explicitly in CI"]
async fn run_snapshot_serializes_independent_connections() {
    use aigov_audit::transactional_ledger::{append_in_transaction, lock_tenant_and_read_run};
    let url = std::env::var("GOVAI_DATABASE_URL").unwrap();
    let first = PgPoolOptions::new().max_connections(2).connect(&url).await.unwrap();
    let second = PgPoolOptions::new().max_connections(2).connect(&url).await.unwrap();
    db::run_sqlx_migrations(&first).await.unwrap();
    let tenant = Uuid::new_v4().to_string();
    append(&first, &tenant, "a", r#"{"event_id":"a","run_id":"one"}"#).await.unwrap();
    append(&first, &tenant, "b", r#"{"event_id":"b","run_id":"two"}"#).await.unwrap();
    let mut tx = first.begin().await.unwrap();
    assert_eq!(lock_tenant_and_read_run(&mut tx, &tenant, "one").await.unwrap().len(), 1);
    let mut competing = second.begin().await.unwrap();
    sqlx::query("SET LOCAL lock_timeout = '200ms'").execute(&mut *competing).await.unwrap();
    let error = lock_tenant_and_read_run(&mut competing, &tenant, "one").await.unwrap_err();
    assert_eq!(error.as_database_error().and_then(|e| e.code()).as_deref(), Some("55P03"));
    competing.rollback().await.unwrap();
    append_in_transaction(&mut tx, &tenant, "c", r#"{"event_id":"c","run_id":"one"}"#).await.unwrap();
    tx.commit().await.unwrap();
    first.close().await;
    let mut recovered = second.begin().await.unwrap();
    let events = lock_tenant_and_read_run(&mut recovered, &tenant, "one").await.unwrap();
    assert_eq!(events, vec![r#"{"event_id":"a","run_id":"one"}"#.to_owned(), r#"{"event_id":"c","run_id":"one"}"#.to_owned()]);
    recovered.rollback().await.unwrap();
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL; run explicitly in CI"]
async fn terminated_backend_rolls_back_decision_and_approval() {
    use aigov_audit::transactional_ledger::{append_in_transaction, reserve_validated_approval};
    let url = std::env::var("GOVAI_DATABASE_URL").expect("disposable PostgreSQL URL");
    let pool = PgPoolOptions::new().max_connections(4).connect(&url).await.unwrap();
    db::run_sqlx_migrations(&pool).await.unwrap();
    let tenant = Uuid::new_v4().to_string();
    let anchor = append(&pool, &tenant, "approval", r#"{"event_id":"approval"}"#).await.unwrap();
    let mut tx = pool.begin().await.unwrap();
    let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()").fetch_one(&mut *tx).await.unwrap();
    append_in_transaction(&mut tx, &tenant, "decision", r#"{"event_id":"decision"}"#).await.unwrap();
    reserve_validated_approval(&mut tx, &tenant, "approval", "decision").await.unwrap();
    let terminated: bool = sqlx::query_scalar("SELECT pg_terminate_backend($1)").bind(pid).fetch_one(&pool).await.unwrap();
    assert!(terminated);
    assert!(tx.commit().await.is_err());
    let mut retry = pool.begin().await.unwrap();
    let result = append_in_transaction(&mut retry, &tenant, "decision", r#"{"event_id":"decision"}"#).await.unwrap();
    assert!(!result.replay);
    assert_eq!(result.sequence, anchor.sequence + 1);
    reserve_validated_approval(&mut retry, &tenant, "approval", "decision").await.unwrap();
    retry.commit().await.unwrap();
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM core_approval_consumptions WHERE tenant_id=$1").bind(&tenant).fetch_one(&pool).await.unwrap();
    assert_eq!(count, 1);
    let replay = append(&pool, &tenant, "decision", r#"{"event_id":"decision"}"#).await.unwrap();
    assert!(replay.replay);
    assert_eq!(replay.record_hash, result.record_hash);
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL; run explicitly in CI"]
async fn trusted_checkpoint_detects_database_history_tampering() {
    use aigov_audit::transactional_ledger::verify_checkpoint;
    let url = std::env::var("GOVAI_DATABASE_URL").expect("disposable PostgreSQL URL");
    let writer = PgPoolOptions::new().max_connections(2).connect(&url).await.unwrap();
    let reader = PgPoolOptions::new().max_connections(2).connect(&url).await.unwrap();
    db::run_sqlx_migrations(&writer).await.unwrap();
    let tenant = Uuid::new_v4().to_string();
    append(&writer, &tenant, "a", r#"{"event_id":"a"}"#).await.unwrap();
    let anchor = append(&writer, &tenant, "b", r#"{"event_id":"b"}"#).await.unwrap();
    verify_checkpoint(&reader, &tenant, anchor.sequence, &anchor.record_hash).await.unwrap();
    assert!(verify_checkpoint(&reader, &tenant, anchor.sequence, &"0".repeat(64)).await.is_err());
    sqlx::query("UPDATE core_ledger_records SET event_json=$2 WHERE tenant_id=$1 AND seq=1")
        .bind(&tenant).bind(r#"{"event_id":"a","tampered":true}"#).execute(&writer).await.unwrap();
    assert!(verify_checkpoint(&reader, &tenant, anchor.sequence, &anchor.record_hash).await.is_err());
}
