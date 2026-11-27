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
