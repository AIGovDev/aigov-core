//! Core's reader against the PostgreSQL anchor (`key_registry_anchor`). Runs only when a disposable database is configured:
//!
//!   AIGOV_TEST_REGISTRY_PG_URL=postgresql://user:pass@host:5432/disposable cargo test --test registry_anchor_pg
//!
//! The log is the cross-language fixture written by the Python writer. Each run uses a fresh registry id, and removes its
//! anchor row afterwards.

use aigov_audit::key_registry::{load_verified, AnchorSource, AnchorState, TrustConfig};
use std::path::{Path, PathBuf};

const FIXTURE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/key_registry_v2");

fn url() -> Option<String> {
    std::env::var("AIGOV_TEST_REGISTRY_PG_URL").ok().map(|v| v.trim().to_string()).filter(|v| !v.is_empty())
}

/// A copy of the fixture with a fresh registry id in its trust file, in its own directory.
fn fixture_copy(dir: &Path, registry_id: &str) -> (PathBuf, TrustConfig, AnchorState) {
    let events = std::fs::read_to_string(Path::new(FIXTURE).join("registry.json.events.jsonl")).unwrap();
    let snap = dir.join("registry.json");
    std::fs::write(aigov_audit::key_registry::events_path_for(&snap), events).unwrap();
    let mut trust: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(Path::new(FIXTURE).join("trust.json")).unwrap()).unwrap();
    trust["registry_id"] = serde_json::Value::String(registry_id.into());
    let trust = TrustConfig::from_value(&trust).unwrap();
    let anchor: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(Path::new(FIXTURE).join("anchor.json")).unwrap()).unwrap();
    let state = AnchorState { seq: anchor["seq"].as_u64().unwrap(), head_hash: anchor["head_hash"].as_str().unwrap().into() };
    (snap, trust, state)
}

async fn set_row(pool: &sqlx::PgPool, registry_id: &str, state: Option<&AnchorState>) {
    sqlx::query("CREATE TABLE IF NOT EXISTS key_registry_anchor (registry_id TEXT PRIMARY KEY, seq BIGINT NOT NULL CHECK (seq >= 0), head_hash TEXT NOT NULL, updated_at TIMESTAMPTZ NOT NULL DEFAULT now())")
        .execute(pool).await.unwrap();
    sqlx::query("DELETE FROM key_registry_anchor WHERE registry_id = $1").bind(registry_id).execute(pool).await.unwrap();
    if let Some(s) = state {
        sqlx::query("INSERT INTO key_registry_anchor (registry_id, seq, head_hash) VALUES ($1, $2, $3)")
            .bind(registry_id).bind(s.seq as i64).bind(&s.head_hash).execute(pool).await.unwrap();
    }
}

#[tokio::test]
async fn core_reads_the_fixture_against_the_postgres_anchor() {
    let Some(url) = url() else {
        eprintln!("skipped: set AIGOV_TEST_REGISTRY_PG_URL to run the registry anchor PostgreSQL test");
        return;
    };
    let id = format!("pgrust-{}", uuid_like());
    let dir = tempfile::tempdir().unwrap();
    let (snap, trust, state) = fixture_copy(dir.path(), &id);
    let anchor = AnchorSource::postgres(&url, &id).unwrap();
    let pool = sqlx::PgPool::connect(&url).await.unwrap();

    // No row: refused.
    set_row(&pool, &id, None).await;
    assert!(load_verified(&snap, &trust, &anchor).await.unwrap_err().starts_with("anchor_missing"));

    // The anchored state: accepted.
    set_row(&pool, &id, Some(&state)).await;
    let view = load_verified(&snap, &trust, &anchor).await.expect("the log matches the anchor");
    assert_eq!(view.version, state.seq);

    // The anchor is one event further on than the log: the log was rolled back. Refused.
    set_row(&pool, &id, Some(&AnchorState { seq: state.seq + 1, head_hash: state.head_hash.clone() })).await;
    assert!(load_verified(&snap, &trust, &anchor).await.unwrap_err().starts_with("anchor_log_behind"));

    // The anchor records a different head at the same length: substitution. Refused.
    set_row(&pool, &id, Some(&AnchorState { seq: state.seq, head_hash: "0".repeat(64) })).await;
    assert!(load_verified(&snap, &trust, &anchor).await.unwrap_err().starts_with("anchor_head_mismatch"));

    sqlx::query("DELETE FROM key_registry_anchor WHERE registry_id = $1").bind(&id).execute(&pool).await.unwrap();
}

#[tokio::test]
async fn an_unreachable_postgres_anchor_fails_closed() {
    let dir = tempfile::tempdir().unwrap();
    let (snap, trust, _state) = fixture_copy(dir.path(), "unreachable");
    let anchor = AnchorSource::postgres("postgresql://127.0.0.1:1/none?connect_timeout=1", "unreachable").unwrap();
    let err = load_verified(&snap, &trust, &anchor).await.unwrap_err();
    assert!(err.starts_with("anchor_unavailable"), "{err}");
}

fn uuid_like() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    format!("{:x}", SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos())
}
