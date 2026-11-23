//! PostgreSQL-backed tests for operator-issued API keys: authentication, revocation, team scoping.
//!
//! Opt-in: set `AIGOV_TEST_PG_AUTH=1`. When set, the test FAILS if the database is missing or unsafe,
//! and never skips silently. When unset, the test returns early and reports that it did not run.
//! The database name must contain `test`. Never point this at production.
use aigov_audit::{build_app_state, build_router, db, tenant_api_keys};
use axum::body::Body;
use axum::http::Request;
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tower::ServiceExt;
use uuid::Uuid;

fn explicitly_enabled() -> bool {
    std::env::var("AIGOV_TEST_PG_AUTH").map(|v| v.trim() == "1").unwrap_or(false)
}

fn require_safe_test_database() -> String {
    let url = std::env::var("GOVAI_DATABASE_URL")
        .or_else(|_| std::env::var("DATABASE_URL"))
        .unwrap_or_default();
    assert!(
        !url.trim().is_empty(),
        "AIGOV_TEST_PG_AUTH=1 but no GOVAI_DATABASE_URL/DATABASE_URL is set (fail closed)"
    );
    let no_query = url.split('?').next().unwrap_or_default();
    let db_name = no_query.rsplit('/').next().unwrap_or_default();
    assert!(
        db_name.contains("test") || db_name == "aigov_integration",
        "refusing destructive-capable test against database {db_name:?}: name must contain 'test'"
    );
    assert!(
        no_query.contains("@localhost") || no_query.contains("@127.0.0.1") || no_query.contains("@[::1]"),
        "refusing test against a non-local database host"
    );
    url
}

async fn body_json(resp: axum::response::Response) -> Value {
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap_or(json!({}))
}

async fn get_with(app: &axum::Router, uri: &str, key: &str) -> (u16, Value) {
    let req = Request::builder()
        .method("GET")
        .uri(uri)
        .header("Authorization", format!("Bearer {key}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let s = resp.status().as_u16();
    (s, body_json(resp).await)
}

async fn post_with(app: &axum::Router, key: &str, body: &Value) -> (u16, Value) {
    let req = Request::builder()
        .method("POST")
        .uri("/evidence")
        .header("Authorization", format!("Bearer {key}"))
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let s = resp.status().as_u16();
    (s, body_json(resp).await)
}

#[tokio::test]
async fn issued_key_auth_revocation_and_team_scope() {
    if !explicitly_enabled() {
        eprintln!("NOT RUN: set AIGOV_TEST_PG_AUTH=1 with a disposable test database to run this test");
        return;
    }
    let url = require_safe_test_database();

    std::env::set_var("GOVAI_DATABASE_URL", &url);
    std::env::set_var("GOVAI_AUTO_MIGRATE", "true");
    std::env::set_var("AIGOV_ENVIRONMENT", "dev");
    std::env::set_var("AIGOV_POLICY_DIR", env!("CARGO_MANIFEST_DIR"));
    std::env::set_var("GOVAI_API_USAGE_STORE", "memory");
    std::env::remove_var("GOVAI_API_KEYS");
    std::env::remove_var("GOVAI_API_KEYS_JSON");
    let ledger = tempfile::tempdir().expect("tempdir");
    std::env::set_var("GOVAI_LEDGER_DIR", ledger.path());

    let pool = db::init_pool_from_env().await.expect("pool");
    let app = build_router(build_app_state().await.expect("app state"));

    let team_a = Uuid::new_v4();
    let team_b = Uuid::new_v4();
    let actor = Uuid::new_v4();
    let tenant_a = format!("pg-tenant-a-{}", Uuid::new_v4().simple());
    let tenant_b = format!("pg-tenant-b-{}", Uuid::new_v4().simple());

    let (row_a, raw_a) = tenant_api_keys::issue_api_key(&pool, team_a, &tenant_a, actor, "test-a")
        .await
        .expect("issue A");
    let (_row_b, raw_b) = tenant_api_keys::issue_api_key(&pool, team_b, &tenant_b, actor, "test-b")
        .await
        .expect("issue B");

    // Positive control: an active issued key authenticates (404 run_not_found, not 401).
    let run = format!("pg-run-{}", Uuid::new_v4().simple());
    let (s, body) = get_with(&app, &format!("/bundle?run_id={run}"), &raw_a).await;
    assert_eq!(s, 404, "active issued key must authenticate: {body}");
    assert_eq!(body.get("error").and_then(Value::as_str), Some("run_not_found"));

    // Ingest under tenant A; tenant B's issued key must not see it.
    let ev = json!({"event_id": format!("{run}-e1"), "event_type": "ai_discovery_reported",
        "ts_utc": "2026-01-01T00:00:01Z", "actor": "t", "system": "t", "run_id": run,
        "payload": {"openai": false, "transformers": false, "model_artifacts": false}});
    let (s, body) = post_with(&app, &raw_a, &ev).await;
    assert_eq!(s, 200, "tenant A ingest failed: {body}");
    let (s, body) = get_with(&app, &format!("/bundle?run_id={run}"), &raw_a).await;
    assert_eq!(s, 200, "tenant A reads own run: {body}");
    let (s, body) = get_with(&app, &format!("/bundle?run_id={run}"), &raw_b).await;
    assert_eq!(s, 404, "tenant B must not see tenant A's run: {body}");

    // Team scoping: team B cannot revoke team A's key.
    let revoked_by_wrong_team = tenant_api_keys::revoke_api_key(&pool, team_b, row_a.id)
        .await
        .expect("revoke call");
    assert!(!revoked_by_wrong_team, "another team must not revoke this key");
    let (s, _) = get_with(&app, &format!("/bundle?run_id={run}"), &raw_a).await;
    assert_eq!(s, 200, "key must still work after a rejected cross-team revoke");

    // Revocation by the owning team takes effect immediately.
    let revoked = tenant_api_keys::revoke_api_key(&pool, team_a, row_a.id).await.expect("revoke");
    assert!(revoked, "owner team must revoke its own key");
    let (s, body) = get_with(&app, &format!("/bundle?run_id={run}"), &raw_a).await;
    assert_eq!(s, 401, "revoked key must be rejected: {body}");
    assert!(!body.to_string().contains(&raw_a), "401 body must not echo the key");

    // Revoking twice is a no-op, not an error.
    let again = tenant_api_keys::revoke_api_key(&pool, team_a, row_a.id).await.expect("revoke again");
    assert!(!again);

    // Other tenant's key is unaffected.
    let (s, _) = get_with(&app, &format!("/bundle?run_id={run}"), &raw_b).await;
    assert_eq!(s, 404, "tenant B key still authenticates after tenant A revocation");

    // Issuance rejects tenant ids that could collide in the ledger file namespace.
    let bad = tenant_api_keys::issue_api_key(&pool, team_a, "team.a", actor, "bad").await;
    assert!(bad.is_err(), "issuance must reject tenant ids outside [A-Za-z0-9_-]");

    // Issuance refuses a tenant that differs from an existing one only by ASCII case
    // (the ledger file name would collide on case-insensitive file systems).
    let upper = tenant_a.to_ascii_uppercase();
    let case_clash = tenant_api_keys::issue_api_key(&pool, team_a, &upper, actor, "case").await;
    assert!(case_clash.is_err(), "case-variant of an existing tenant must be refused at issuance");
}
