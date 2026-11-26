//! An explicitly listed legacy tenant keeps reading and writing its pre-v2 ledger file.
use aigov_audit::{build_app_state, build_router};
use axum::body::Body;
use axum::http::Request;
use http_body_util::BodyExt;
use serde_json::json;
use tower::ServiceExt;

#[tokio::test]
async fn listed_legacy_tenant_uses_its_existing_ledger_file() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("audit_log__team_a.jsonl"), "").unwrap();
    std::env::set_var("GOVAI_LEDGER_DIR", dir.path());
    std::env::set_var("GOVAI_API_KEYS", "legacy-key-two");
    std::env::set_var("GOVAI_API_KEYS_JSON", r#"{"legacy-key-two":"team.a"}"#);
    std::env::set_var("AIGOV_LEDGER_LEGACY_TENANTS", "team.a");
    std::env::set_var("AIGOV_ENVIRONMENT", "dev");
    std::env::set_var("AIGOV_POLICY_DIR", env!("CARGO_MANIFEST_DIR"));
    std::env::set_var("GOVAI_API_USAGE_STORE", "memory");
    std::env::remove_var("GOVAI_DATABASE_URL");
    std::env::remove_var("DATABASE_URL");
    let app = build_router(build_app_state().await.expect("listed legacy tenant starts"));
    let ev = json!({"event_id": "legacy-ev-1", "event_type": "ai_discovery_reported",
        "ts_utc": "2026-01-01T00:00:01Z", "actor": "t", "system": "t", "run_id": "legacy-run",
        "payload": {"openai": false, "transformers": false, "model_artifacts": false}});
    let req = Request::builder().method("POST").uri("/evidence")
        .header("Authorization", "Bearer legacy-key-two")
        .header("content-type", "application/json")
        .body(Body::from(ev.to_string())).unwrap();
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), 200);
    let text = std::fs::read_to_string(dir.path().join("audit_log__team_a.jsonl")).unwrap();
    assert!(text.contains("legacy-ev-1"), "event must land in the explicitly listed legacy file");
    let req = Request::builder().uri("/bundle?run_id=legacy-run")
        .header("Authorization", "Bearer legacy-key-two").body(Body::empty()).unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 200);
    let _ = resp.into_body().collect().await.unwrap();
}
