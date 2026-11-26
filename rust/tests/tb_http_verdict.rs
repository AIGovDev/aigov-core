//! Verdict path through the real router in production mode with a signed bundle.
//! Separate binary: process-wide startup state.
mod common;
use aigov_audit::{build_app_state, build_router};
use axum::body::Body;
use axum::http::Request;
use common::*;
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tower::ServiceExt;

const KEY: &str = "tb-key-admin";

/// Posts with the agent key by default; approvals are posted with the approver key.
async fn post(app: &axum::Router, ev: &Value) -> (u16, Value) {
    let key = if ev["event_type"] == "human_approved" { "tb-key-approver" } else { KEY };
    let req = Request::builder()
        .method("POST")
        .uri("/evidence")
        .header("Authorization", format!("Bearer {key}"))
        .header("content-type", "application/json")
        .body(Body::from(ev.to_string()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let s = resp.status().as_u16();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (s, serde_json::from_slice(&bytes).unwrap_or(json!({})))
}

async fn get(app: &axum::Router, uri: &str) -> (u16, Value) {
    let req = Request::builder()
        .method("GET")
        .uri(uri)
        .header("Authorization", format!("Bearer {KEY}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let s = resp.status().as_u16();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (s, serde_json::from_slice(&bytes).unwrap_or(json!({})))
}

fn discovery(run: &str) -> Value {
    json!({"event_id": format!("{run}-d"), "event_type": "ai_discovery_reported",
        "ts_utc": "2026-01-01T00:00:01Z", "actor": "t", "system": "t", "run_id": run,
        "payload": {"openai": false, "transformers": false, "model_artifacts": false}})
}

fn approval(run: &str, id: &str, approver: &str) -> Value {
    json!({"event_id": id, "event_type": "human_approved",
        "ts_utc": "2026-01-01T00:00:02Z", "actor": "t", "system": "t", "run_id": run,
        "payload": {"approver": approver, "decision": "approve"}})
}

#[tokio::test]
#[ignore = "requires AIGOV_TEST_PG_ADMIN_URL (PostgreSQL); run with --ignored"]
async fn signed_policy_governs_ingest_and_verdict_in_production() {
    let ledger = tempfile::tempdir().expect("ledger");
    let dir = tempfile::tempdir().expect("dir");
    let mut doc = base_policy();
    sign_v2(&mut doc, "ci", created_at(), Some(future()));
    let bundle = write_bundle(dir.path(), &doc);
    prod_env(ledger.path(), Some(&bundle));
    // The durable revision anchor needs PostgreSQL. Each run gets its own fresh database.
    let Some(url) = common::fresh_database_url().await else {
        panic!("requires AIGOV_TEST_PG_ADMIN_URL (run with --ignored against a PostgreSQL server)");
    };
    std::env::set_var("GOVAI_DATABASE_URL", url);
    std::env::set_var("GOVAI_AUTO_MIGRATE", "true");
    let app = build_router(
        build_app_state()
            .await
            .expect("prod start with signed bundle"),
    );

    let run = "tb-run-1";
    let (s, body) = post(&app, &discovery(run)).await;
    assert_eq!(s, 200, "allowed event must be admitted: {body}");

    // Approval by a non-allowlisted approver is refused by the signed policy.
    let (s, body) = post(&app, &approval(run, "tb-appr-1", "mallory")).await;
    assert!(
        s >= 400,
        "non-allowlisted approver must be refused, got {s}: {body}"
    );

    // Allowlisted approver is admitted.
    let (s, body) = post(&app, &approval(run, "tb-appr-2", "alice")).await;
    assert_eq!(s, 200, "allowlisted approver must be admitted: {body}");

    // Verdict path returns a verdict for the run.
    let (s, body) = get(&app, &format!("/compliance-summary?run_id={run}")).await;
    assert_eq!(s, 200, "verdict summary must be available: {body}");
    assert!(body.get("ok").is_some(), "summary must report ok: {body}");
}
