//! A consequential call must name a real, unrevoked, unused human approval before Core issues an execution
//! authorization for it. These tests go through the real router with registry-mode issuance enabled, under the
//! built-in dev policy. That policy has no approval gate for `consequential_tool_call`, so the check that refuses these
//! calls is Core's own, applied before anything is appended.
//!
//! The approval check applies in every issuance mode. These tests use the single-key mode, which needs no database; the
//! registry mode is covered by the unit tests and by the PostgreSQL-backed test in `registry_anchor_pg.rs`.
//!
//! One process-wide configuration (issuance mode is a process global), so all scenarios run from one test function.

use aigov_audit::{build_app_state, build_router};
use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use ed25519_dalek::SigningKey;
use http_body_util::BodyExt;
use serde_json::{json, Map, Value};
use std::path::Path;
use tower::ServiceExt;

const KID: &str = "exe-approval-test";
/// A throwaway 32-byte seed for the single-key issuance mode. Nothing in the repository depends on it.
const SEED_HEX: &str = "2929292929292929292929292929292929292929292929292929292929292929";

async fn post(app: &axum::Router, key: &str, body: &Value) -> (StatusCode, Value) {
    let req = Request::builder()
        .method("POST")
        .uri("/evidence")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::AUTHORIZATION, format!("Bearer {key}"))
        .body(Body::from(body.to_string()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (status, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
}

fn call(event_id: &str, approval_event_id: &str) -> Value {
    json!({
        "event_id": event_id,
        "event_type": "consequential_tool_call",
        "ts_utc": "2026-11-26T10:00:00Z",
        "actor": "agent",
        "system": "approval-test",
        "run_id": "run-approval-http",
        "payload": {
            "tool_name": "create_file",
            "tool_call_id": format!("call-{event_id}"),
            "approval_event_id": approval_event_id,
            "args_binding_hash": "a".repeat(64),
        },
    })
}

fn code_of(body: &Value) -> String {
    body.pointer("/error/code").and_then(Value::as_str).unwrap_or("").to_string()
}

fn message_of(body: &Value) -> String {
    body.pointer("/error/message").and_then(Value::as_str).unwrap_or("").to_string()
}

fn ledger_records(ledger: &Path) -> usize {
    std::fs::read_to_string(ledger.join("audit_log__t1.jsonl"))
        .map(|s| s.lines().filter(|l| !l.trim().is_empty()).count())
        .unwrap_or(0)
}

#[tokio::test]
async fn consequential_calls_without_a_real_approval_get_no_authorization() {
    let dir = tempfile::tempdir().unwrap();
    let ledger = dir.path().join("ledger");
    std::fs::create_dir_all(&ledger).unwrap();

    // Issuance on (single-key mode). The built-in dev policy is in force: no policy file.
    for k in ["AIGOV_POLICY_FILE", "AIGOV_POLICY_DIR", "AIGOV_KEY_REGISTRY_PATH", "GOVAI_KEY_REGISTRY_PATH", "AIGOV_ENVIRONMENT", "AIGOV_ENV", "AIGOV_LEDGER_DIR"] {
        std::env::remove_var(k);
    }
    std::env::set_var("GOVAI_ENV", "dev");
    std::env::set_var("GOVAI_LEDGER_DIR", &ledger);
    std::env::set_var("GOVAI_EXECUTION_AUTH_SIGNING_SEED_HEX", SEED_HEX);
    std::env::set_var("GOVAI_EXECUTION_AUTH_KEY_ID", KID);
    std::env::set_var("GOVAI_API_KEYS", "agent-k");
    std::env::set_var("GOVAI_API_KEYS_JSON", r#"{"agent-k":"t1"}"#);
    std::env::set_var(
        "GOVAI_PRINCIPALS_JSON",
        r#"{"agent-k":{"principal":"agent:approval-test","identity":"agent:approval-test","role":"agent","tenant":"t1"}}"#,
    );

    let state = build_app_state().await.expect("core state");
    let app = build_router(state);

    // 1. A made-up approval id is refused, nothing is appended, and no authorization is issued.
    let (status, body) = post(&app, "agent-k", &call("call-made-up", "human_approved-does-not-exist")).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "unapproved call was accepted: {body}");
    assert_eq!(code_of(&body), "policy_violation", "{body}");
    assert!(message_of(&body).contains("approval_not_found"), "{body}");
    assert!(body.get("execution_authorization").is_none(), "authorization issued without approval: {body}");
    assert_eq!(ledger_records(&ledger), 0, "a refused call was appended to the ledger");

    // 2. An empty approval id is refused for the same reason class.
    let (status, body) = post(&app, "agent-k", &call("call-empty", "")).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(message_of(&body).contains("approval_missing"), "{body}");
    assert!(body.get("execution_authorization").is_none(), "{body}");
    assert_eq!(ledger_records(&ledger), 0);
}
