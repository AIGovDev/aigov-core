//! In-process HTTP tests for authentication failures and tenant isolation.
//!
//! Runs the real router (`build_app_state` + `build_router`) with synthetic API keys.
//! This file is its own test binary, so its process-wide key map does not collide with other suites.
//! Tests are sequential in one `#[tokio::test]` because the key map is initialised once per process.

use aigov_audit::{build_app_state, build_router};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tower::ServiceExt;

const KEY_A: &str = "test-key-tenant-a-0001";
const KEY_B: &str = "test-key-tenant-b-0002";
const RUN_A: &str = "run-isolation-a-1";

async fn body_json(response: axum::response::Response) -> Value {
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap_or(json!({}))
}

async fn raw(app: &axum::Router, method: &str, uri: &str, auth: Option<&str>, body: Option<&Value>) -> (StatusCode, String) {
    let mut b = Request::builder().method(method).uri(uri);
    if let Some(a) = auth {
        b = b.header("Authorization", a);
    }
    let req = match body {
        Some(v) => {
            b = b.header("content-type", "application/json");
            b.body(Body::from(serde_json::to_vec(v).unwrap())).unwrap()
        }
        None => b.body(Body::empty()).unwrap(),
    };
    let resp = app.clone().oneshot(req).await.expect("response");
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

async fn send(app: &axum::Router, method: &str, uri: &str, key: &str, body: Option<&Value>) -> (StatusCode, Value) {
    let (s, text) = raw(app, method, uri, Some(&format!("Bearer {key}")), body).await;
    (s, serde_json::from_str(&text).unwrap_or(json!({})))
}

fn discovery_event(run_id: &str, id: &str) -> Value {
    json!({
        "event_id": id,
        "event_type": "ai_discovery_reported",
        "ts_utc": "2026-01-01T00:00:01Z",
        "actor": "test",
        "system": "test",
        "run_id": run_id,
        "payload": { "openai": false, "transformers": false, "model_artifacts": false }
    })
}

fn configure_env(ledger_dir: &std::path::Path) {
    std::env::set_var("GOVAI_LEDGER_DIR", ledger_dir);
    std::env::set_var("GOVAI_API_KEYS", format!("{KEY_A},{KEY_B}"));
    std::env::set_var(
        "GOVAI_API_KEYS_JSON",
        format!(r#"{{"{KEY_A}":"tenant-a","{KEY_B}":"tenant-b"}}"#),
    );
    std::env::set_var("AIGOV_ENVIRONMENT", "dev");
    std::env::set_var("AIGOV_POLICY_DIR", env!("CARGO_MANIFEST_DIR"));
    std::env::set_var("AIGOV_POLICY_FILE", concat!(env!("CARGO_MANIFEST_DIR"), "/policy.dev.json"));
    std::env::set_var("GOVAI_API_USAGE_STORE", "memory");
    std::env::remove_var("GOVAI_DATABASE_URL");
    std::env::remove_var("DATABASE_URL");
    std::env::remove_var("AIGOV_DATABASE_URL");
}

fn is_run_not_found(status: StatusCode, body: &Value) -> bool {
    status == StatusCode::NOT_FOUND && body.get("error").and_then(Value::as_str) == Some("run_not_found")
}

#[tokio::test]
async fn tenant_isolation_and_auth_suite() {
    let dir = tempfile::tempdir().expect("tempdir");
    configure_env(dir.path());
    let app = build_router(build_app_state().await.expect("app state"));

    // Positive control: tenant A ingests its own evidence.
    let (s, body) = send(&app, "POST", "/evidence", KEY_A, Some(&discovery_event(RUN_A, "ev-a-1"))).await;
    assert_eq!(s, StatusCode::OK, "tenant A ingest failed: {body}");
    assert_eq!(body.get("ok"), Some(&json!(true)));

    // Positive control: tenant A can read its own run.
    let (s, body) = send(&app, "GET", &format!("/bundle?run_id={RUN_A}"), KEY_A, None).await;
    assert!(!is_run_not_found(s, &body), "owner must see own run: {s} {body}");

    // Cross-tenant reads must be indistinguishable from "run does not exist".
    for uri in [
        format!("/bundle?run_id={RUN_A}"),
        format!("/bundle/{RUN_A}"),
        format!("/bundle-hash?run_id={RUN_A}"),
        format!("/compliance-summary?run_id={RUN_A}"),
        format!("/compliance-summary/{RUN_A}"),
        format!("/api/export/{RUN_A}"),
        format!("/verify/{RUN_A}"),
    ] {
        let (s, body) = send(&app, "GET", &uri, KEY_B, None).await;
        assert!(
            is_run_not_found(s, &body),
            "tenant B must not see tenant A run via {uri}: {s} {body}"
        );
    }

    // Cross-tenant write must not alter tenant A's run: tenant B posts under the same run id.
    let (s, _) = send(&app, "POST", "/evidence", KEY_B, Some(&discovery_event(RUN_A, "ev-b-1"))).await;
    assert_eq!(s, StatusCode::OK);
    let (s, body) = send(&app, "GET", &format!("/bundle?run_id={RUN_A}"), KEY_B, None).await;
    assert_eq!(s, StatusCode::OK, "tenant B's own ledger should now hold its event: {body}");
    let (s, body) = send(&app, "GET", &format!("/bundle?run_id={RUN_A}"), KEY_A, None).await;
    assert_eq!(s, StatusCode::OK);
    let text = body.to_string();
    assert!(!text.contains("ev-b-1"), "tenant A's bundle must not contain tenant B events: {text}");

    // Header spoofing must not change tenant resolution.
    let req = Request::builder()
        .method("GET")
        .uri(format!("/bundle?run_id={RUN_A}"))
        .header("Authorization", format!("Bearer {KEY_B}"))
        .header("x-govai-project", "tenant-a")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let s = resp.status();
    let spoofed = body_json(resp).await;
    assert_eq!(s, StatusCode::OK);
    let log_path = spoofed.get("log_path").and_then(Value::as_str).unwrap_or_default();
    assert!(log_path.ends_with("audit_log__tenant-b.jsonl"), "x-govai-project must not select tenant: {log_path}");
    assert!(!spoofed.to_string().contains("ev-a"), "spoofed header must not expose tenant A events");

    // Unauthenticated status must not expose absolute server paths.
    let (s, text) = raw(&app, "GET", "/status", None, None).await;
    assert_eq!(s, StatusCode::OK);
    assert!(!text.contains(env!("CARGO_MANIFEST_DIR")), "status must not expose absolute paths: {text}");
    assert!(!text.contains(&dir.path().display().to_string()), "status must not expose ledger directory path");
    assert!(!text.contains(KEY_A) && !text.contains(KEY_B), "status must not expose API keys");

    // Authentication failures: deny by default, no secret echoed back.
    let bad_auth: Vec<(&str, Option<&str>)> = vec![
        ("missing header", None),
        ("empty bearer", Some("Bearer ")),
        ("basic scheme", Some("Basic dXNlcjpwYXNz")),
        ("unknown key", Some("Bearer test-key-unknown-9999")),
        ("jwt-shaped token", Some("Bearer eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ4In0.c2ln")),
    ];
    for (label, auth) in bad_auth {
        for (method, uri, body) in [
            ("GET", format!("/bundle?run_id={RUN_A}"), None),
            ("POST", "/evidence".to_string(), Some(discovery_event(RUN_A, "ev-x"))),
        ] {
            let (s, text) = raw(&app, method, &uri, auth, body.as_ref()).await;
            assert_eq!(s, StatusCode::UNAUTHORIZED, "{label} {method} {uri} must be 401, got {s}: {text}");
            if let Some(a) = auth {
                let token = a.trim_start_matches("Bearer ").trim();
                if !token.is_empty() && a.starts_with("Bearer") {
                    assert!(!text.contains(token), "{label}: response must not echo the bearer token");
                }
            }
        }
    }

    // A valid key with a revoked-looking prefix or near-miss value must not authenticate.
    let (s, _) = send(&app, "GET", &format!("/bundle?run_id={RUN_A}"), &KEY_A[..KEY_A.len() - 1], None).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED, "truncated key must not authenticate");
}
