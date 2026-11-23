//! Adversarial tenant ids through the real router: each tenant sees only its own evidence,
//! and every ledger file stays inside the ledger directory.
use aigov_audit::{build_app_state, build_router};
use axum::body::Body;
use axum::http::Request;
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tower::ServiceExt;

const RUN: &str = "shared-run-id";

async fn post(app: &axum::Router, key: &str, ev: &Value) -> u16 {
    let req = Request::builder()
        .method("POST")
        .uri("/evidence")
        .header("Authorization", format!("Bearer {key}"))
        .header("content-type", "application/json")
        .body(Body::from(ev.to_string()))
        .unwrap();
    app.clone().oneshot(req).await.unwrap().status().as_u16()
}

async fn bundle(app: &axum::Router, key: &str) -> (u16, String) {
    let req = Request::builder()
        .method("GET")
        .uri(format!("/bundle?run_id={RUN}"))
        .header("Authorization", format!("Bearer {key}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let s = resp.status().as_u16();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (s, String::from_utf8_lossy(&bytes).into_owned())
}

#[tokio::test]
async fn adversarial_tenants_are_isolated_over_http() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::env::set_var("GOVAI_LEDGER_DIR", dir.path());
    let long_a = format!("{}a", "L".repeat(140));
    let long_b = format!("{}b", "L".repeat(140));
    let tenants: Vec<(String, String)> = vec![
        ("adv-key-0".into(), "team.a".into()),
        ("adv-key-1".into(), "team_a".into()),
        ("adv-key-2".into(), "a/b".into()),
        ("adv-key-3".into(), "a_b".into()),
        ("adv-key-4".into(), "café".into()),
        ("adv-key-5".into(), "cafe\u{301}".into()),
        ("adv-key-6".into(), long_a),
        ("adv-key-7".into(), long_b),
        ("adv-key-8".into(), "../escape".into()),
    ];
    let map: serde_json::Map<String, Value> = tenants
        .iter()
        .map(|(k, t)| (k.clone(), Value::String(t.clone())))
        .collect();
    let keys: Vec<String> = tenants.iter().map(|(k, _)| k.clone()).collect();
    std::env::set_var("GOVAI_API_KEYS", keys.join(","));
    std::env::set_var("GOVAI_API_KEYS_JSON", Value::Object(map).to_string());
    std::env::set_var("AIGOV_ENVIRONMENT", "dev");
    std::env::set_var("AIGOV_POLICY_DIR", env!("CARGO_MANIFEST_DIR"));
    std::env::set_var("AIGOV_POLICY_FILE", concat!(env!("CARGO_MANIFEST_DIR"), "/policy.dev.json"));
    std::env::set_var("GOVAI_API_USAGE_STORE", "memory");
    std::env::remove_var("GOVAI_DATABASE_URL");
    std::env::remove_var("DATABASE_URL");
    std::env::remove_var("AIGOV_LEDGER_LEGACY_TENANTS");

    let app = build_router(build_app_state().await.expect("startup accepts distinct tenants"));

    for (i, (key, _)) in tenants.iter().enumerate() {
        let ev = json!({"event_id": format!("ev-{i}"), "event_type": "ai_discovery_reported",
            "ts_utc": "2026-01-01T00:00:01Z", "actor": "t", "system": "t", "run_id": RUN,
            "payload": {"openai": false, "transformers": false, "model_artifacts": false}});
        assert_eq!(post(&app, key, &ev).await, 200, "tenant {i} ingest");
    }

    for (i, (key, tenant)) in tenants.iter().enumerate() {
        let (s, body) = bundle(&app, key).await;
        assert_eq!(s, 200, "tenant {tenant:?} reads own run");
        assert!(body.contains(&format!("\"ev-{i}\"")), "tenant {tenant:?} must see its own event");
        for j in 0..tenants.len() {
            if j != i {
                assert!(!body.contains(&format!("\"ev-{j}\"")), "tenant {tenant:?} must not see event {j}");
            }
        }
    }

    // Every ledger file is directly inside the ledger directory (no traversal, no escape).
    let all: Vec<_> = std::fs::read_dir(dir.path()).unwrap().map(|e| e.unwrap().path()).collect();
    for f in &all {
        assert_eq!(f.parent().unwrap(), dir.path(), "ledger file escaped the ledger directory");
    }
    let ledgers: Vec<_> = all
        .iter()
        .filter(|f| f.file_name().unwrap().to_string_lossy().ends_with(".jsonl"))
        .collect();
    assert_eq!(ledgers.len(), tenants.len(), "one ledger per distinct tenant: {ledgers:?}");
}
