//! Real TCP HTTP integration with a temporary Core ledger.
use aigov_audit::{build_app_state, build_router};
use serde_json::json;

const KEY_A: &str = "test-key-tenant-a-0001";
const KEY_B: &str = "test-key-tenant-b-0002";

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


#[tokio::test]
async fn observed_evidence_over_tcp_does_not_authorize_promotion() {
    let dir = tempfile::tempdir().unwrap();
    configure_env(dir.path());
    let app = build_router(build_app_state().await.expect("app state"));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let client = reqwest::Client::new();
    let base = format!("http://{addr}");
    let observation = json!({
        "event_id": "hf-observation-1", "event_type": "huggingface_evaluation_observed",
        "ts_utc": "2026-01-01T00:00:01Z", "actor": "test", "system": "hf",
        "run_id": "hf-http-run", "payload": {"record_sha256": "a".repeat(64),
            "measurement": "caller_reported", "passed": true}
    });
    let response = client.post(format!("{base}/evidence")).bearer_auth(KEY_A)
        .json(&observation).send().await.unwrap();
    assert_eq!(response.status().as_u16(), 200);
    let response = client.get(format!("{base}/bundle?run_id=hf-http-run"))
        .bearer_auth(KEY_A).send().await.unwrap();
    assert_eq!(response.status().as_u16(), 200);
    assert!(response.text().await.unwrap().contains("hf-observation-1"));
    let promotion = json!({
        "event_id": "hf-promotion-1", "event_type": "model_promoted",
        "ts_utc": "2026-01-01T00:00:02Z", "actor": "test", "system": "hf",
        "run_id": "hf-http-run", "payload": {
            "artifact_path": "model", "promotion_reason": "test", "assessment_id": "a",
            "risk_id": "r", "dataset_governance_commitment": "c", "ai_system_id": "s",
            "dataset_id": "d", "model_version_id": "m", "approved_human_event_id": "missing"
        }
    });
    let response = client.post(format!("{base}/evidence")).bearer_auth(KEY_A)
        .json(&promotion).send().await.unwrap();
    assert!(response.status().is_client_error());
    let body = response.text().await.unwrap();
    assert!(body.contains("missing_passed_evaluation_for_promotion") ||
        body.contains("requires prior evaluation_reported"), "{body}");
    server.abort();
}
