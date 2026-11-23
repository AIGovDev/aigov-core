//! Startup must refuse a key map whose tenant ids would share one ledger file.
//! Separate test binary: the key map is process-global.
use aigov_audit::build_app_state;

#[tokio::test]
async fn startup_refuses_colliding_tenant_ledgers() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::env::set_var("GOVAI_LEDGER_DIR", dir.path());
    std::env::set_var("GOVAI_API_KEYS", "collide-key-one,collide-key-two");
    std::env::set_var(
        "GOVAI_API_KEYS_JSON",
        r#"{"collide-key-one":"team.a","collide-key-two":"team_a"}"#,
    );
    std::env::set_var("AIGOV_ENVIRONMENT", "dev");
    std::env::set_var("AIGOV_POLICY_DIR", env!("CARGO_MANIFEST_DIR"));
    std::env::set_var("GOVAI_API_USAGE_STORE", "memory");
    std::env::remove_var("GOVAI_DATABASE_URL");
    std::env::remove_var("DATABASE_URL");
    let err = build_app_state().await.err().expect("startup must fail closed");
    assert!(err.contains("share one ledger file"), "{err}");
    assert!(!err.contains("collide-key"), "startup error must not echo API keys");
}
