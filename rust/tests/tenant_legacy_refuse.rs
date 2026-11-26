//! A pre-v2 ledger file that is not explicitly listed must stop startup, never be ignored.
use aigov_audit::build_app_state;

#[tokio::test]
async fn startup_refuses_unlisted_legacy_ledger_file() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("audit_log__team_a.jsonl"), "").unwrap();
    std::env::set_var("GOVAI_LEDGER_DIR", dir.path());
    std::env::set_var("GOVAI_API_KEYS", "legacy-key-one");
    std::env::set_var("GOVAI_API_KEYS_JSON", r#"{"legacy-key-one":"team.a"}"#);
    std::env::remove_var("AIGOV_LEDGER_LEGACY_TENANTS");
    std::env::set_var("AIGOV_ENVIRONMENT", "dev");
    std::env::set_var("AIGOV_POLICY_DIR", env!("CARGO_MANIFEST_DIR"));
    std::env::set_var("GOVAI_API_USAGE_STORE", "memory");
    std::env::remove_var("GOVAI_DATABASE_URL");
    std::env::remove_var("DATABASE_URL");
    let err = build_app_state().await.err().expect("must fail closed");
    assert!(err.contains("AIGOV_LEDGER_LEGACY_TENANTS"), "{err}");
    assert!(!err.contains("legacy-key-one"), "must not echo keys");
}
